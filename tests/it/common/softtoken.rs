//! Test-only software authenticator backed by cpky's maintained `test-authenticator` feature.
//!
//! This replaces the retired `webauthn-authenticator-rs` `SoftToken` fixture at the same call
//! shape: `new(user_verified)`, `perform_register(origin, options, timeout)` and
//! `perform_auth(origin, options, timeout)`, returning the ordinary `webauthn-rs-proto` values.
//! The cryptography, counter, ES256 key and PRF handling come from the maintained upstream
//! `passkey` authenticator that cpky ships for tests; nothing here implements WebAuthn.
#![allow(dead_code)]

use std::future::Future;
use std::pin::pin;
use std::task::{Context as TaskContext, Poll, Waker};

use ckyh::Url;
use cpky::software::{SoftwareAuthenticator, TestConfiguration};
use cpky::{Client, Context};
use serde_json::json;
use webauthn_rs_proto::{
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

/// The ceremonies are pure computation: one poll completes them. This keeps the fixture
/// synchronous without a runtime and without a nested `block_on` inside tokio tests.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut task = TaskContext::from_waker(Waker::noop());
    for _ in 0..10_000 {
        match future.as_mut().poll(&mut task) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
    panic!("the software authenticator did not complete without a runtime");
}

/// In-memory software authenticator bound to one origin and relying party.
pub struct SoftwareToken {
    user_verified: bool,
    bound: Option<(String, String, Client<SoftwareAuthenticator>)>,
    credential_id: Option<Vec<u8>>,
}

impl SoftwareToken {
    /// Construct a synthetic token. The optional string keeps the old constructor's shape.
    pub fn new(user_verified: bool) -> Result<(Self, Option<String>), cpky::Error> {
        Ok((
            Self {
                user_verified,
                bound: None,
                credential_id: None,
            },
            None,
        ))
    }

    /// The credential registered through this token, for fixtures that address it explicitly.
    pub fn credential_id(&self) -> Option<&[u8]> {
        self.credential_id.as_deref()
    }

    fn client(
        &mut self,
        origin: &Url,
        rp: &str,
    ) -> Result<&mut Client<SoftwareAuthenticator>, cpky::Error> {
        // `Url::as_str` keeps a root path ("https://host/"); clientDataJSON must carry the
        // exact ascii origin ("https://host"), as cpky's Context requires.
        let origin = origin.origin().ascii_serialization();
        let current = self
            .bound
            .as_ref()
            .is_some_and(|(bound_origin, bound_rp, _)| bound_origin == &origin && bound_rp == rp);
        if !current {
            assert!(
                self.bound.is_none() || self.credential_id.is_none(),
                "a software token cannot move a registered credential to another origin"
            );
            let authenticator = SoftwareAuthenticator::new(
                &origin,
                TestConfiguration {
                    user_verified: self.user_verified,
                    // The fixture publishes no vault secret; cpky still strips the PRF
                    // extension output before the public response, as ckyh requires.
                    prf: false,
                    evaluate_at_create: false,
                },
            )?;
            let context = Context::new(&origin, rp)?;
            self.bound = Some((origin, rp.to_owned(), Client::new(context, authenticator)));
        }
        Ok(&mut self.bound.as_mut().expect("bound just above").2)
    }

    /// Registration ceremony; same arguments as the retired fixture.
    pub fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        _timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, cpky::Error> {
        let rp = options.rp.id.clone();
        let client = self.client(&origin, &rp)?;
        let credential = block_on(client.register_privileged(json!({ "publicKey": options })))?;
        self.credential_id = credential.credential_id().ok();
        serde_json::from_value(credential.into_json()).map_err(|_| cpky::Error::InvalidResponse)
    }

    /// Authentication ceremony; same arguments as the retired fixture.
    pub fn perform_auth(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        _timeout_ms: u32,
    ) -> Result<PublicKeyCredential, cpky::Error> {
        let rp = options.rp_id.clone();
        let client = self.client(&origin, &rp)?;
        let authentication = block_on(client.sign_in(json!({ "publicKey": options })))?;
        let (credential, _outcome) = authentication.into_parts();
        serde_json::from_value(credential.into_json()).map_err(|_| cpky::Error::InvalidResponse)
    }
}
