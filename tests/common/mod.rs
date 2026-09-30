#![allow(dead_code)]

use cnrl::{Config, Enrol, Record, Storage};
use cpky::{CredentialID, CredentialStore, Error, StoredPasskey, Uuid};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

pub const USER: Uuid = Uuid::from_u128(1);
pub const COMMUNITY: &str = "community-a";
pub const SUBJECT: &str = "community-pseudonym";
pub const ACTION: &str = "membership";
pub const ORIGIN: &str = "https://members.example.org";

pub fn now() -> i64 {
    "2026-09-30T12:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap()
        .timestamp()
}

pub fn date(at: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(at, 0).unwrap()
}

pub fn enrol<S: Storage>(store: S) -> Enrol<S> {
    Enrol::new(store, Config::new(2, ACTION).unwrap())
}

pub fn migrations() -> [crlt::Migration<'static>; 3] {
    [
        crlt::Migration::new(1, "cnrl", cnrl::SCHEMA),
        crlt::Migration::new(2, "crgs", crgs::SCHEMA),
        crlt::Migration::new(3, "clbs", clbs::SCHEMA),
    ]
}

pub async fn open(path: &std::path::Path) -> crlt::Db {
    let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    db.migrate(&migrations()).await.unwrap();
    db
}

pub fn reservation(record: &Record) -> crgs::Reservation {
    crgs::Reservation {
        member_id: record.member_id(),
        handle: crgs::Handle::new("member_handle", "member_handle").unwrap(),
        expires_at: date(record.expires_at().unwrap()),
    }
}

pub fn admission(record: &Record) -> crgs::Admission {
    crgs::Admission {
        id: record.member_id(),
        handle: crgs::Handle::new("member_handle", "member_handle").unwrap(),
        role: crgs::Role::Member,
        lease_end: crgs::YearMonth::new(2027, 9).unwrap(),
    }
}

pub fn proof(community: &str) -> crbk::GateResult {
    crbk::GateResult {
        gate: "cvch".into(),
        level: crbk::GateLevel::Community,
        subject: SUBJECT.into(),
        community: Some(community.into()),
        provider: "community".into(),
        valid_until: now() + 3600,
        proven_at: None,
    }
}

pub fn policy(community: &str) -> crbk::Snapshot {
    let proof = proof(community);
    let action = crbk::ActionPolicy {
        all_of: vec![crbk::Requirement {
            gate: proof.gate.clone(),
            level: proof.level,
            provider: None,
        }],
        ..Default::default()
    };
    crbk::Snapshot {
        community: community.into(),
        kind: crbk::SnapshotKind::Settings,
        revision: 1,
        policy_epoch: 1,
        issued: now(),
        content: [
            (
                crbk::action_key(ACTION),
                serde_json::to_value(action).unwrap(),
            ),
            (
                crbk::gate_key(proof.level, &proof.gate),
                serde_json::json!(true),
            ),
            (
                crbk::provider_key(proof.level, &proof.gate, &proof.provider),
                serde_json::json!(true),
            ),
        ]
        .into(),
    }
}

// Real credential storage for real WebAuthn ceremonies; updates commit a copy.
type Key = (String, Vec<u8>);
#[derive(Clone, Default)]
pub struct Credentials(Arc<Mutex<BTreeMap<Key, StoredPasskey>>>);

impl CredentialStore for Credentials {
    fn list(&self, community: &str, member: Uuid) -> Result<Vec<StoredPasskey>, Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.community() == community && r.member() == member)
            .cloned()
            .collect())
    }
    fn insert(&self, record: StoredPasskey) -> Result<(), Error> {
        let mut rows = self.0.lock().unwrap();
        let key = (
            record.community().into(),
            record.credential_id().as_ref().to_vec(),
        );
        if rows.contains_key(&key) {
            return Err(Error::DuplicateCredential);
        }
        rows.insert(key, record);
        Ok(())
    }
    fn update<T>(
        &self,
        community: &str,
        credential_id: &CredentialID,
        change: impl FnOnce(&mut StoredPasskey) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut rows = self.0.lock().unwrap();
        let key = (community.into(), credential_id.as_ref().to_vec());
        let mut record = rows.get(&key).ok_or(Error::NotFound)?.clone();
        let result = change(&mut record)?;
        rows.insert(key, record);
        Ok(result)
    }
}

pub fn passkeys(community: &str) -> cpky::Passkeys<Credentials> {
    cpky::Passkeys::new(
        Credentials::default(),
        community,
        "members.example.org",
        &[cpky::Url::parse(ORIGIN).unwrap()],
    )
    .unwrap()
}

pub fn register(server: &cpky::Passkeys<Credentials>, user: Uuid) -> (SoftToken, StoredPasskey) {
    let mut token = SoftToken::new(true).unwrap().0;
    let (challenge, pending) = server.start_registration(user).unwrap();
    let response = token
        .perform_register(
            cpky::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let record = server
        .finish_registration(
            pending,
            &response,
            cpky::CreationMonth::new(2026, 9).unwrap(),
        )
        .unwrap();
    (token, record)
}

pub fn login(server: &cpky::Passkeys<Credentials>, token: &mut SoftToken) -> cpky::Authentication {
    let (challenge, pending) = server.start_authentication(USER).unwrap();
    let response = token
        .perform_auth(
            cpky::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    server.finish_authentication(pending, &response).unwrap()
}

pub async fn pending<S: Storage, R: crgs::Storage>(
    enrol: &Enrol<S>,
    register: &crgs::Register<R>,
) -> Record {
    let started = enrol.start(USER, SUBJECT, now()).await.unwrap();
    let (_, passkey) = self::register(&passkeys(COMMUNITY), USER);
    let passkey = enrol
        .apply(&started, cnrl::Event::PasskeyRegistered(&passkey), now())
        .await
        .unwrap();
    let reserved = register
        .reserve_handle(reservation(&passkey), date(now()))
        .await
        .unwrap();
    let reserved = enrol
        .apply(&passkey, cnrl::Event::HandleReserved(&reserved), now())
        .await
        .unwrap();
    enrol
        .apply(&reserved, cnrl::Event::GatesStarted, now())
        .await
        .unwrap()
}
