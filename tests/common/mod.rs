#![allow(dead_code)]

use ckyh::{StoredPasskey, Uuid};
use cnrl::{Config, Enrol, Record, Storage};
use std::sync::LazyLock;
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

pub fn migrations() -> [crlt::Migration<'static>; 2] {
    [
        crlt::Migration::new(1, "cnrl", cnrl::SCHEMA),
        crlt::Migration::new(2, "crgs", crgs::SCHEMA),
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
        handle: crgs::Handle::from_display("member_handle").unwrap(),
        expires_at: date(record.expires_at().unwrap()),
    }
}

pub fn admission(record: &Record) -> crgs::Admission {
    crgs::Admission {
        id: record.member_id(),
        handle: crgs::Handle::from_display("member_handle").unwrap(),
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

// The owner store needs a multithreaded runtime kept alive by the test process.
// Calls run on ordinary threads because its synchronous API drives that runtime.
static PASSKEY_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
});

pub struct PasskeyFixture {
    server: ckyh::Passkeys<ckyh::LibsqlStore>,
    _directory: tempfile::TempDir,
}

impl PasskeyFixture {
    pub fn with<T: Send>(
        &self,
        call: impl FnOnce(&ckyh::Passkeys<ckyh::LibsqlStore>) -> T + Send,
    ) -> T {
        std::thread::scope(|scope| scope.spawn(|| call(&self.server)).join().unwrap())
    }
}

pub fn passkeys(community: &str) -> PasskeyFixture {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let directory = tempfile::tempdir().unwrap();
                let db = PASSKEY_RUNTIME.block_on(async {
                    let db = crlt::Db::open(crlt::Config::new(
                        format!("file://{}", directory.path().join("passkeys.db").display()),
                        "",
                    ))
                    .await
                    .unwrap();
                    db.migrate(&[crlt::Migration::new(
                        1,
                        "cpky_passkeys",
                        ckyh::LIBSQL_SCHEMA,
                    )])
                    .await
                    .unwrap();
                    db
                });
                let server = ckyh::Passkeys::new(
                    ckyh::LibsqlStore::new(&db, community, PASSKEY_RUNTIME.handle().clone())
                        .unwrap(),
                    community,
                    "members.example.org",
                    &[ckyh::Url::parse(ORIGIN).unwrap()],
                )
                .unwrap();
                PasskeyFixture {
                    server,
                    _directory: directory,
                }
            })
            .join()
            .unwrap()
    })
}

pub fn register(server: &PasskeyFixture, user: Uuid) -> (SoftToken, StoredPasskey) {
    server.with(|server| {
        let mut token = SoftToken::new(true).unwrap().0;
        let (challenge, pending) = server.start_registration(user).unwrap();
        let response = token
            .perform_register(
                ckyh::Url::parse(ORIGIN).unwrap(),
                {
                    // SoftToken is a legacy non-resident fixture.
                    let mut options = challenge.public_key;
                    options
                        .authenticator_selection
                        .as_mut()
                        .unwrap()
                        .require_resident_key = false;
                    options
                },
                300_000,
            )
            .unwrap();
        let record = server
            .finish_registration(
                pending,
                &response.into(),
                ckyh::CreationMonth::new(2026, 9).unwrap(),
            )
            .unwrap();
        (token, record)
    })
}

pub fn login(server: &PasskeyFixture, token: &mut SoftToken) -> ckyh::Authentication {
    server.with(|server| {
        let (challenge, pending) = server.start_authentication(USER).unwrap();
        let response = token
            .perform_auth(
                ckyh::Url::parse(ORIGIN).unwrap(),
                challenge.public_key,
                300_000,
            )
            .unwrap();
        server
            .finish_authentication(pending, &response.into())
            .unwrap()
    })
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
