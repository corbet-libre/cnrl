//! Failure, replay, isolation and persistence checks against real storage.
mod common;

use cnrl::{Config, Error, Event, LibsqlStorage, MemoryStorage, State, Storage};
use common::*;
use cpky::Uuid;

#[tokio::test]
async fn reject_invalid_inputs_and_identity_rebinding() {
    assert!(Config::new(0, ACTION).is_err());
    assert!(Config::new(1, "").is_err());
    assert!(MemoryStorage::new("").is_err());
    let enrol = enrol(MemoryStorage::new(COMMUNITY).unwrap());
    for (user, subject, at) in [
        (Uuid::nil(), SUBJECT, now()),
        (USER, "", now()),
        (USER, "a\0b", now()),
        (USER, SUBJECT, -1),
        (USER, SUBJECT, i64::MAX),
    ] {
        assert_eq!(
            enrol.start(user, subject, at).await,
            Err(Error::InvalidInput)
        );
    }
    let row = enrol.start(USER, SUBJECT, now()).await.unwrap();
    assert_eq!(enrol.start(USER, "other", now()).await, Err(Error::Scope));
    assert_eq!(
        enrol.start(Uuid::from_u128(2), SUBJECT, now()).await,
        Err(Error::Conflict)
    );
    assert_eq!(
        enrol.get(Uuid::from_u128(3), now()).await,
        Err(Error::NotFound)
    );
    assert_eq!(enrol.expire_due(now(), 0).await, Err(Error::InvalidInput));
    assert_eq!(
        enrol.expire_due(now(), 1001).await,
        Err(Error::InvalidInput)
    );
    assert_eq!(enrol.get(USER, now()).await.unwrap(), row);
}

#[tokio::test]
async fn passkey_receipts_and_authentication_enforce_scope_and_revocation() {
    let enrol = enrol(MemoryStorage::new(COMMUNITY).unwrap());
    let row = enrol.start(USER, SUBJECT, now()).await.unwrap();
    let wrong = passkeys("another-community");
    let (mut token, foreign) = register(&wrong, USER);
    assert_eq!(
        enrol
            .apply(&row, Event::PasskeyRegistered(&foreign), now())
            .await,
        Err(Error::Scope)
    );
    assert_eq!(
        enrol.resume(&login(&wrong, &mut token), now()).await,
        Err(Error::Scope)
    );
    let server = passkeys(COMMUNITY);
    let (_, other) = register(&server, Uuid::from_u128(2));
    assert_eq!(
        enrol
            .apply(&row, Event::PasskeyRegistered(&other), now())
            .await,
        Err(Error::Scope)
    );
    let (_, passkey) = register(&server, USER);
    server.revoke(USER, passkey.credential_id()).unwrap();
    let revoked = server
        .list(USER)
        .unwrap()
        .into_iter()
        .find(|r| r.credential_id() == passkey.credential_id())
        .unwrap();
    assert_eq!(
        enrol
            .apply(&row, Event::PasskeyRegistered(&revoked), now())
            .await,
        Err(Error::InvalidInput)
    );
    assert_eq!(enrol.get(USER, now()).await.unwrap(), row);
}

#[tokio::test]
async fn malformed_gate_policy_and_register_inputs_never_advance() {
    let store = MemoryStorage::new(COMMUNITY).unwrap();
    let enrol = enrol(store);
    let register = crgs::Register::new(
        crgs::MemoryStorage::default(),
        crgs::ReleasePeriod::default(),
    );
    let gates = pending(&enrol, &register).await;
    for mode in 0..6 {
        let mut proof = proof(COMMUNITY);
        match mode {
            0 => proof.subject = "another".into(),
            1 => proof.community = Some("another".into()),
            2 => proof.level = crbk::GateLevel::Global,
            3 => proof.valid_until = now(),
            4 => proof.proven_at = Some(now() + 1),
            _ => proof.provider.clear(),
        }
        assert!(
            enrol
                .apply(&gates, Event::GatePassed(&proof), now())
                .await
                .is_err()
        );
    }
    assert_eq!(
        enrol.evaluate(&gates, &policy("another"), &[], now()).await,
        Err(Error::Scope)
    );
    let mut malformed = policy(COMMUNITY);
    malformed
        .content
        .insert(crbk::action_key(ACTION), serde_json::json!(42));
    assert_eq!(
        enrol.evaluate(&gates, &malformed, &[], now()).await,
        Err(Error::Policy)
    );
    let (_, denied) = enrol
        .evaluate(&gates, &policy(COMMUNITY), &[], now())
        .await
        .unwrap();
    assert!(!denied.allowed);
    let member = register
        .admit(admission(&gates), date(now()))
        .await
        .unwrap();
    assert_eq!(
        enrol
            .apply(
                &gates,
                Event::AdmissionRecorded {
                    member: &member,
                    decision: &denied
                },
                now()
            )
            .await,
        Err(Error::Transition)
    );
    let inconsistent = crbk::Decision {
        allowed: true,
        missing: vec![crbk::Missing::ActionUnavailable],
    };
    assert_eq!(
        enrol
            .apply(&gates, Event::PolicyEvaluated(&inconsistent), now())
            .await,
        Err(Error::InvalidInput)
    );
    let (_, allowed) = enrol
        .evaluate(&gates, &policy(COMMUNITY), &[proof(COMMUNITY)], now())
        .await
        .unwrap();
    for mode in 0..4 {
        let mut member = member.clone();
        match mode {
            0 => member.id = crgs::MemberId::new(b"other".to_vec()).unwrap(),
            1 => member.handle = None,
            2 => {
                member.handle = Some(crgs::Handle::new("another_handle", "another_handle").unwrap())
            }
            _ => member.lease_end = crgs::YearMonth::new(2025, 1).unwrap(),
        }
        assert!(
            enrol
                .apply(
                    &gates,
                    Event::AdmissionRecorded {
                        member: &member,
                        decision: &allowed
                    },
                    now()
                )
                .await
                .is_err()
        );
    }
    assert_eq!(enrol.get(USER, now()).await.unwrap(), gates);
}

#[tokio::test]
async fn reservations_cannot_extend_or_change_pending_claims() {
    let enrol = enrol(MemoryStorage::new(COMMUNITY).unwrap());
    let start = enrol.start(USER, SUBJECT, now()).await.unwrap();
    let (_, passkey) = register(&passkeys(COMMUNITY), USER);
    let keyed = enrol
        .apply(&start, Event::PasskeyRegistered(&passkey), now())
        .await
        .unwrap();
    for offset in [-1, 1] {
        let mut receipt = reservation(&keyed);
        receipt.expires_at += chrono::Duration::seconds(offset);
        assert_eq!(
            enrol
                .apply(&keyed, Event::HandleReserved(&receipt), now())
                .await,
            Err(Error::InvalidInput)
        );
    }
    let receipt = reservation(&keyed);
    let held = enrol
        .apply(&keyed, Event::HandleReserved(&receipt), now())
        .await
        .unwrap();
    let wrong = crgs::Reservation {
        handle: crgs::Handle::new("other_handle", "other_handle").unwrap(),
        ..receipt
    };
    assert_eq!(
        enrol
            .apply(&held, Event::HandleReserved(&wrong), now())
            .await,
        Err(Error::Transition)
    );
}

#[tokio::test]
async fn libsql_reopen_isolate_and_detect_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("persist.db");
    let db = open(&path).await;
    let store = LibsqlStorage::new(&db, COMMUNITY).unwrap();
    let first = enrol(store.clone())
        .start(USER, SUBJECT, now())
        .await
        .unwrap();
    let other = enrol(LibsqlStorage::new(&db, "other").unwrap());
    assert_eq!(other.get(USER, now()).await, Err(Error::NotFound));
    let second = other.start(USER, SUBJECT, now()).await.unwrap();
    assert_eq!(
        other.apply(&first, Event::AllPasskeysLost, now()).await,
        Err(Error::Scope)
    );
    drop(store);
    drop(other);
    drop(db);
    let db = open(&path).await;
    assert_eq!(db.migrate(&migrations()).await.unwrap(), 0);
    let enrol = enrol(LibsqlStorage::new(&db, COMMUNITY).unwrap());
    assert_eq!(enrol.get(USER, now()).await.unwrap(), first);
    let scope = db.community(COMMUNITY).unwrap();
    // Payload and index projection disagree: fail closed, without echoing data.
    scope
        .execute(
            "UPDATE cnrl_enrolments SET cleanup = 1 WHERE user_id = ?1",
            [USER.to_string()],
        )
        .await
        .unwrap();
    assert_eq!(enrol.get(USER, now()).await, Err(Error::Storage));
    assert_eq!(
        common::enrol(LibsqlStorage::new(&db, "other").unwrap())
            .get(USER, now())
            .await
            .unwrap(),
        second
    );
    scope
        .execute(
            "UPDATE cnrl_enrolments SET payload = ?1 WHERE user_id = ?2",
            crlt::params!["secret-corrupt-input", USER.to_string()],
        )
        .await
        .unwrap();
    assert_eq!(
        enrol.get(USER, now()).await.unwrap_err().to_string(),
        "enrolment storage failed"
    );
}

#[tokio::test]
async fn missing_schema_is_a_storage_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("empty.db").display()),
        "",
    ))
    .await
    .unwrap();
    let enrol = enrol(LibsqlStorage::new(&db, COMMUNITY).unwrap());
    assert_eq!(enrol.start(USER, SUBJECT, now()).await, Err(Error::Storage));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_libsql_handles_serialize_retries_and_reject_stale_writers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("race.db");
    let a = open(&path).await;
    let b = open(&path).await;
    let first = enrol(LibsqlStorage::new(&a, COMMUNITY).unwrap());
    let second = enrol(LibsqlStorage::new(&b, COMMUNITY).unwrap());
    let row = first.start(USER, SUBJECT, now()).await.unwrap();
    let row_copy = row.clone();
    let left =
        tokio::spawn(async move { first.apply(&row_copy, Event::AllPasskeysLost, now()).await });
    let right =
        tokio::spawn(async move { second.apply(&row, Event::AllPasskeysLost, now()).await });
    let left = left.await.unwrap().unwrap();
    assert_eq!(left, right.await.unwrap().unwrap());
    assert_eq!(left.state(), State::Released);
}

#[tokio::test]
async fn expiry_batches_are_bounded_and_resume_without_skipping() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("batches.db")).await;
    let store = LibsqlStorage::new(&db, COMMUNITY).unwrap();
    let enrol = enrol(store.clone());
    for n in 1..=5 {
        enrol
            .start(Uuid::from_u128(n), &format!("subject-{n}"), now())
            .await
            .unwrap();
    }
    assert_eq!(
        enrol.expire_due(now() + 86400 * 3, 2).await.unwrap().len(),
        2
    );
    assert_eq!(
        enrol.expire_due(now() + 86400 * 3, 2).await.unwrap().len(),
        2
    );
    assert_eq!(
        enrol.expire_due(now() + 86400 * 3, 2).await.unwrap().len(),
        1
    );
    assert!(store.due(i64::MAX, 2).await.unwrap().is_empty());
    assert!(store.cleanup_due(2).await.unwrap().is_empty());
}

#[tokio::test]
async fn current_record_contains_no_gate_data_or_activity_history() {
    let enrol = enrol(MemoryStorage::new(COMMUNITY).unwrap());
    let register = crgs::Register::new(
        crgs::MemoryStorage::default(),
        crgs::ReleasePeriod::default(),
    );
    let gates = pending(&enrol, &register).await;
    let encoded = serde_json::to_value(&gates).unwrap();
    let keys: Vec<_> = encoded
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "community",
            "expires_day",
            "revision",
            "skeleton",
            "state",
            "subject",
            "user"
        ]
    );
    assert!(!format!("{gates:?}").contains(SUBJECT));
    assert!(!serde_json::to_string(&gates).unwrap().contains("cvch"));
}

#[tokio::test]
async fn policy_cannot_report_allowed_for_an_expired_enrolment() {
    let enrol = enrol(MemoryStorage::new(COMMUNITY).unwrap());
    let register = crgs::Register::new(
        crgs::MemoryStorage::default(),
        crgs::ReleasePeriod::default(),
    );
    let gates = pending(&enrol, &register).await;
    let deadline = gates.expires_at().unwrap();
    let mut proof = proof(COMMUNITY);
    proof.valid_until = deadline + 3600;
    assert_eq!(
        enrol
            .evaluate(&gates, &policy(COMMUNITY), &[proof], deadline)
            .await,
        Err(Error::Transition)
    );
    assert_eq!(
        enrol.get(USER, deadline).await.unwrap().state(),
        State::Expired
    );
}
