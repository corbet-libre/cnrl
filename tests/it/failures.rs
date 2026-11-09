//! Failure, replay, isolation and persistence checks against real storage.

use crate::common;
use crate::common::*;
use ckyh::Uuid;
use cnrl::{Config, Error, Event, LibsqlStorage, MemoryStorage, State, Storage};

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
    let revoked = server.with(|server| {
        server.revoke(USER, passkey.credential_id()).unwrap();
        server
            .list(USER)
            .unwrap()
            .into_iter()
            .find(|r| r.credential_id() == passkey.credential_id())
            .unwrap()
    });
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
            2 => member.handle = Some(crgs::Handle::from_display("another_handle").unwrap()),
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
        handle: crgs::Handle::from_display("other_handle").unwrap(),
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
    // Key order depends on the serde_json feature set of the whole graph; compare as a set.
    let mut keys: Vec<_> = encoded
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
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

fn edited(record: &cnrl::Record, changes: serde_json::Value) -> cnrl::Record {
    let mut wire = serde_json::to_value(record).unwrap();
    for (key, value) in changes.as_object().unwrap() {
        wire[key] = value.clone();
    }
    serde_json::from_value(wire).unwrap()
}

async fn storage_rejects_skipped_states<S: Storage + Clone>(store: S, terminal_state: &str) {
    use serde_json::json;
    let facade = enrol(store.clone());
    let started = facade.start(USER, SUBJECT, now()).await.unwrap();
    let admitted = edited(
        &started,
        json!({"state":"admitted", "expires_day":null, "revision":2}),
    );
    assert_eq!(
        store.compare_exchange(Some(&started), &admitted).await,
        Err(Error::Transition)
    );
    let changed_deadline = edited(
        &started,
        json!({"state":"passkey_registered", "revision":2, "expires_day":started.expires_at().unwrap()/86400+1}),
    );
    assert_eq!(
        store
            .compare_exchange(Some(&started), &changed_deadline)
            .await,
        Err(Error::Transition)
    );
    assert_eq!(store.load(USER).await.unwrap(), Some(started.clone()));
    let passkey = edited(
        &started,
        json!({"state":"passkey_registered", "revision":2}),
    );
    store
        .compare_exchange(Some(&started), &passkey)
        .await
        .unwrap();
    store
        .compare_exchange(Some(&started), &passkey)
        .await
        .unwrap();
    let reserved = edited(
        &passkey,
        json!({"state":"handle_reserved", "skeleton":"checked-key", "revision":3}),
    );
    store
        .compare_exchange(Some(&passkey), &reserved)
        .await
        .unwrap();
    let rebound = edited(
        &reserved,
        json!({"state":"gates_in_progress", "skeleton":"different-key", "revision":4}),
    );
    assert_eq!(
        store.compare_exchange(Some(&reserved), &rebound).await,
        Err(Error::Transition)
    );
    let terminal = edited(
        &reserved,
        json!({"state":terminal_state, "expires_day":null, "revision":4}),
    );
    // Termination must retain the marker until the real register is cancelled.
    assert_eq!(
        store
            .compare_exchange(
                Some(&reserved),
                &edited(&terminal, json!({"skeleton":null}))
            )
            .await,
        Err(Error::Transition)
    );
    store
        .compare_exchange(Some(&reserved), &terminal)
        .await
        .unwrap();
    assert_eq!(
        store
            .compare_exchange(Some(&terminal), &edited(&terminal, json!({"revision":5})))
            .await,
        Err(Error::Transition)
    );
    let revival = edited(&admitted, json!({"revision":5}));
    assert_eq!(
        store.compare_exchange(Some(&terminal), &revival).await,
        Err(Error::Transition)
    );
    let cleaned = edited(&terminal, json!({"skeleton":null, "revision":5}));
    store
        .compare_exchange(Some(&terminal), &cleaned)
        .await
        .unwrap();
    store
        .compare_exchange(Some(&terminal), &cleaned)
        .await
        .unwrap();
    assert_eq!(store.load(USER).await.unwrap(), Some(cleaned.clone()));
    assert_eq!(
        store
            .compare_exchange(Some(&cleaned), &edited(&cleaned, json!({"revision":6})))
            .await,
        Err(Error::Transition)
    );
    let inserted = edited(
        &admitted,
        json!({"user":Uuid::from_u128(2), "subject":"other", "revision":1}),
    );
    assert_eq!(
        store.compare_exchange(None, &inserted).await,
        Err(Error::Transition)
    );
    assert!(store.load(Uuid::from_u128(2)).await.unwrap().is_none());
}

#[tokio::test]
async fn memory_storage_enforces_transition_order() {
    for state in ["expired", "released"] {
        storage_rejects_skipped_states(MemoryStorage::new(COMMUNITY).unwrap(), state).await;
    }
}

#[tokio::test]
async fn sql_storage_enforces_transition_order() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("transitions.db")).await;
    for state in ["expired", "released"] {
        storage_rejects_skipped_states(
            LibsqlStorage::new(&db, format!("{COMMUNITY}-{state}")).unwrap(),
            state,
        )
        .await;
    }
}

#[tokio::test]
async fn deserialization_establishes_safe_record_accessors() {
    use serde_json::json;
    let row = enrol(MemoryStorage::new(COMMUNITY).unwrap())
        .start(USER, SUBJECT, now())
        .await
        .unwrap();
    let wire = serde_json::to_value(&row).unwrap();
    for change in [
        json!({"subject":""}),
        json!({"community":""}),
        json!({"user":Uuid::nil()}),
        json!({"expires_day":i64::MAX}),
        json!({"expires_day":-1}),
        json!({"expires_day":0}),
        json!({"expires_day":null}),
        json!({"revision":0}),
        json!({"revision":u64::MAX}),
        json!({"state":"admitted"}),
        json!({"state":"handle_reserved"}),
        json!({"skeleton":"unexpected"}),
        json!({"unknown":true}),
    ] {
        let mut malformed = wire.clone();
        for (key, value) in change.as_object().unwrap() {
            malformed[key] = value.clone();
        }
        assert!(serde_json::from_value::<cnrl::Record>(malformed).is_err());
    }
    let round_trip: cnrl::Record = serde_json::from_value(wire).unwrap();
    assert_eq!(round_trip.expires_at(), row.expires_at());
    assert_eq!(round_trip.member_id(), row.member_id());
    assert_eq!(round_trip, row);
}
