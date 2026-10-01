//! Real lifecycle round trips through sibling crates and both storage backends.
mod common;

use ckyh::Uuid;
use cnrl::{Enrol, Error, Event, LibsqlStorage, MemoryStorage, State, Storage};
use common::*;

async fn lifecycle<S: Storage, R: crgs::Storage>(store: S, register: crgs::Register<R>) {
    let enrol = enrol(store);
    let started = enrol.start(USER, SUBJECT, now()).await.unwrap();
    assert_eq!(started.state(), State::Started);
    assert_eq!(
        enrol.start(USER, SUBJECT, now() + 3600).await.unwrap(),
        started
    );
    assert_eq!(started.expires_at().unwrap() % 86400, 0);
    assert_eq!(
        enrol.apply(&started, Event::GatesStarted, now()).await,
        Err(Error::Transition)
    );
    let server = passkeys(COMMUNITY);
    let (mut token, passkey) = register_passkey(&server);
    let keyed = enrol
        .apply(&started, Event::PasskeyRegistered(&passkey), now())
        .await
        .unwrap();
    assert_eq!(keyed.state(), State::PasskeyRegistered);
    assert_eq!(
        enrol
            .apply(&started, Event::PasskeyRegistered(&passkey), now())
            .await
            .unwrap(),
        keyed
    );
    let auth = login(&server, &mut token);
    assert_eq!(enrol.resume(&auth, now()).await.unwrap(), keyed);
    let (mut second, second_record) = common::register(&server, USER);
    assert_eq!(
        enrol
            .apply(&keyed, Event::PasskeyRegistered(&second_record), now())
            .await
            .unwrap(),
        keyed
    );
    assert_eq!(
        enrol
            .resume(&login(&server, &mut second), now())
            .await
            .unwrap(),
        keyed
    );
    let reservation = register
        .reserve_handle(reservation(&keyed), date(now()))
        .await
        .unwrap();
    let held = enrol
        .apply(&keyed, Event::HandleReserved(&reservation), now())
        .await
        .unwrap();
    assert_eq!(held.state(), State::HandleReserved);
    let gates = enrol
        .apply(&held, Event::GatePassed(&proof(COMMUNITY)), now())
        .await
        .unwrap();
    assert_eq!(gates.state(), State::GatesInProgress);
    let (gates, decision) = enrol
        .evaluate(&gates, &policy(COMMUNITY), &[proof(COMMUNITY)], now())
        .await
        .unwrap();
    assert!(decision.allowed);
    let member = register
        .admit(admission(&gates), date(now()))
        .await
        .unwrap();
    let admitted = enrol
        .apply(
            &gates,
            Event::AdmissionRecorded {
                member: &member,
                decision: &decision,
            },
            now(),
        )
        .await
        .unwrap();
    assert_eq!(admitted.state(), State::Admitted);
    assert_eq!(admitted.expires_at(), None);
    assert_eq!(
        enrol
            .apply(
                &gates,
                Event::AdmissionRecorded {
                    member: &member,
                    decision: &decision
                },
                now()
            )
            .await
            .unwrap(),
        admitted
    );
    assert_eq!(
        enrol
            .apply(&admitted, Event::CredentialIssued, now())
            .await
            .unwrap(),
        admitted
    );
    assert!(
        enrol
            .expire_due(now() + 86400 * 30, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let (lapsed, missing) = enrol
        .evaluate(&admitted, &policy(COMMUNITY), &[], now())
        .await
        .unwrap();
    assert!(!missing.allowed);
    assert_eq!(lapsed.state(), State::Lapsed);
    // A delayed admission receipt cannot undo a newer denial.
    assert_eq!(
        enrol
            .apply(
                &gates,
                Event::AdmissionRecorded {
                    member: &member,
                    decision: &decision
                },
                now()
            )
            .await,
        Err(Error::Conflict)
    );
    let (_, decision) = enrol
        .evaluate(&lapsed, &policy(COMMUNITY), &[proof(COMMUNITY)], now())
        .await
        .unwrap();
    let renewed = enrol
        .apply(
            &lapsed,
            Event::AdmissionRecorded {
                member: &member,
                decision: &decision,
            },
            now(),
        )
        .await
        .unwrap();
    assert_eq!(renewed.state(), State::Admitted);
    // ABA protection: an old denial cannot lapse a later renewal.
    assert_eq!(
        enrol
            .apply(&admitted, Event::PolicyEvaluated(&missing), now())
            .await,
        Err(Error::Conflict)
    );
    let released = enrol
        .apply(&renewed, Event::AllPasskeysLost, now())
        .await
        .unwrap();
    assert_eq!(released.state(), State::Released);
    assert_eq!(
        enrol
            .apply(&renewed, Event::AllPasskeysLost, now())
            .await
            .unwrap(),
        released
    );
    assert_eq!(
        enrol
            .apply(
                &released,
                Event::AdmissionRecorded {
                    member: &member,
                    decision: &decision
                },
                now()
            )
            .await,
        Err(Error::Transition)
    );
    assert_eq!(enrol.start(USER, SUBJECT, now()).await.unwrap(), released);
    assert!(
        !register
            .is_handle_available(
                crgs::Handle::from_display("member_handle")
                    .unwrap()
                    .skeleton(),
                date(now())
            )
            .await
            .unwrap()
    );
    register
        .release_expired(
            date(
                "2030-01-01T00:00:00Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap()
                    .timestamp(),
            ),
            10,
        )
        .await
        .unwrap();
    assert!(
        register
            .member(&released.member_id())
            .await
            .unwrap()
            .unwrap()
            .handle
            .is_none()
    );
}

fn register_passkey(
    server: &ckyh::Passkeys<Credentials>,
) -> (
    webauthn_authenticator_rs::softtoken::SoftToken,
    ckyh::StoredPasskey,
) {
    common::register(server, USER)
}

#[tokio::test]
async fn memory_lifecycle() {
    lifecycle(
        MemoryStorage::new(COMMUNITY).unwrap(),
        crgs::Register::new(
            crgs::MemoryStorage::default(),
            crgs::ReleasePeriod::default(),
        ),
    )
    .await;
}

#[tokio::test]
async fn libsql_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("members.db")).await;
    lifecycle(
        LibsqlStorage::new(&db, COMMUNITY).unwrap(),
        crgs::Register::new(
            crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
            crgs::ReleasePeriod::default(),
        ),
    )
    .await;
}

async fn expiry<S: Storage, R: crgs::Storage>(enrol: Enrol<S>, register: crgs::Register<R>) {
    let gates = pending(&enrol, &register).await;
    let until = gates.expires_at().unwrap();
    assert_eq!(enrol.get(USER, until - 1).await.unwrap(), gates);
    assert!(
        !register
            .is_handle_available(
                crgs::Handle::from_display("member_handle")
                    .unwrap()
                    .skeleton(),
                date(until - 1)
            )
            .await
            .unwrap()
    );
    assert_eq!(
        enrol.expire_due(until, 1).await.unwrap()[0].state(),
        State::Expired
    );
    assert!(
        register
            .is_handle_available(
                crgs::Handle::from_display("member_handle")
                    .unwrap()
                    .skeleton(),
                date(until)
            )
            .await
            .unwrap()
    );
    assert!(enrol.get(USER, until).await.unwrap().needs_cleanup());
    // Another user acquires the same skeleton before old cleanup runs.
    register
        .reserve_handle(
            crgs::Reservation {
                member_id: crgs::MemberId::new(b"other".to_vec()).unwrap(),
                expires_at: date(until + 86400),
                ..reservation(&gates)
            },
            date(until),
        )
        .await
        .unwrap();
    assert_eq!(enrol.cleanup(&register, 10).await.unwrap(), 1);
    assert_eq!(enrol.cleanup(&register, 10).await.unwrap(), 0);
    assert!(
        !register
            .is_handle_available(
                crgs::Handle::from_display("member_handle")
                    .unwrap()
                    .skeleton(),
                date(until)
            )
            .await
            .unwrap()
    );
    assert!(!enrol.get(USER, until).await.unwrap().needs_cleanup());
    assert_eq!(
        enrol.start(USER, SUBJECT, until + 1).await.unwrap().state(),
        State::Expired
    );
    assert_eq!(
        enrol.start(Uuid::from_u128(2), SUBJECT, until).await,
        Err(Error::Conflict)
    );
}

#[tokio::test]
async fn memory_expiry_and_ownership_safe_cleanup() {
    expiry(
        enrol(MemoryStorage::new(COMMUNITY).unwrap()),
        crgs::Register::new(
            crgs::MemoryStorage::default(),
            crgs::ReleasePeriod::default(),
        ),
    )
    .await;
}

#[tokio::test]
async fn libsql_expiry_and_ownership_safe_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("expiry.db")).await;
    expiry(
        enrol(LibsqlStorage::new(&db, COMMUNITY).unwrap()),
        crgs::Register::new(
            crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
            crgs::ReleasePeriod::default(),
        ),
    )
    .await;
}

#[tokio::test]
async fn pending_deadline_overrides_late_events_and_changed_settings() {
    let store = MemoryStorage::new(COMMUNITY).unwrap();
    let enrol = enrol(store.clone());
    let start = enrol.start(USER, SUBJECT, now()).await.unwrap();
    let changed = Enrol::new(store, cnrl::Config::new(500, ACTION).unwrap());
    assert_eq!(changed.start(USER, SUBJECT, now()).await.unwrap(), start);
    let expired = enrol
        .apply(&start, Event::GatesStarted, start.expires_at().unwrap())
        .await
        .unwrap();
    assert_eq!(expired.state(), State::Expired);
    assert_eq!(
        enrol
            .apply(&start, Event::GatesStarted, start.expires_at().unwrap())
            .await
            .unwrap(),
        expired
    );
}

async fn no_return(store: impl Storage + Clone) {
    let e = enrol(store.clone());
    let first = e.start(USER, SUBJECT, now()).await.unwrap();
    let deadline = first.expires_at().unwrap();
    assert_eq!(
        e.view(USER, deadline).await.unwrap().state(),
        State::Expired
    );
    assert_eq!(store.load(USER).await.unwrap(), Some(first));
    assert_eq!(
        store.load_subject(SUBJECT).await.unwrap().unwrap().user(),
        USER
    );
    assert!(
        e.start(Uuid::from_u128(99), SUBJECT, deadline)
            .await
            .is_err()
    );
    assert_eq!(e.get(USER, deadline).await.unwrap().state(), State::Expired);
    assert!(
        e.start(Uuid::from_u128(99), SUBJECT, deadline + 86400)
            .await
            .is_err()
    );
    assert_eq!(
        e.start(USER, SUBJECT, deadline + 86400)
            .await
            .unwrap()
            .state(),
        State::Expired
    );
    let other = e
        .start(Uuid::from_u128(3), "other-member", now())
        .await
        .unwrap();
    e.apply(&other, Event::AllPasskeysLost, now())
        .await
        .unwrap();
    assert!(
        e.start(Uuid::from_u128(4), "other-member", now())
            .await
            .is_err()
    );
    assert_eq!(
        e.start(other.user(), "other-member", now())
            .await
            .unwrap()
            .state(),
        State::Released
    );
}
#[tokio::test]
async fn pure_expiry_views_and_no_return_hold_in_both_stores() {
    no_return(MemoryStorage::new(COMMUNITY).unwrap()).await;
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("no-return.db")).await;
    no_return(LibsqlStorage::new(&db, COMMUNITY).unwrap()).await;
}
