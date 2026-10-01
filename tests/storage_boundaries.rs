//! Boundary cases at the actual storage and sibling receipt interfaces.
mod common;

use cnrl::{Error, Event, LibsqlStorage, MemoryStorage, Record, Storage};
use common::*;
use serde_json::{Value, json};

fn change(record: &Record, changes: Value) -> Record {
    let mut value = serde_json::to_value(record).unwrap();
    for (key, value_part) in changes.as_object().unwrap() {
        value[key] = value_part.clone();
    }
    serde_json::from_value(value).unwrap()
}

async fn write_boundaries<S: Storage + Clone>(store: S) {
    let facade = enrol(store.clone());
    let row = facade.start(USER, SUBJECT, now()).await.unwrap();
    assert_eq!(row.community(), COMMUNITY);
    assert_eq!(row.user(), USER);
    assert_eq!(row.subject(), SUBJECT);
    assert_eq!(row.revision(), 1);
    assert_eq!(facade.view(USER, now()).await.unwrap(), row);
    assert!(store.load_subject("unknown").await.unwrap().is_none());
    assert_eq!(
        store.load_subject(SUBJECT).await.unwrap(),
        Some(row.clone())
    );
    let next = change(&row, json!({"state":"passkey_registered","revision":2}));
    assert_eq!(
        store
            .compare_exchange(Some(&row), &change(&next, json!({"community":"foreign"})))
            .await,
        Err(Error::Scope)
    );
    assert_eq!(
        store
            .compare_exchange(Some(&row), &change(&row, json!({"revision":2})))
            .await,
        Err(Error::Transition)
    );
    for changes in [
        json!({"community":"another-community"}),
        json!({"user":ckyh::Uuid::from_u128(2)}),
        json!({"subject":"another-subject"}),
    ] {
        assert_eq!(
            store
                .compare_exchange(Some(&change(&row, changes)), &next)
                .await,
            Err(Error::Scope)
        );
    }
    assert_eq!(
        store
            .compare_exchange(
                None,
                &change(
                    &next,
                    json!({"user":ckyh::Uuid::from_u128(2),"subject":"other"})
                )
            )
            .await,
        Err(Error::Conflict)
    );
    let premature = change(
        &next,
        json!({"revision":1,"user":ckyh::Uuid::from_u128(2),"subject":"other"}),
    );
    assert_eq!(
        store.compare_exchange(None, &premature).await,
        Err(Error::Transition)
    );
    assert_eq!(
        store
            .compare_exchange(Some(&row), &change(&next, json!({"revision":3})))
            .await,
        Err(Error::Conflict)
    );
    assert_eq!(store.load(USER).await.unwrap(), Some(row.clone()));
    assert_eq!(
        facade
            .view(USER, row.expires_at().unwrap())
            .await
            .unwrap()
            .state(),
        cnrl::State::Expired
    );
    // A pure view cannot replace the durable original lifecycle.
    assert_eq!(store.load(USER).await.unwrap(), Some(row));
}

#[tokio::test]
async fn write_boundaries_hold_in_memory_and_persistent_storage() {
    write_boundaries(MemoryStorage::new(COMMUNITY).unwrap()).await;
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("boundaries.db")).await;
    write_boundaries(LibsqlStorage::new(&db, COMMUNITY).unwrap()).await;
}

#[tokio::test]
async fn corrupted_index_projections_cannot_rebind_a_persisted_identity() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("projections.db")).await;
    let store = LibsqlStorage::new(&db, COMMUNITY).unwrap();
    let original = enrol(store.clone())
        .start(USER, SUBJECT, now())
        .await
        .unwrap();
    let scope = db.community(COMMUNITY).unwrap();
    for changes in [
        json!({"community":"foreign"}),
        json!({"user":ckyh::Uuid::from_u128(2)}),
        json!({"subject":"foreign-subject"}),
        json!({"expires_day":original.expires_at().unwrap()/86400+1}),
    ] {
        let altered = change(&original, changes);
        scope
            .execute(
                "UPDATE cnrl_enrolments SET payload = ?1 WHERE user_id = ?2",
                crlt::params![serde_json::to_string(&altered).unwrap(), USER.to_string()],
            )
            .await
            .unwrap();
        assert_eq!(store.load(USER).await, Err(Error::Storage));
        let next = change(
            &original,
            json!({"state":"passkey_registered","revision":2}),
        );
        assert_eq!(
            store.compare_exchange(Some(&original), &next).await,
            Err(Error::Storage)
        );
    }
    scope
        .execute(
            "UPDATE cnrl_enrolments SET payload = ?1, expires_day = ?2 WHERE user_id = ?3",
            crlt::params![
                serde_json::to_string(&original).unwrap(),
                "invalid-day",
                USER.to_string()
            ],
        )
        .await
        .unwrap();
    assert_eq!(store.load(USER).await, Err(Error::Storage));
}

#[tokio::test]
async fn sibling_receipts_reject_wrong_handles_and_invalid_clock_ranges() {
    let facade = enrol(MemoryStorage::new(COMMUNITY).unwrap());
    let start = facade.start(USER, SUBJECT, now()).await.unwrap();
    assert_eq!(
        facade
            .evaluate(&start, &policy(COMMUNITY), &[], now())
            .await,
        Err(Error::Transition)
    );
    let (_, passkey) = register(&passkeys(COMMUNITY), USER);
    let keyed = facade
        .apply(&start, Event::PasskeyRegistered(&passkey), now())
        .await
        .unwrap();
    let reserved = reservation(&keyed);
    let mut wrong = reserved.clone();
    wrong.member_id = crgs::MemberId::new(b"foreign".to_vec()).unwrap();
    assert_eq!(
        facade
            .apply(&keyed, Event::HandleReserved(&wrong), now())
            .await,
        Err(Error::Scope)
    );
    wrong = reserved.clone();
    wrong.expires_at += chrono::Duration::nanoseconds(1);
    assert_eq!(
        facade
            .apply(&keyed, Event::HandleReserved(&wrong), now())
            .await,
        Err(Error::InvalidInput)
    );
    assert_eq!(
        facade.apply(&keyed, Event::CredentialIssued, now()).await,
        Err(Error::Transition)
    );
    assert_eq!(
        facade.view(USER, 253_402_300_800).await,
        Err(Error::InvalidInput)
    );
    let huge = cnrl::Enrol::new(
        MemoryStorage::new("huge").unwrap(),
        cnrl::Config::new(u32::MAX, ACTION).unwrap(),
    );
    assert_eq!(
        huge.start(USER, SUBJECT, now()).await,
        Err(Error::InvalidInput)
    );
    let held = facade
        .apply(&keyed, Event::HandleReserved(&reserved), now())
        .await
        .unwrap();
    assert_eq!(
        facade
            .apply(&held, Event::HandleReserved(&reserved), now())
            .await
            .unwrap(),
        held
    );
    let gates = facade
        .apply(&held, Event::GatesStarted, now())
        .await
        .unwrap();
    assert_eq!(
        facade
            .apply(&gates, Event::GatesStarted, now())
            .await
            .unwrap(),
        gates
    );
    for at in [-1, now() + 1] {
        let mut proof = proof(COMMUNITY);
        proof.proven_at = Some(at);
        assert_eq!(
            facade.apply(&gates, Event::GatePassed(&proof), now()).await,
            Err(Error::InvalidInput)
        );
    }
}
