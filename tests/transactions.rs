//! Trusted lifecycle storage composition; this does not qualify production
//! admission, voucher signatures or configured external gates.
mod common;

use cnrl::{Enrol, Error, Event, LibsqlStorage, Record, State, Storage};
use common::*;
use std::future::Future;

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    db: crlt::Db,
    store: LibsqlStorage,
    enrol: Enrol<LibsqlStorage>,
    register: crgs::Register<crgs::LibsqlStorage>,
    held: Record,
    decision: crbk::Decision,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("joined.db");
        let db = open(&path).await;
        let store = LibsqlStorage::new(&db, COMMUNITY).unwrap();
        let enrol = common::enrol(store.clone());
        let register = crgs::Register::new(
            crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
            crgs::ReleasePeriod::months(1),
        );
        let started = enrol.start(USER, SUBJECT, now()).await.unwrap();
        let keys = passkeys(COMMUNITY);
        let (_, passkey) = common::register(&keys, USER);
        let keyed = enrol
            .apply(&started, Event::PasskeyRegistered(&passkey), now())
            .await
            .unwrap();
        let reserved = register
            .reserve_handle(reservation(&keyed), date(now()))
            .await
            .unwrap();
        let held = enrol
            .apply(&keyed, Event::HandleReserved(&reserved), now())
            .await
            .unwrap();
        // Use the real Rulebook with an explicitly empty test requirement list,
        // not a fabricated Decision or a purported verified external proof.
        let mut settings = policy(COMMUNITY);
        settings.content.insert(
            crbk::action_key(ACTION),
            serde_json::to_value(crbk::ActionPolicy::default()).unwrap(),
        );
        let decision = settings
            .may(
                crbk::Subject {
                    id: held.subject(),
                    membership: held.state().membership(),
                },
                ACTION,
                &Vec::<crbk::GateResult>::new(),
                now(),
            )
            .unwrap();
        assert!(decision.allowed);
        Self {
            _directory: directory,
            path,
            db,
            store,
            enrol,
            register,
            held,
            decision,
        }
    }

    async fn gates(&self) -> (crlt::Transaction, Record) {
        self.enrol
            .apply_in_transaction(
                self.db.community(COMMUNITY).unwrap().tx().await.unwrap(),
                &self.held,
                Event::PolicyEvaluated(&self.decision),
                now(),
            )
            .await
            .unwrap()
    }

    async fn unchanged(&self) {
        assert_eq!(
            self.store.load(USER).await.unwrap(),
            Some(self.held.clone())
        );
        assert!(
            self.register
                .member(&self.held.member_id())
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn original_policy_register_and_admission_share_one_commit_and_exact_retry() {
    let fixture = Fixture::new().await;
    let (tx, gates) = fixture.gates().await;
    let (tx, member) = fixture
        .register
        .admit_in_transaction(tx, admission(&gates), date(now()))
        .await
        .unwrap();
    let (tx, admitted) = fixture
        .enrol
        .apply_in_transaction(
            tx,
            &gates,
            Event::AdmissionRecorded {
                member: &member,
                decision: &fixture.decision,
            },
            now(),
        )
        .await
        .unwrap();
    assert_eq!(admitted.state(), State::Admitted);
    tx.commit().await.unwrap();
    assert_eq!(
        fixture.store.load(USER).await.unwrap(),
        Some(admitted.clone())
    );
    assert_eq!(
        fixture.register.member(&gates.member_id()).await.unwrap(),
        Some(member.clone())
    );

    let (tx, retried) = fixture
        .enrol
        .apply_in_transaction(
            fixture.db.community(COMMUNITY).unwrap().tx().await.unwrap(),
            &gates,
            Event::AdmissionRecorded {
                member: &member,
                decision: &fixture.decision,
            },
            now(),
        )
        .await
        .unwrap();
    assert_eq!(retried, admitted);
    tx.commit().await.unwrap();
    assert_eq!(
        fixture
            .enrol
            .apply(
                &gates,
                Event::AdmissionRecorded {
                    member: &member,
                    decision: &fixture.decision
                },
                now()
            )
            .await
            .unwrap(),
        admitted
    );
}

#[tokio::test]
async fn later_refusal_drops_all_staged_owners() {
    let fixture = Fixture::new().await;
    let (tx, gates) = fixture.gates().await;
    let (tx, _) = fixture
        .register
        .admit_in_transaction(tx, admission(&gates), date(now()))
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .enrol
            .apply_in_transaction(tx, &gates, Event::CredentialIssued, now())
            .await,
        Err(Error::Transition)
    ));
    fixture.unchanged().await;
}

#[tokio::test]
async fn foreign_community_and_separate_reopened_handle_refuse_and_rollback() {
    let fixture = Fixture::new().await;
    let other_store = LibsqlStorage::new(&fixture.db, "other").unwrap();
    let other = common::enrol(other_store.clone());
    let initial = other.start(USER, "other-subject", now()).await.unwrap();
    let (tx, _) = other
        .apply_in_transaction(
            fixture.db.community("other").unwrap().tx().await.unwrap(),
            &initial,
            Event::AllPasskeysLost,
            now(),
        )
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .enrol
            .apply_in_transaction(tx, &fixture.held, Event::GatesStarted, now())
            .await,
        Err(Error::Scope)
    ));
    assert_eq!(other_store.load(USER).await.unwrap(), Some(initial));

    let reopened = open(&fixture.path).await;
    let other_handle = common::enrol(LibsqlStorage::new(&reopened, COMMUNITY).unwrap());
    let (tx, _) = other_handle
        .apply_in_transaction(
            reopened.community(COMMUNITY).unwrap().tx().await.unwrap(),
            &fixture.held,
            Event::AllPasskeysLost,
            now(),
        )
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .enrol
            .apply_in_transaction(tx, &fixture.held, Event::GatesStarted, now())
            .await,
        Err(Error::Scope)
    ));
    fixture.unchanged().await;
}

#[tokio::test]
async fn stale_revision_conflict_rolls_back_another_staged_lifecycle() {
    let fixture = Fixture::new().await;
    let progressed = fixture
        .enrol
        .apply(&fixture.held, Event::GatesStarted, now())
        .await
        .unwrap();
    let released = fixture
        .enrol
        .apply(&progressed, Event::AllPasskeysLost, now())
        .await
        .unwrap();
    let second = fixture
        .enrol
        .start(ckyh::Uuid::from_u128(2), "second", now())
        .await
        .unwrap();
    let (tx, _) = fixture
        .enrol
        .apply_in_transaction(
            fixture.db.community(COMMUNITY).unwrap().tx().await.unwrap(),
            &second,
            Event::AllPasskeysLost,
            now(),
        )
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .enrol
            .apply_in_transaction(
                tx,
                &fixture.held,
                Event::PolicyEvaluated(&fixture.decision),
                now()
            )
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(fixture.store.load(USER).await.unwrap(), Some(released));
    assert_eq!(
        fixture.store.load(second.user()).await.unwrap(),
        Some(second)
    );
}

#[tokio::test]
async fn abandoning_the_owned_future_before_poll_rolls_back_prior_staging() {
    let fixture = Fixture::new().await;
    let (tx, gates) = fixture.gates().await;
    let future = fixture
        .enrol
        .apply_in_transaction(tx, &gates, Event::GatesStarted, now());
    drop(future);
    fixture.unchanged().await;
}

#[tokio::test]
async fn dropping_after_an_actual_poll_never_commits_the_joined_writer() {
    let fixture = Fixture::new().await;
    let (tx, gates) = fixture.gates().await;
    let mut future = Box::pin(fixture.enrol.apply_in_transaction(
        tx,
        &gates,
        Event::GatesStarted,
        now(),
    ));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Pending => drop(future),
        std::task::Poll::Ready(result) => {
            let (tx, staged) = result.unwrap();
            assert_eq!(staged, gates);
            drop(tx);
            drop(future);
        }
    }
    fixture.unchanged().await;
}

#[tokio::test]
async fn decoded_current_and_expired_views_never_mutate_the_original_record() {
    let fixture = Fixture::new().await;
    for at in [now(), fixture.held.expires_at().unwrap()] {
        let (tx, view) = fixture
            .enrol
            .get_in_transaction(
                fixture.db.community(COMMUNITY).unwrap().tx().await.unwrap(),
                USER,
                at,
            )
            .await
            .unwrap();
        assert_eq!(view.revision(), fixture.held.revision());
        assert_eq!(view.member_id(), fixture.held.member_id());
        assert_eq!(
            view.state(),
            if at == now() {
                State::HandleReserved
            } else {
                State::Expired
            }
        );
        tx.commit().await.unwrap();
        fixture.unchanged().await;
    }
}

#[tokio::test]
async fn missing_or_corrupt_read_drops_prior_staging_without_returning_evidence() {
    let fixture = Fixture::new().await;
    let (tx, _) = fixture.gates().await;
    assert!(matches!(
        fixture
            .enrol
            .get_in_transaction(tx, ckyh::Uuid::from_u128(99), now())
            .await,
        Err(Error::NotFound)
    ));
    fixture.unchanged().await;

    let (mut tx, _) = fixture.gates().await;
    // A real same-writer corruption of the indexed copy must fail the original
    // decoder, and dropping the refused read must undo both participating writes.
    tx.execute(
        "UPDATE cnrl_enrolments SET cleanup = 1 WHERE user_id = ?1",
        [USER.to_string()],
    )
    .await
    .unwrap();
    assert!(matches!(
        fixture.enrol.get_in_transaction(tx, USER, now()).await,
        Err(Error::Storage)
    ));
    fixture.unchanged().await;
}

#[tokio::test]
async fn read_refuses_foreign_community_and_reopened_handle_and_drops_the_writer() {
    let fixture = Fixture::new().await;
    let other = common::enrol(LibsqlStorage::new(&fixture.db, "other").unwrap());
    let (tx, _) = fixture.gates().await;
    assert!(matches!(
        other.get_in_transaction(tx, USER, now()).await,
        Err(Error::Scope)
    ));
    fixture.unchanged().await;

    let reopened = open(&fixture.path).await;
    let other_handle = common::enrol(LibsqlStorage::new(&reopened, COMMUNITY).unwrap());
    let (tx, _) = fixture.gates().await;
    assert!(matches!(
        other_handle.get_in_transaction(tx, USER, now()).await,
        Err(Error::Scope)
    ));
    fixture.unchanged().await;
}
