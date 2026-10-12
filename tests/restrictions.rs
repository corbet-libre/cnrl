//! Verified clbs restrictions, literal scope and resumable release cleanup.
mod common;

use clbs::{Order, OrderKind, SignedOrder};
use cnrl::{Error, Event, LibsqlStorage, State};
use common::*;
use ed25519_dalek::{Signature, Signer, SigningKey};

// Authentic signed fixtures at clbs's external authority boundary.
struct Verifier;
impl Verifier {
    fn verify(&self, order: &SignedOrder) -> clbs::Result<()> {
        let signature = Signature::from_slice(&order.proof).map_err(|_| clbs::Error::Denied)?;
        SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .verify_strict(&order.order.signing_payload()?, &signature)
            .map_err(|_| clbs::Error::Denied)
    }
}
impl clbs::Verifier for Verifier {
    async fn verify_legal(&self, order: &SignedOrder) -> clbs::Result<()> {
        self.verify(order)
    }
    async fn verify_self_ban(&self, order: &SignedOrder) -> clbs::Result<()> {
        self.verify(order)
    }
}

fn order(id: &str, kind: OrderKind) -> SignedOrder {
    let entered_by = if kind == OrderKind::SelfBan {
        SUBJECT
    } else {
        "root"
    };
    let order = Order {
        community: COMMUNITY.into(),
        id: id.into(),
        subject: SUBJECT.into(),
        reference: "test-reference".into(),
        entered_by: entered_by.into(),
        kind,
    };
    let proof = SigningKey::from_bytes(&[7; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    SignedOrder { order, proof }
}

fn legal() -> OrderKind {
    OrderKind::Legal {
        authority: "test-court".into(),
    }
}

#[tokio::test]
async fn self_ban_releases_pending_and_cleanup_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("self-ban.db");
    let db = open(&path).await;
    let enrol = enrol(LibsqlStorage::new(&db, COMMUNITY).unwrap());
    let register = crgs::Register::new(
        crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
        crgs::ReleasePeriod::default(),
    );
    let pending = pending(&enrol, &register).await;
    let gate = clbs::Gate::new(clbs::MemoryStore::new(COMMUNITY).unwrap(), Verifier);
    // Legal verification is RAM-only; cnrl/crgs still exercise actual durable cleanup.
    let signed = order("self-ban", OrderKind::SelfBan);
    gate.self_ban(&signed).await.unwrap();
    let verified = gate.record("self-ban").await.unwrap().unwrap();
    let released = enrol
        .apply(&pending, Event::Restriction(&verified), now())
        .await
        .unwrap();
    assert_eq!(released.state(), State::Released);
    assert!(released.needs_cleanup());
    assert_eq!(
        enrol
            .apply(&pending, Event::Restriction(&verified), now())
            .await
            .unwrap(),
        released
    );
    // Simulate a process dying after cancel but before clearing cnrl's marker.
    register
        .cancel_reservation(
            &released.member_id(),
            crgs::Handle::from_display("member_handle")
                .unwrap()
                .skeleton(),
        )
        .await
        .unwrap();
    drop(register);
    drop(gate);
    drop(enrol);
    drop(db);
    let db = open(&path).await;
    let enrol = common::enrol(LibsqlStorage::new(&db, COMMUNITY).unwrap());
    let register = crgs::Register::new(
        crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
        crgs::ReleasePeriod::default(),
    );
    assert_eq!(enrol.get(USER, now()).await.unwrap(), released);
    assert_eq!(enrol.cleanup(&register, 10).await.unwrap(), 1);
    assert_eq!(enrol.cleanup(&register, 10).await.unwrap(), 0);
    assert!(
        register
            .is_handle_available(
                crgs::Handle::from_display("member_handle")
                    .unwrap()
                    .skeleton(),
                date(now())
            )
            .await
            .unwrap()
    );
    let row = enrol.get(USER, now()).await.unwrap();
    assert!(
        !serde_json::to_string(&row)
            .unwrap()
            .contains("test-reference")
    );
    assert!(!row.needs_cleanup());
}

#[tokio::test]
async fn permanent_legal_block_releases_the_enrolment() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("legal.db")).await;
    let enrol = enrol(LibsqlStorage::new(&db, COMMUNITY).unwrap());
    let register = crgs::Register::new(
        crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
        crgs::ReleasePeriod::default(),
    );
    let gates = pending(&enrol, &register).await;
    let (_, allowed) = enrol
        .evaluate(&gates, &policy(COMMUNITY), &[proof(COMMUNITY)], now())
        .await
        .unwrap();
    let member = register
        .admit(admission(&gates), date(now()))
        .await
        .unwrap();
    let admitted = enrol
        .apply(
            &gates,
            Event::AdmissionRecorded {
                member: &member,
                decision: &allowed,
            },
            now(),
        )
        .await
        .unwrap();
    let gate = clbs::Gate::new(clbs::MemoryStore::new(COMMUNITY).unwrap(), Verifier);
    let permanent = order("permanent", legal());
    gate.record_legal(&permanent).await.unwrap();
    let permanent = gate.record("permanent").await.unwrap().unwrap();
    let released = enrol
        .apply(&admitted, Event::Restriction(&permanent), now())
        .await
        .unwrap();
    assert_eq!(released.state(), State::Released);
    assert!(!released.needs_cleanup());
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
}

#[tokio::test]
async fn invalid_signatures_cannot_produce_release_receipts() {
    let gate = clbs::Gate::new(clbs::MemoryStore::new(COMMUNITY).unwrap(), Verifier);
    let mut signed = order("tampered", OrderKind::SelfBan);
    signed.order.subject = "tampered".into();
    assert!(gate.self_ban(&signed).await.is_err());
    assert!(gate.record("tampered").await.unwrap().is_none());
}

#[tokio::test]
async fn authentic_foreign_restrictions_cannot_change_another_enrolment() {
    let enrol = enrol(cnrl::MemoryStorage::new(COMMUNITY).unwrap());
    let row = enrol.start(USER, SUBJECT, now()).await.unwrap();
    for (community, subject) in [("foreign", SUBJECT), (COMMUNITY, "foreign-member")] {
        let gate = clbs::Gate::new(clbs::MemoryStore::new(community).unwrap(), Verifier);
        let mut signed = order("foreign", legal());
        signed.order.community = community.into();
        signed.order.subject = subject.into();
        signed.proof = SigningKey::from_bytes(&[7; 32])
            .sign(&signed.order.signing_payload().unwrap())
            .to_bytes()
            .to_vec();
        gate.record_legal(&signed).await.unwrap();
        let record = gate.record("foreign").await.unwrap().unwrap();
        assert_eq!(
            enrol.apply(&row, Event::Restriction(&record), now()).await,
            Err(Error::Scope)
        );
    }
    assert_eq!(enrol.get(USER, now()).await.unwrap(), row);
}
