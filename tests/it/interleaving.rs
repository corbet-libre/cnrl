//! Controlled scheduling over real stores; every result comes from its owner.

use crate::common::*;
use ckyh::Uuid;
use cnrl::{Error, Event, LibsqlStorage, Record, Result, Storage};
use std::sync::Arc;
use tokio::sync::Barrier;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Point {
    EmptyLoad,
    Due,
    Cleanup,
}

#[derive(Clone)]
struct Pause {
    point: Point,
    entered: Arc<Barrier>,
    released: Arc<Barrier>,
}

impl Pause {
    fn new(point: Point, participants: usize) -> Self {
        Self {
            point,
            entered: Arc::new(Barrier::new(participants)),
            released: Arc::new(Barrier::new(participants)),
        }
    }
    async fn after(&self, point: Point) {
        if self.point == point {
            self.entered.wait().await;
            self.released.wait().await;
        }
    }
}

// This adapter only suspends after an actual completed read. It never creates,
// changes or fabricates a record, error, CAS result or authority receipt.
#[derive(Clone)]
struct Paused<S> {
    inner: S,
    pause: Pause,
}

impl<S: Storage> Storage for Paused<S> {
    fn community(&self) -> &str {
        self.inner.community()
    }
    async fn load(&self, user: Uuid) -> Result<Option<Record>> {
        let result = self.inner.load(user).await?;
        if result.is_none() {
            self.pause.after(Point::EmptyLoad).await;
        }
        Ok(result)
    }
    async fn load_subject(&self, subject: &str) -> Result<Option<Record>> {
        self.inner.load_subject(subject).await
    }
    async fn compare_exchange(&self, previous: Option<&Record>, next: &Record) -> Result<()> {
        self.inner.compare_exchange(previous, next).await
    }
    async fn due(&self, day: i64, limit: usize) -> Result<Vec<Record>> {
        let result = self.inner.due(day, limit).await?;
        self.pause.after(Point::Due).await;
        Ok(result)
    }
    async fn cleanup_due(&self, limit: usize) -> Result<Vec<Record>> {
        let result = self.inner.cleanup_due(limit).await?;
        self.pause.after(Point::Cleanup).await;
        Ok(result)
    }
}

async fn concurrent_start<S: Storage + Clone>(store: S, other_subject: &str) {
    let pause = Pause::new(Point::EmptyLoad, 3);
    let facade = enrol(Paused {
        inner: store.clone(),
        pause: pause.clone(),
    });
    let second = enrol(Paused {
        inner: store.clone(),
        pause: pause.clone(),
    });
    let (left, right, ()) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        tokio::join!(
            facade.start(USER, SUBJECT, now()),
            second.start(USER, other_subject, now()),
            async {
                pause.entered.wait().await;
                pause.released.wait().await;
            }
        )
    })
    .await
    .unwrap();
    let durable = store.load(USER).await.unwrap().unwrap();
    if other_subject == SUBJECT {
        assert_eq!(left.unwrap(), durable);
        assert_eq!(right.unwrap(), durable);
    } else {
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert!(left == Err(Error::Scope) || right == Err(Error::Scope));
        assert!(durable.subject() == SUBJECT || durable.subject() == other_subject);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_concurrent_initial_reads_cannot_rebind_or_duplicate_an_identity() {
    let directory = tempfile::tempdir().unwrap();
    let db = open(&directory.path().join("races.db")).await;
    for (community, subject) in [("same", SUBJECT), ("different", "another-subject")] {
        concurrent_start(cnrl::MemoryStorage::new(community).unwrap(), subject).await;
        concurrent_start(LibsqlStorage::new(&db, community).unwrap(), subject).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_actual_schema_loss_after_the_empty_read_cannot_report_registration() {
    let directory = tempfile::tempdir().unwrap();
    let db = open(&directory.path().join("schema-loss.db")).await;
    let pause = Pause::new(Point::EmptyLoad, 2);
    let facade = enrol(Paused {
        inner: LibsqlStorage::new(&db, COMMUNITY).unwrap(),
        pause: pause.clone(),
    });
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        tokio::join!(facade.start(USER, SUBJECT, now()), async {
            pause.entered.wait().await;
            let mut history = migrations().to_vec();
            history.push(crlt::Migration::new(
                3,
                "lose-enrolment-table",
                "DROP TABLE cnrl_enrolments",
            ));
            db.migrate(&history).await.unwrap();
            pause.released.wait().await;
        })
    })
    .await
    .unwrap();
    assert_eq!(result, Err(Error::Storage));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_refuses_changed_or_corrupt_rows_read_before_the_write() {
    for corrupt in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let db = open(&directory.path().join("expiry.db")).await;
        let store = LibsqlStorage::new(&db, COMMUNITY).unwrap();
        let actual = enrol(store.clone());
        let row = actual.start(USER, SUBJECT, now()).await.unwrap();
        let pause = Pause::new(Point::Due, 2);
        let facade = enrol(Paused {
            inner: store,
            pause: pause.clone(),
        });
        let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(facade.expire_due(row.expires_at().unwrap(), 1), async {
                pause.entered.wait().await;
                if corrupt {
                    db.community(COMMUNITY)
                        .unwrap()
                        .execute(
                            "UPDATE cnrl_enrolments SET payload = ?1 WHERE user_id = ?2",
                            crlt::params!["invalid", USER.to_string()],
                        )
                        .await
                        .unwrap();
                } else {
                    actual
                        .apply(&row, Event::AllPasskeysLost, now())
                        .await
                        .unwrap();
                }
                pause.released.wait().await;
            })
        })
        .await
        .unwrap();
        if corrupt {
            assert_eq!(result, Err(Error::Storage));
        } else {
            assert!(result.unwrap().is_empty());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_preserves_real_register_cancellation_across_late_store_failures() {
    for corrupt in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let db = open(&directory.path().join("cleanup.db")).await;
        let store = LibsqlStorage::new(&db, COMMUNITY).unwrap();
        let actual = enrol(store.clone());
        let register = crgs::Register::new(
            crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
            crgs::ReleasePeriod::default(),
        );
        let row = pending(&actual, &register).await;
        actual
            .apply(&row, Event::AllPasskeysLost, now())
            .await
            .unwrap();
        let pause = Pause::new(Point::Cleanup, 2);
        let facade = enrol(Paused {
            inner: store,
            pause: pause.clone(),
        });
        let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(facade.cleanup(&register, 1), async {
                pause.entered.wait().await;
                let scope = db.community(COMMUNITY).unwrap();
                if corrupt {
                    scope
                        .execute(
                            "UPDATE cnrl_enrolments SET payload = ?1 WHERE user_id = ?2",
                            crlt::params!["invalid", USER.to_string()],
                        )
                        .await
                        .unwrap();
                } else {
                    scope
                        .execute(
                            "DELETE FROM cnrl_enrolments WHERE user_id = ?1",
                            [USER.to_string()],
                        )
                        .await
                        .unwrap();
                }
                pause.released.wait().await;
            })
        })
        .await
        .unwrap();
        if corrupt {
            assert_eq!(result, Err(Error::Storage));
        } else {
            assert_eq!(result.unwrap(), 0);
        }
        assert!(
            register
                .is_handle_available(reservation(&row).handle.skeleton(), date(now()))
                .await
                .unwrap()
        );
    }
}

async fn changed_start<S: Storage + Clone>(store: S, prior_subject: &str) {
    let pause = Pause::new(Point::EmptyLoad, 2);
    let contender = enrol(Paused {
        inner: store.clone(),
        pause: pause.clone(),
    });
    let current = enrol(store.clone());
    let (result, durable) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        tokio::join!(contender.start(USER, SUBJECT, now()), async {
            pause.entered.wait().await;
            let started = current.start(USER, prior_subject, now()).await.unwrap();
            let released = current
                .apply(&started, Event::AllPasskeysLost, now())
                .await
                .unwrap();
            pause.released.wait().await;
            released
        })
    })
    .await
    .unwrap();
    if prior_subject == SUBJECT {
        assert_eq!(result.unwrap(), durable);
    } else {
        assert_eq!(result, Err(Error::Scope));
    }
    assert_eq!(store.load(USER).await.unwrap().unwrap(), durable);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_competing_start_reloads_actual_advanced_state_without_rebinding_identity() {
    let directory = tempfile::tempdir().unwrap();
    let db = open(&directory.path().join("advanced.db")).await;
    for (community, subject) in [("same", SUBJECT), ("different", "another-subject")] {
        changed_start(cnrl::MemoryStorage::new(community).unwrap(), subject).await;
        changed_start(LibsqlStorage::new(&db, community).unwrap(), subject).await;
    }
}

#[tokio::test]
async fn unavailable_register_keeps_actual_pending_cleanup_for_retry() {
    let directory = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!(
            "file://{}",
            directory.path().join("no-register.db").display()
        ),
        "",
    ))
    .await
    .unwrap();
    // The register's real storage capability has no migrated tables.
    let unavailable = crgs::Register::new(
        crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
        crgs::ReleasePeriod::default(),
    );
    let register = crgs::Register::new(
        crgs::MemoryStorage::default(),
        crgs::ReleasePeriod::default(),
    );
    let facade = enrol(cnrl::MemoryStorage::new(COMMUNITY).unwrap());
    let pending = pending(&facade, &register).await;
    let released = facade
        .apply(&pending, Event::AllPasskeysLost, now())
        .await
        .unwrap();
    assert_eq!(facade.cleanup(&unavailable, 1).await, Err(Error::Storage));
    assert_eq!(facade.get(USER, now()).await.unwrap(), released);
    assert!(released.needs_cleanup());
    assert_eq!(facade.cleanup(&register, 1).await.unwrap(), 1);
    assert!(!facade.get(USER, now()).await.unwrap().needs_cleanup());
}
