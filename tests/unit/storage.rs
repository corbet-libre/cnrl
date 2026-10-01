use super::*;

#[tokio::test]
async fn every_query_is_indexed() {
    let dir = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("plans.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[crlt::Migration::new(1, "cnrl", SCHEMA)])
        .await
        .unwrap();
    let scope = db.community("a").unwrap();
    let cases = [
        (LOAD, vec![Value::Text("user".into())]),
        (SUBJECT, vec![Value::Text("subject".into())]),
        (DUE, vec![Value::Integer(1), Value::Integer(10)]),
        (CLEANUP, vec![Value::Integer(10)]),
        (
            INSERT,
            vec![
                Value::Text("user".into()),
                Value::Text("subject".into()),
                Value::Integer(1),
                Value::Integer(0),
                Value::Text("{}".into()),
            ],
        ),
        (
            UPDATE,
            vec![
                Value::Null,
                Value::Integer(0),
                Value::Text("{}".into()),
                Value::Text("user".into()),
            ],
        ),
    ];
    for (sql, params) in cases {
        scope
            .explain(sql, params)
            .await
            .unwrap()
            .assert_indexed()
            .unwrap();
    }
    let plan = scope.explain(DUE, params![1, 10]).await.unwrap();
    assert!(plan.details().iter().any(|d| d.contains("cnrl_expiry")));
    let plan = scope.explain(CLEANUP, [10]).await.unwrap();
    assert!(plan.details().iter().any(|d| d.contains("cnrl_cleanup")));
}

#[tokio::test]
async fn cleanup_rechecks_real_payloads_after_its_index_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("cleanup-race.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[crlt::Migration::new(1, "cnrl", SCHEMA)])
        .await
        .unwrap();
    let store = LibsqlStorage::new(&db, "a").unwrap();
    let facade = crate::Enrol::new(store.clone(), crate::Config::new(1, "membership").unwrap());
    let now = 1_800_000_000;
    let row = facade
        .start(Uuid::from_u128(1), "subject", now)
        .await
        .unwrap();
    // Build persisted lifecycle states through the real storage transition
    // validator; these values are private storage snapshots, never authority.
    let mut keyed = row.clone();
    keyed.state = State::PasskeyRegistered;
    keyed.revision += 1;
    store.compare_exchange(Some(&row), &keyed).await.unwrap();
    let mut held = keyed.clone();
    held.state = State::HandleReserved;
    held.skeleton = Some("handle".into());
    held.revision += 1;
    store.compare_exchange(Some(&keyed), &held).await.unwrap();
    let released = facade
        .apply(&held, crate::Event::AllPasskeysLost, now)
        .await
        .unwrap();
    let keys_before_clear = store.scope.query(CLEANUP, [1]).await.unwrap();
    let keys_before_delete = store.scope.query(CLEANUP, [1]).await.unwrap();
    assert_eq!(keys_before_clear.len(), 1);
    assert_eq!(keys_before_delete.len(), 1);
    assert_eq!(store.cleanup_due(1).await.unwrap(), vec![released.clone()]);
    let mut cleaned = released.clone();
    cleaned.skeleton = None;
    cleaned.revision += 1;
    store
        .compare_exchange(Some(&released), &cleaned)
        .await
        .unwrap();
    assert!(
        store
            .load_cleanup(keys_before_clear)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.load(cleaned.user).await.unwrap(),
        Some(cleaned.clone())
    );
    store
        .scope
        .execute(
            "DELETE FROM cnrl_enrolments WHERE user_id = ?1",
            [cleaned.user.to_string()],
        )
        .await
        .unwrap();
    assert!(
        store
            .load_cleanup(keys_before_delete)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(store.load(cleaned.user).await.unwrap().is_none());
}
