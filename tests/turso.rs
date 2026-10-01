//! Opt-in remote round trip; no public-CI credentials or default remote traffic.
use cnrl::{Config, Enrol, LibsqlStorage, State};

#[tokio::test]
async fn optional_turso_round_trip() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        eprintln!("Skipping Turso: TURSO_URL and TURSO_TOKEN must both be set");
        return;
    };
    if url.is_empty() || token.is_empty() {
        eprintln!("Skipping Turso: TURSO_URL and TURSO_TOKEN must both be nonempty");
        return;
    }
    let db = crlt::Db::open(crlt::Config::new(url, token)).await.unwrap();
    db.migrate(&[crlt::Migration::new(1, "cnrl remote test", cnrl::SCHEMA)])
        .await
        .unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let community = format!("cnrl-test-{nonce}");
    let enrol = Enrol::new(
        LibsqlStorage::new(&db, &community).unwrap(),
        Config::new(1, "membership").unwrap(),
    );
    let now = 1_790_769_600;
    let row = enrol
        .start(ckyh::Uuid::from_u128(1), "test-pseudonym", now)
        .await
        .unwrap();
    assert_eq!(row.state(), State::Started);
    assert_eq!(enrol.get(row.user(), now).await.unwrap(), row);
    assert_eq!(
        enrol
            .expire_due(row.expires_at().unwrap(), 1)
            .await
            .unwrap()[0]
            .state(),
        State::Expired
    );
}
