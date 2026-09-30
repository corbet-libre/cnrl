use std::{collections::BTreeMap, future::Future, sync::Arc};

use cpky::Uuid;
use crlt::{Community, Row, Value, params};
use tokio::sync::Mutex;

use crate::{Error, Record, Result, State, enrol::batch, model::text};

/// Add this DDL to the service's complete crlt migration history.
pub const SCHEMA: &str = include_str!("schema.sql");

/// Storage for exactly one community. Implementations must make compare/exchange
/// atomic, enforce unique subjects and users, and retain only the latest row.
/// Records are trusted storage values, never client input.
pub trait Storage: Send + Sync {
    /// Fixed community scope; never chosen from a member request.
    fn community(&self) -> &str;
    /// Read the current snapshot using the passkey owner's unique index.
    fn load(&self, user: Uuid) -> impl Future<Output = Result<Option<Record>>> + Send;
    /// Read through the permanent unique community pseudonym index.
    fn load_subject(&self, subject: &str) -> impl Future<Output = Result<Option<Record>>> + Send;
    /// Replace exactly `previous`, or insert if absent. If the stored record
    /// already equals `next`, succeed without writing (lost-response replay).
    /// Otherwise return Conflict. Errors/cancellation must leave no partial write.
    fn compare_exchange(
        &self,
        previous: Option<&Record>,
        next: &Record,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Pending expiry index, ordered by deadline then user, at most `limit` rows.
    fn due(&self, day: i64, limit: usize) -> impl Future<Output = Result<Vec<Record>>> + Send;
    /// Terminal reservation cleanup index, at most `limit` rows.
    fn cleanup_due(&self, limit: usize) -> impl Future<Output = Result<Vec<Record>>> + Send;
}

/// Transactional in-memory storage for tests. Clones share a fixed community.
#[derive(Clone)]
pub struct MemoryStorage {
    community: String,
    rows: Arc<Mutex<BTreeMap<Uuid, Record>>>,
}

impl MemoryStorage {
    /// Create an empty community, with no wall clock or logging.
    pub fn new(community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        text(&community)?;
        Ok(Self {
            community,
            rows: Arc::default(),
        })
    }
}

impl Storage for MemoryStorage {
    fn community(&self) -> &str {
        &self.community
    }

    async fn load(&self, user: Uuid) -> Result<Option<Record>> {
        Ok(self.rows.lock().await.get(&user).cloned())
    }

    async fn load_subject(&self, subject: &str) -> Result<Option<Record>> {
        text(subject)?;
        Ok(self
            .rows
            .lock()
            .await
            .values()
            .find(|row| row.subject == subject)
            .cloned())
    }

    async fn compare_exchange(&self, previous: Option<&Record>, next: &Record) -> Result<()> {
        validate_write(&self.community, previous, next)?;
        let mut rows = self.rows.lock().await;
        let current = rows.get(&next.user);
        if current == Some(next) {
            return Ok(());
        }
        if current != previous {
            return Err(Error::Conflict);
        }
        if rows
            .values()
            .any(|r| r.subject == next.subject && r.user != next.user)
        {
            return Err(Error::Conflict);
        }
        rows.insert(next.user, next.clone());
        Ok(())
    }

    async fn due(&self, day: i64, limit: usize) -> Result<Vec<Record>> {
        batch(limit)?;
        let rows = self.rows.lock().await;
        let mut due: Vec<_> = rows
            .values()
            .filter(|r| r.expires_day.is_some_and(|d| d <= day))
            .cloned()
            .collect();
        due.sort_by_key(|r| (r.expires_day, r.user));
        due.truncate(limit);
        Ok(due)
    }

    async fn cleanup_due(&self, limit: usize) -> Result<Vec<Record>> {
        batch(limit)?;
        Ok(self
            .rows
            .lock()
            .await
            .values()
            .filter(|r| r.needs_cleanup())
            .take(limit)
            .cloned()
            .collect())
    }
}

/// Persistent storage through crlt and its official libSQL driver.
#[derive(Clone)]
pub struct LibsqlStorage {
    community: String,
    scope: Community,
}

impl LibsqlStorage {
    /// Use a service-owned database after applying SCHEMA. Deploy one DB per community.
    pub fn new(db: &crlt::Db, community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        let scope = db.community(community.clone())?;
        Ok(Self { community, scope })
    }

    fn decode(&self, row: &Row) -> Result<Record> {
        let record: Record = serde_json::from_str(row.get_str(0)?).map_err(|_| Error::Storage)?;
        record.validate().map_err(|_| Error::Storage)?;
        let expiry = match row.get_value(3)? {
            Value::Null => None,
            Value::Integer(value) => Some(*value),
            _ => return Err(Error::Storage),
        };
        if record.community != self.community
            || row.get_str(1)? != record.user.to_string()
            || row.get_str(2)? != record.subject
            || expiry != record.expires_day
            || row.get_i64(4)? != i64::from(record.needs_cleanup())
        {
            return Err(Error::Storage);
        }
        Ok(record)
    }
}

const LOAD: &str = "SELECT payload, user_id, subject, expires_day, cleanup FROM cnrl_enrolments WHERE user_id = ?1";
const SUBJECT: &str = "SELECT user_id FROM cnrl_enrolments WHERE subject = ?1";
const DUE: &str = "SELECT payload, user_id, subject, expires_day, cleanup FROM cnrl_enrolments WHERE expires_day <= ?1 ORDER BY expires_day, user_id LIMIT ?2";
const CLEANUP: &str =
    "SELECT user_id FROM cnrl_enrolments WHERE cleanup = 1 ORDER BY user_id LIMIT ?1";
const INSERT: &str = "INSERT INTO cnrl_enrolments (user_id, subject, expires_day, cleanup, payload) VALUES (?1, ?2, ?3, ?4, ?5)";
const UPDATE: &str =
    "UPDATE cnrl_enrolments SET expires_day = ?1, cleanup = ?2, payload = ?3 WHERE user_id = ?4";

impl Storage for LibsqlStorage {
    fn community(&self) -> &str {
        &self.community
    }

    async fn load(&self, user: Uuid) -> Result<Option<Record>> {
        self.scope
            .query(LOAD, [user.to_string()])
            .await?
            .first()
            .map(|r| self.decode(r))
            .transpose()
    }

    async fn load_subject(&self, subject: &str) -> Result<Option<Record>> {
        text(subject)?;
        match self.scope.query(SUBJECT, [subject]).await?.first() {
            Some(row) => {
                self.load(Uuid::parse_str(row.get_str(0)?).map_err(|_| Error::Storage)?)
                    .await
            }
            None => Ok(None),
        }
    }

    async fn compare_exchange(&self, previous: Option<&Record>, next: &Record) -> Result<()> {
        validate_write(&self.community, previous, next)?;
        let mut tx = self.scope.tx().await?;
        let current = tx
            .query(LOAD, [next.user.to_string()])
            .await?
            .first()
            .map(|r| self.decode(r))
            .transpose()?;
        if current.as_ref() == Some(next) {
            tx.commit().await?;
            return Ok(());
        }
        if current.as_ref() != previous {
            tx.rollback().await?;
            return Err(Error::Conflict);
        }
        let payload = serde_json::to_string(next).map_err(|_| Error::Storage)?;
        if previous.is_some() {
            tx.execute(
                UPDATE,
                params![
                    next.expires_day,
                    i64::from(next.needs_cleanup()),
                    payload,
                    next.user.to_string()
                ],
            )
            .await?;
        } else {
            if !tx.query(SUBJECT, [next.subject.as_str()]).await?.is_empty() {
                tx.rollback().await?;
                return Err(Error::Conflict);
            }
            tx.execute(
                INSERT,
                params![
                    next.user.to_string(),
                    next.subject.clone(),
                    next.expires_day,
                    i64::from(next.needs_cleanup()),
                    payload
                ],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn due(&self, day: i64, limit: usize) -> Result<Vec<Record>> {
        batch(limit)?;
        self.scope
            .query(DUE, params![day, limit as i64])
            .await?
            .iter()
            .map(|r| self.decode(r))
            .collect()
    }

    async fn cleanup_due(&self, limit: usize) -> Result<Vec<Record>> {
        batch(limit)?;
        // Enumerate only keys so SQLite uses the covering cleanup index even
        // when very few rows exist, then load each payload through its primary key.
        let mut records = Vec::new();
        for row in self.scope.query(CLEANUP, [limit as i64]).await? {
            let user = Uuid::parse_str(row.get_str(0)?).map_err(|_| Error::Storage)?;
            if let Some(record) = self.load(user).await?
                && record.needs_cleanup()
            {
                records.push(record);
            }
        }
        Ok(records)
    }
}

fn validate_write(community: &str, previous: Option<&Record>, next: &Record) -> Result<()> {
    next.validate()?;
    if next.community != community {
        return Err(Error::Scope);
    }
    if let Some(previous) = previous {
        previous.validate()?;
        if previous.community != community
            || previous.user != next.user
            || previous.subject != next.subject
        {
            return Err(Error::Scope);
        }
        if next != previous && previous.revision.checked_add(1) != Some(next.revision) {
            return Err(Error::Conflict);
        }
        validate_transition(previous, next)?;
    } else {
        if next.revision != 1 {
            return Err(Error::Conflict);
        }
        if next.state != State::Started {
            return Err(Error::Transition);
        }
    }
    Ok(())
}

fn validate_transition(previous: &Record, next: &Record) -> Result<()> {
    if previous == next {
        return Ok(());
    }
    use State::*;
    let allowed = match (previous.state, next.state) {
        (Started, PasskeyRegistered)
        | (PasskeyRegistered, HandleReserved)
        | (HandleReserved, GatesInProgress)
        | (GatesInProgress | Lapsed, Admitted)
        | (Admitted, Lapsed) => true,
        (old, new) if old == new && old.is_terminal() => {
            previous.skeleton.is_some() && next.skeleton.is_none()
        }
        (state, Expired) => state.is_pending(),
        (state, Released) => !state.is_terminal(),
        _ => false,
    };
    if !allowed
        || (previous.state.is_pending()
            && next.state.is_pending()
            && previous.expires_day != next.expires_day)
        || (previous.state != PasskeyRegistered
            && next.state.is_pending()
            && previous.skeleton != next.skeleton)
        || (previous.state != next.state
            && next.state.is_terminal()
            && previous.skeleton != next.skeleton)
    {
        return Err(Error::Transition);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
