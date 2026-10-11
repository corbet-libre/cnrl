//! Original lifecycle staging in one caller-owned writer.
use super::*;

impl Enrol<crate::LibsqlStorage> {
    /// Read the original decoded current lifecycle inside the exact caller-owned
    /// database/community writer. This is the same pure view as `view`: a due
    /// pending deadline projects Expired without writing a revision or cleanup.
    ///
    /// This method grants no membership, role or authentication. The caller must
    /// verify the required actual state and member binding before its sole commit.
    /// Only success returns the writer; absent/corrupt data, a foreign writer,
    /// storage failure or cancellation drops every previously staged change.
    pub async fn get_in_transaction(
        &self,
        transaction: crlt::Transaction,
        user: Uuid,
        now: i64,
    ) -> Result<(crlt::Transaction, Record)> {
        time(now)?;
        let (transaction, record) = self.storage.load_in_transaction(transaction, user).await?;
        let record = self.project_view(record.ok_or(Error::NotFound)?, now)?;
        Ok((transaction, record))
    }

    /// Apply the exact original event and revision compare/exchange inside this
    /// database/community's existing writer, without beginning or committing it.
    ///
    /// The caller keeps genuine authentication, policy and leaf authority current
    /// and owns the only final commit after all participating owners succeed.
    /// This storage composition method creates no admission or role authority.
    /// Ownership is returned only on success; any refusal, storage error or
    /// cancelled future drops ALL staged changes. A returned Record is staged,
    /// not a durable acknowledgement. Exact stored retries retain the original
    /// compare/exchange semantics and never manufacture another revision.
    pub async fn apply_in_transaction(
        &self,
        transaction: crlt::Transaction,
        expected: &Record,
        event: Event<'_>,
        now: i64,
    ) -> Result<(crlt::Transaction, Record)> {
        let next = self.prepare_event(expected, event, now)?;
        let transaction = self
            .storage
            .compare_exchange_in_transaction(transaction, Some(expected), &next)
            .await?;
        Ok((transaction, next))
    }
}
