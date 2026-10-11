//! Original lifecycle staging in one caller-owned writer.
use super::*;

impl Enrol<crate::LibsqlStorage> {
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
