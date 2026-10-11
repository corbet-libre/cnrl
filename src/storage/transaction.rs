//! One implementation of the original revision CAS for owned or joined writers.
use super::*;

impl LibsqlStorage {
    pub(crate) async fn compare_exchange_in_transaction(
        &self,
        mut tx: crlt::Transaction,
        previous: Option<&Record>,
        next: &Record,
    ) -> Result<crlt::Transaction> {
        if !tx.belongs_to(&self.scope) {
            return Err(Error::Scope);
        }
        self.stage_compare_exchange(&mut tx, previous, next).await?;
        Ok(tx)
    }

    pub(super) async fn stage_compare_exchange(
        &self,
        tx: &mut crlt::Transaction,
        previous: Option<&Record>,
        next: &Record,
    ) -> Result<()> {
        validate_write(&self.community, previous, next)?;
        let current = tx
            .query(LOAD, [next.user.to_string()])
            .await?
            .first()
            .map(|r| self.decode(r))
            .transpose()?;
        if current.as_ref() == Some(next) {
            return Ok(());
        }
        if current.as_ref() != previous {
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
        Ok(())
    }
}
