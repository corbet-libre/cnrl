use chrono::Datelike;
use ckyh::Uuid;

use crate::{
    Config, Error, Event, Record, Result, State, Storage,
    model::{DAY, text, time},
};

mod transaction;

/// Community enrolment facade. Clones of a storage backend share current state.
pub struct Enrol<S> {
    storage: S,
    config: Config,
}

impl<S: Storage> Enrol<S> {
    /// Use a fixed community capability and resolved platform settings.
    pub fn new(storage: S, config: Config) -> Self {
        Self { storage, config }
    }

    /// Start once. Retries return the existing row and never extend its deadline.
    /// The service binds ckyh's user UUID to the canonical community pseudonym.
    pub async fn start(&self, user: Uuid, subject: &str, now: i64) -> Result<Record> {
        time(now)?;
        text(subject)?;
        if let Some(existing) = self.storage.load(user).await? {
            if existing.subject != subject {
                return Err(Error::Scope);
            }
            return self.refresh(&existing, now).await;
        }
        // time(now) bounds the year to 9999, and pending_days is u32. The sum
        // and product fit i64; time still rejects a deadline past year 9999.
        let expires_day = now / DAY + i64::from(self.config.pending_days);
        time(expires_day * DAY)?;
        let record = Record {
            community: self.storage.community().into(),
            user,
            subject: subject.into(),
            state: State::Started,
            revision: 1,
            expires_day: Some(expires_day),
            skeleton: None,
        };
        record.validate()?;
        match self.storage.compare_exchange(None, &record).await {
            Ok(()) => Ok(record),
            Err(Error::Conflict) => {
                let current = self.storage.load(user).await?.ok_or(Error::Conflict)?;
                if current.subject != subject {
                    return Err(Error::Scope);
                }
                self.refresh(&current, now).await
            }
            Err(error) => Err(error),
        }
    }

    /// Trusted service lookup. Reading does not record activity; due pending
    /// rows become expired. Client-facing callers should use `resume`.
    pub async fn get(&self, user: Uuid, now: i64) -> Result<Record> {
        let record = self.storage.load(user).await?.ok_or(Error::NotFound)?;
        self.refresh(&record, now).await
    }

    /// Pure current view: reflect a passed registration deadline without writing
    /// expiry, cleanup or activity state. Maintenance owns durable expiration.
    pub async fn view(&self, user: Uuid, now: i64) -> Result<Record> {
        time(now)?;
        let record = self.storage.load(user).await?.ok_or(Error::NotFound)?;
        self.project_view(record, now)
    }

    fn project_view(&self, mut record: Record, now: i64) -> Result<Record> {
        self.scope(&record)?;
        if record.expires_at().is_some_and(|until| until <= now) {
            record.state = State::Expired;
            record.expires_day = None;
        }
        Ok(record)
    }

    /// Resume after ckyh has authenticated and committed its counter update.
    /// Additional passkeys for the same ckyh user resume the same lifecycle.
    pub async fn resume(&self, auth: &ckyh::Authentication, now: i64) -> Result<Record> {
        if auth.community() != self.storage.community() {
            return Err(Error::Scope);
        }
        self.get(auth.member(), now).await
    }

    /// Apply an event to the caller's trusted snapshot. An exact retry of the
    /// same snapshot/event returns the same row. A later revision conflicts,
    /// including after a complete admitted/lapsed/admitted cycle.
    pub async fn apply(&self, expected: &Record, event: Event<'_>, now: i64) -> Result<Record> {
        let next = self.prepare_event(expected, event, now)?;
        self.storage.compare_exchange(Some(expected), &next).await?;
        Ok(next)
    }

    fn prepare_event(&self, expected: &Record, event: Event<'_>, now: i64) -> Result<Record> {
        self.scope(expected)?;
        let date = time(now)?;
        let mut next = expected.clone();
        // Expiry takes precedence over late gate, policy and registration events.
        if expected.expires_at().is_some_and(|until| until <= now) {
            next.state = State::Expired;
            next.expires_day = None;
            return prepare_record(expected, next);
        }
        if expected.state.is_terminal() {
            return Err(Error::Transition);
        }
        match event {
            Event::PasskeyRegistered(passkey) => {
                if passkey.community() != expected.community || passkey.member() != expected.user {
                    return Err(Error::Scope);
                }
                if passkey.is_revoked() {
                    return Err(Error::InvalidInput);
                }
                if next.state == State::Started {
                    next.state = State::PasskeyRegistered;
                }
            }
            Event::HandleReserved(reservation) => {
                if reservation.member_id != expected.member_id() {
                    return Err(Error::Scope);
                }
                if expected.expires_at() != Some(reservation.expires_at.timestamp())
                    || reservation.expires_at.timestamp_subsec_nanos() != 0
                {
                    return Err(Error::InvalidInput);
                }
                match next.state {
                    State::PasskeyRegistered => {
                        next.state = State::HandleReserved;
                        next.skeleton = Some(reservation.handle.skeleton().into());
                    }
                    State::HandleReserved | State::GatesInProgress
                        if next.skeleton.as_deref() == Some(reservation.handle.skeleton()) => {}
                    _ => return Err(Error::Transition),
                }
            }
            Event::GatesStarted => enter_gates(&mut next)?,
            Event::GatePassed(proof) => {
                if proof.subject != expected.subject
                    || match proof.level {
                        crbk::GateLevel::Global => proof.community.is_some(),
                        crbk::GateLevel::Community => {
                            proof.community.as_deref() != Some(expected.community.as_str())
                        }
                    }
                {
                    return Err(Error::Scope);
                }
                text(&proof.gate)?;
                text(&proof.provider)?;
                if proof.valid_until <= now || proof.proven_at.is_some_and(|t| t < 0 || t > now) {
                    return Err(Error::InvalidInput);
                }
                enter_gates(&mut next)?;
            }
            Event::PolicyEvaluated(decision) => {
                validate_decision(decision)?;
                if matches!(next.state, State::Started | State::PasskeyRegistered) {
                    return Err(Error::Transition);
                }
                if !decision.allowed && next.state == State::Admitted {
                    next.state = State::Lapsed;
                }
                if next.state == State::HandleReserved {
                    next.state = State::GatesInProgress;
                }
            }
            Event::AdmissionRecorded { member, decision } => {
                validate_decision(decision)?;
                if !decision.allowed {
                    return Err(Error::Transition);
                }
                if member.id != expected.member_id() {
                    return Err(Error::Scope);
                }
                let handle = member.handle.as_ref().ok_or(Error::InvalidInput)?;
                // Both owners have already validated these calendar fields.
                // Compare them directly without constructing a second month.
                if (member.lease_end.year(), member.lease_end.month())
                    < (date.year() as u16, date.month() as u8)
                {
                    return Err(Error::InvalidInput);
                }
                match next.state {
                    State::GatesInProgress
                        if next.skeleton.as_deref() == Some(handle.skeleton()) => {}
                    State::Admitted | State::Lapsed => {}
                    _ => return Err(Error::Transition),
                }
                next.state = State::Admitted;
                next.expires_day = None;
                next.skeleton = None;
            }
            Event::CredentialIssued => {
                if next.state != State::Admitted {
                    return Err(Error::Transition);
                }
            }
            Event::Restriction(record) => {
                let order = record.order();
                if order.community != next.community || order.subject != next.subject {
                    return Err(Error::Scope);
                }
                // Every block is permanent: the enrolment is released for good.
                next.state = State::Released;
                next.expires_day = None;
            }
            Event::AllPasskeysLost => {
                next.state = State::Released;
                next.expires_day = None;
            }
            Event::RegisterReleased(member) => {
                if member.id != next.member_id() {
                    return Err(Error::Scope);
                }
                if member.handle.is_some() || !matches!(next.state, State::Admitted | State::Lapsed)
                {
                    return Err(Error::Transition);
                }
                next.state = State::Released;
            }
        }
        prepare_record(expected, next)
    }

    /// Ask the real rulebook what is missing, without storing gate metadata.
    /// Snapshot authenticity, freshness and proof verification belong to cvld.
    /// Reevaluate with the returned snapshot before performing admission.
    pub async fn evaluate(
        &self,
        expected: &Record,
        policy: &crbk::Snapshot,
        results: &[crbk::GateResult],
        now: i64,
    ) -> Result<(Record, crbk::Decision)> {
        self.scope(expected)?;
        if policy.community != expected.community {
            return Err(Error::Scope);
        }
        // Do not return a positive policy verdict alongside an expired row.
        if self.refresh(expected, now).await?.state.is_terminal() {
            return Err(Error::Transition);
        }
        let decision = policy
            .may(
                crbk::Subject {
                    id: &expected.subject,
                    membership: expected.state.membership(),
                },
                &self.config.membership_action,
                results,
                now,
            )
            .map_err(|_| Error::Policy)?;
        let record = self
            .apply(expected, Event::PolicyEvaluated(&decision), now)
            .await?;
        Ok((record, decision))
    }

    /// Mark a bounded indexed batch as expired. Concurrently changed rows are
    /// skipped and can be revisited. crgs claims expire at this same deadline.
    pub async fn expire_due(&self, now: i64, limit: usize) -> Result<Vec<Record>> {
        time(now)?;
        batch(limit)?;
        let mut expired = Vec::new();
        for record in self.storage.due(now / DAY, limit).await? {
            match self.refresh(&record, now).await {
                Ok(record) => expired.push(record),
                Err(Error::Conflict) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(expired)
    }

    /// Cancel terminal pending claims through crgs, then clear their cleanup
    /// marker. Cancellation checks ownership and is safe after a crash/retry.
    /// Supply the register for this exact community; crgs has no scope getter.
    pub async fn cleanup<R: crgs::Storage>(
        &self,
        register: &crgs::Register<R>,
        limit: usize,
    ) -> Result<usize> {
        batch(limit)?;
        let mut count = 0;
        for record in self.storage.cleanup_due(limit).await? {
            self.scope(&record)?;
            let skeleton = record.skeleton.as_deref().ok_or(Error::Storage)?;
            register
                .cancel_reservation(&record.member_id(), skeleton)
                .await
                .map_err(|_| Error::Storage)?;
            let mut next = record.clone();
            next.skeleton = None;
            match self.save(&record, next).await {
                Ok(_) => count += 1,
                Err(Error::Conflict) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(count)
    }

    fn scope(&self, record: &Record) -> Result<()> {
        record.validate()?;
        if record.community != self.storage.community() {
            return Err(Error::Scope);
        }
        Ok(())
    }

    async fn refresh(&self, record: &Record, now: i64) -> Result<Record> {
        self.scope(record)?;
        time(now)?;
        if record.expires_at().is_some_and(|until| until <= now) {
            let mut next = record.clone();
            next.state = State::Expired;
            next.expires_day = None;
            self.save(record, next).await
        } else {
            Ok(record.clone())
        }
    }

    async fn save(&self, previous: &Record, next: Record) -> Result<Record> {
        let next = prepare_record(previous, next)?;
        self.storage.compare_exchange(Some(previous), &next).await?;
        Ok(next)
    }
}

fn prepare_record(previous: &Record, mut next: Record) -> Result<Record> {
    if &next != previous {
        next.revision = next.revision.checked_add(1).ok_or(Error::InvalidInput)?;
    }
    next.validate()?;
    Ok(next)
}

fn validate_decision(decision: &crbk::Decision) -> Result<()> {
    if decision.allowed != decision.missing.is_empty() {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

fn enter_gates(record: &mut Record) -> Result<()> {
    match record.state {
        State::HandleReserved => record.state = State::GatesInProgress,
        State::GatesInProgress | State::Admitted | State::Lapsed => {}
        _ => return Err(Error::Transition),
    }
    Ok(())
}

pub(crate) fn batch(limit: usize) -> Result<()> {
    if (1..=1000).contains(&limit) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}
