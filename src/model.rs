use std::fmt;

use ckyh::Uuid;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub(crate) const DAY: i64 = 86_400;

/// Coarse pending lifetime and the exact membership action used by clbs.
#[derive(Clone, Debug)]
pub struct Config {
    pub(crate) pending_days: u32,
    pub(crate) membership_action: String,
}

impl Config {
    /// No product defaults: supply the resolved platform setting and action.
    /// Expiry is the start of UTC day `floor(now / 86400) + pending_days`.
    pub fn new(pending_days: u32, membership_action: impl Into<String>) -> Result<Self> {
        let membership_action = membership_action.into();
        text(&membership_action)?;
        if pending_days == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            pending_days,
            membership_action,
        })
    }
}

/// Current lifecycle state; terminal states cannot be reopened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Registration has started with a fixed coarse deadline.
    Started,
    /// ckyh has durably registered a live passkey.
    PasskeyRegistered,
    /// crgs has reserved a handle until the pending deadline.
    HandleReserved,
    /// The lobby is collecting or renewing requirements.
    GatesInProgress,
    /// crgs admission and a fresh positive rulebook decision were received.
    Admitted,
    /// A previously admitted member must return to the lobby.
    Lapsed,
    /// A pending registration expired; its handle is reusable.
    Expired,
    /// Membership has ended. crgs owns any remaining handle retention.
    Released,
}

impl State {
    /// Whether the original registration deadline still applies.
    pub fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Started | Self::PasskeyRegistered | Self::HandleReserved | Self::GatesInProgress
        )
    }

    /// Whether this lifecycle can never resume.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Released)
    }

    /// Corresponding policy state; terminal registrations can never rejoin.
    pub fn membership(self) -> crbk::MembershipState {
        match self {
            Self::Admitted => crbk::MembershipState::Admitted,
            Self::Lapsed => crbk::MembershipState::Lapsed,
            Self::Expired | Self::Released => crbk::MembershipState::Released,
            _ => crbk::MembershipState::Pending,
        }
    }
}

/// A trusted storage snapshot, not a client-supplied command or authorization.
/// Serialization exists for storage implementors; never accept it from a client.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    pub(crate) community: String,
    pub(crate) user: Uuid,
    pub(crate) subject: String,
    pub(crate) state: State,
    pub(crate) revision: u64,
    pub(crate) expires_day: Option<i64>,
    // Present only while a pending claim exists or awaits cancellation.
    pub(crate) skeleton: Option<String>,
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            community: String,
            user: Uuid,
            subject: String,
            state: State,
            revision: u64,
            expires_day: Option<i64>,
            skeleton: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let record = Self {
            community: wire.community,
            user: wire.user,
            subject: wire.subject,
            state: wire.state,
            revision: wire.revision,
            expires_day: wire.expires_day,
            skeleton: wire.skeleton,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Record {
    /// Community scope, selected by the service.
    pub fn community(&self) -> &str {
        &self.community
    }
    /// ckyh's opaque community-local user handle; all its passkeys resume this row.
    pub fn user(&self) -> Uuid {
        self.user
    }
    /// Canonical text encoding of the community pseudonym, bound by the service.
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// The current state, without login or transition times.
    pub fn state(&self) -> State {
        self.state
    }
    /// Optimistic concurrency token; no prior versions are retained.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Exclusive UTC deadline, always a whole day boundary; absent after admission.
    pub fn expires_at(&self) -> Option<i64> {
        self.expires_day.map(|d| d * DAY)
    }
    /// Whether an early termination still needs crgs reservation cancellation.
    pub fn needs_cleanup(&self) -> bool {
        self.state.is_terminal() && self.skeleton.is_some()
    }
    /// Register ID convention: UTF-8 bytes of the canonical pseudonym encoding.
    pub fn member_id(&self) -> crgs::MemberId {
        crgs::MemberId::new(self.subject.as_bytes()).expect("validated subject")
    }

    pub(crate) fn validate(&self) -> Result<()> {
        text(&self.community)?;
        text(&self.subject)?;
        if self.user.is_nil()
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.state.is_pending() != self.expires_day.is_some()
            || self
                .expires_day
                .is_some_and(|d| d <= 0 || d.checked_mul(DAY).is_none())
            || (matches!(
                self.state,
                State::Started | State::PasskeyRegistered | State::Admitted | State::Lapsed
            ) && self.skeleton.is_some())
            || (matches!(self.state, State::HandleReserved | State::GatesInProgress)
                && self.skeleton.is_none())
        {
            return Err(Error::InvalidInput);
        }
        if let Some(skeleton) = &self.skeleton {
            text(skeleton)?;
        }
        if let Some(expiry) = self.expires_at() {
            time(expiry)?;
        }
        Ok(())
    }
}

/// In-process events from trusted sibling crates. These are never deserialized.
/// The service authenticates the caller and supplies current dependency records.
pub enum Event<'a> {
    /// Successful ckyh registration; a revoked record is refused.
    PasskeyRegistered(&'a ckyh::StoredPasskey),
    /// Successful crgs reservation, with exactly this enrolment's deadline.
    HandleReserved(&'a crgs::Reservation),
    /// Enter the headless lobby; safe to repeat.
    GatesStarted,
    /// A verified gate result was received; it never grants admission by itself.
    GatePassed(&'a crbk::GateResult),
    /// A fresh crbk decision. Denial lapses an admitted member; allowance alone
    /// cannot admit or renew without the register confirmation below.
    PolicyEvaluated(&'a crbk::Decision),
    /// A fresh positive decision plus a durable crgs member record.
    AdmissionRecorded {
        /// crgs record for this pseudonym with a current handle and lease.
        member: &'a crgs::Member,
        /// Current decision, computed for this revision by crbk.
        decision: &'a crbk::Decision,
    },
    /// csgn confirmation; no credential or issuance timestamp is retained.
    CredentialIssued,
    /// Verified clbs record; permanent membership blocks terminate, temporary
    /// ones lapse admission. Other actions and inactive orders are refused.
    Restriction(&'a clbs::Record),
    /// The service confirmed that every ckyh credential is lost/revoked.
    /// crgs retains admitted handles through its existing release deadline.
    AllPasskeysLost,
    /// crgs has released an admitted member's handle after its retention period.
    RegisterReleased(&'a crgs::Member),
}

pub(crate) fn text(value: &str) -> Result<()> {
    if value.is_empty() || value.contains('\0') {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

pub(crate) fn time(now: i64) -> Result<chrono::DateTime<chrono::Utc>> {
    if now < 0 {
        return Err(Error::InvalidInput);
    }
    let date = chrono::DateTime::from_timestamp(now, 0).ok_or(Error::InvalidInput)?;
    use chrono::Datelike;
    if !(1..=9999).contains(&date.year()) {
        return Err(Error::InvalidInput);
    }
    Ok(date)
}
