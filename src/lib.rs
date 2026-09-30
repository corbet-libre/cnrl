#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod enrol;
mod model;
mod storage;

pub use enrol::Enrol;
pub use model::{Config, Event, Record, State};
pub use storage::{LibsqlStorage, MemoryStorage, SCHEMA, Storage};

/// A result with no identity or supplied input in its error text.
pub type Result<T> = std::result::Result<T, Error>;

/// Failures are closed: never interpret one as admission.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Invalid structural input, clock or configuration.
    #[error("invalid enrolment input")]
    InvalidInput,
    /// The event belongs to another identity or community.
    #[error("enrolment scope mismatch")]
    Scope,
    /// The caller must reload and reevaluate before trying again.
    #[error("enrolment revision conflict")]
    Conflict,
    /// An event cannot apply at this point in the lifecycle.
    #[error("invalid enrolment transition")]
    Transition,
    /// No enrolment exists for this passkey owner.
    #[error("enrolment not found")]
    NotFound,
    /// A backend, stored record or dependency failed validation.
    #[error("enrolment storage failed")]
    Storage,
    /// Rulebook evaluation failed; no state was changed.
    #[error("enrolment policy evaluation failed")]
    Policy,
}

impl From<crlt::Error> for Error {
    fn from(_: crlt::Error) -> Self {
        Self::Storage
    }
}
