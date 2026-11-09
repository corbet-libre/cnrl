//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/unit` stays put (the library compiles it via `#[path]`).
mod common;
mod failures;
mod interleaving;
mod lifecycle;
mod restrictions;
mod storage_boundaries;
mod transactions;
mod turso;
