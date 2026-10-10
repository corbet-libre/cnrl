# cnrl

**Enrol: the resumable member life cycle from newcomer to member.**

Part of `cvld → cmty → cmbr`. Native Rust, asynchronous storage, current state
only. Interfaces may change. [Implemented contract](docs/CONTRACT.md).

## API

`Enrol<S>` supports `start`, `get`, authenticated `resume`, revision-checked
`apply`, rulebook `evaluate`, bounded `expire_due`, and retryable reservation
`cleanup`. Use `MemoryStorage` for tests and `LibsqlStorage` for persistence.

```rust
use cnrl::{Config, Enrol, MemoryStorage, State};
use ckyh::Uuid;

# async fn example() -> cnrl::Result<()> {
let enrol = Enrol::new(MemoryStorage::new("example-community")?,
    Config::new(2, "membership")?);
// The authenticated service binds this ckyh user handle to the pseudonym.
let row = enrol.start(Uuid::from_u128(1), "community-pseudonym", 1_790_769_600).await?;
assert_eq!(row.state(), State::Started);
assert_eq!(enrol.get(row.user(), 1_790_769_600).await?, row);
# Ok(())
# }
```

The pending duration is an explicit platform setting in whole UTC days; there
is no product default. Every pending step retains the original deadline.
Passkeys remain in ckyh; handles, roles and leases remain in crgs; gate evidence
and decisions are transient inputs from crbk. No gate metadata, raw evidence,
credentials, login times, activity logs or state history are persisted here.

Add `SCHEMA` to the service's complete crlt migration history, then construct
`LibsqlStorage::new(&db, community)`. Deploy one database per community.
crlt injects the community key and enforces indexed query plans. cnrl retains
one current JSON record plus its indexed identity, expiry and cleanup fields.
All indexed projections are checked when reading the payload.

## Dependency survey

Surveyed crates.io and upstream GitHub sources on 2026-09-30 before implementation:

| Candidate | Decision and reason |
|---|---|
| [statig](https://crates.io/crates/statig), [upstream](https://github.com/mdeloof/statig) (MIT) | Maintained hierarchical state-machine library. Not selected: this flat persisted lifecycle needs optimistic concurrency and sibling receipts, not a hierarchy or entry/exit callback runtime. The small transition function is product policy. |
| [smlang](https://crates.io/crates/smlang), [upstream](https://github.com/korken89/smlang-rs) (MIT/Apache-2.0) | State-machine DSL candidate. Generated guards/actions would still require all persistence, replay and dependency-boundary rules here, adding an unnecessary macro layer. |
| [crlt](https://github.com/corbet-foss/crlt) | Selected pinned Git dependency from main; scoped transactions, migrations and index enforcement are ready. Delegates SQL, pooling and TLS to established libraries. |
| [libsql](https://github.com/tursodatabase/libsql) (MIT) | Official driver used through crlt. No direct-driver fallback is needed. |
| [ckyh](https://github.com/corbet-foss/ckyh), [crgs](https://github.com/corbet-foss/crgs), [crbk](https://github.com/corbet-foss/crbk), [clbs](https://github.com/corbet-foss/clbs) | Selected pinned Git revisions already on main. Reuse their verified passkey/authorization records, reservations/member records, gate/decision types and verified restrictions. Do not duplicate their logic. All have the same LGPL linking exception. |

The exact Git revisions are in `Cargo.toml`. All siblings share one crlt revision
and clones of one service-owned database pool.
Serde/serde_json encode the current record, Tokio locks memory transactions,
chrono converts supplied calendar times, and thiserror supplies sanitized errors
(all MIT/Apache-2.0). No homegrown crypto or GPL/AGPL-only dependencies are added.
Test-only dependencies are tempfile, webauthn-authenticator-rs (MPL-2.0), and
ed25519-dalek (BSD-3-Clause) for real ceremonies and signed fixtures.

## Integration boundaries

Events are trusted in-process receipts, not HTTP commands. The service must
bind the authenticated ckyh UUID to a canonical text pseudonym (the UTF-8 bytes
are its crgs ID), verify global proof binding, authenticate snapshots, check
clbs before every action, and supply a trusted current clock. Retrying the same
snapshot and event is safe; a revision conflict requires reloading and obtaining
fresh decisions. An enrolment row is not a forum access credential.

cnrl does not perform admission inside crgs. The composition layer must serialize
register operations and their cnrl receipts with expiry/release for that member,
and reconcile a committed register operation after a lost response before
expiring that enrolment. These crates currently expose separate transactions;
there is no claim of cross-crate atomic admission. See the contract for details.

## Verification

Crow runs stable Rust `cargo fmt --all --check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test`. Compilation and tests never run
on the workstation. Tests use actual storage, libSQL files, WebAuthn ceremonies,
rulebook decisions and signed clbs records. The resolved dependency lockfile is
retained as a CI artifact and committed after resolution on CI.

The optional Turso test is ignored by default and requires explicit operator
authorization, `--ignored` selection, and nonempty `TURSO_URL`/`TURSO_TOKEN`. Use a
**disposable test database**: it migrates schema and writes test records. No live
probe is run by ordinary CI. Never publish this crate to a registry.

Restriction fixtures use the real clbs RAM store and signed verifier. Enrolment
and registration still use actual libSQL files to test persistence and resumable
cleanup. Legal SQL persistence belongs to the caller; cnrl neither requires its
schema nor imports a higher-level gate facade to create restriction fixtures.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under [LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt) [WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt). See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
