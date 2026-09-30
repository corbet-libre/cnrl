# cnrl implemented contract

cnrl is the native community enrolment library under `cvld → cmnt → cmbr`.
Its binding lifecycle is started → passkey registered → handle reserved → gates
in progress → admitted ⇄ lapsed → released. Pending registrations can also end
in expired. It stores current state and a coarse expiry, never history, login
dates, request logs, raw gate data or cryptographic material. It uses crlt for
all persistent storage and requires one database per community. Every table
and unique key includes `community_id`; every application query is indexed.
The license is LGPL-3.0-only WITH LGPL-3.0-linking-exception.

## Identity and trusted inputs

One row per cpky user UUID and per community pseudonym, both unique within the
community. A service-authorized binding is supplied to `start`; additional
passkeys for the same UUID resume the same row. `resume` accepts cpky's opaque
`Authentication`, verifies its community, and records no authentication data.
`get` is for trusted service orchestration, not authentication.

The pseudonym uses a caller-selected canonical, nonempty text encoding, also
used by crbk and clbs. crgs receives the UTF-8 bytes of that exact encoding.
The service must consistently enforce this binding across all siblings. cnrl
does not derive, truncate, hash or otherwise invent a pseudonym mapping.

`Event` has no deserializer. Passkeys must come from cpky's committed store;
reservations and admissions from the same community's crgs; gate metadata and
decisions from verified cgts/crbk inputs; restrictions from clbs's private-
constructor `Record`. cnrl checks identities, community bindings when carried,
revocation, expiry, scope and structural consistency, but cannot authenticate
a caller that can manufacture a public crgs/crbk value. It is not an API server.

## Transitions

| Input | Result |
|---|---|
| First `start` | Started, revision 1, fixed coarse pending expiry |
| Retry `start` | Existing state; never extends a deadline or revives a terminal row |
| Live cpky passkey registered | Started → passkey registered; later stages are unchanged |
| crgs handle reservation | Passkey registered → handle reserved; its owner and exact deadline must match |
| Gates started / valid gate metadata | Handle reserved → gates in progress; never grants admission |
| crbk decision | Handle reserved → gates in progress; a negative decision makes admitted → lapsed; positive decisions alone cannot admit |
| crgs admission + fresh positive decision | Gates in progress / lapsed → admitted; handle and current coarse lease required; clears pending expiry and reservation pointer |
| Credential issued | No-op only for admitted; no credential or issuance time retained |
| Permanent clbs membership restriction | Any live state → released; self-ban is always permanent in clbs |
| Temporary clbs membership restriction | Admitted → lapsed; pending remains pending; clbs must continue vetoing every action for the ordered period |
| All passkeys lost | Any live state → released; no recovery or resurrection |
| Released crgs record | Admitted / lapsed → released, only if crgs confirms the handle is absent |
| Pending deadline reached | Any pending state → expired, taking precedence over a late event |

An inactive or unrelated-action legal order is refused. Legal scope is literal:
the configured membership action must be covered. A temporary order never
becomes a permanent termination. cnrl does not retain order references or legal
metadata. The service checks clbs again before admission/renewal; a cnrl state
alone cannot override a current veto.

Gate inputs reuse `crbk::GateResult`: gate, level, subject, provider, valid until,
plus its community binding and optional proof-issuance metadata. Global results
must already be rebound to the pseudonym by the trusted proof verifier. Neither
these results nor missing-gate lists are stored. `evaluate` delegates to
`Snapshot::may` and returns the current missing requirements for the lobby.
After any revision change, recompute decisions before confirming admission.
Evaluating an expired pending row commits its expiry and returns Transition;
it never returns a positive policy verdict alongside a terminal enrolment.

## Expiry and handle release

`Config::new(pending_days, membership_action)` requires a positive duration.
The exclusive deadline is midnight UTC on
`floor(now / 86400) + pending_days`. This deliberately has day precision; a
two-day setting lasts between one and two days depending on the start time.
No creation timestamp is kept. Setting changes never extend existing rows.
All clocks are supplied by the trusted caller, in nonnegative Unix seconds
within calendar years 1–9999; arithmetic overflow is rejected.

crgs reservations must expire at exactly this deadline, so the handle is
logically free even before cnrl's bounded `expire_due` maintenance runs.
Expired/released pending rows retain only their reservation skeleton until
`cleanup` calls crgs's idempotent owner-checked cancellation. The cleanup marker
is current unfinished work, not an event log. A crash after cancellation and
before acknowledgment is safe to retry; another owner's claim is never removed.
Run expiry and cleanup periodically, including when users never return.

For admitted/lapsed members, cnrl never shortens crgs's stored retention policy.
All-passkey loss or permanent block ends eligibility immediately; crgs releases
the handle at its own existing coarse lease plus release deadline (normally
24 months). cnrl consumes `RegisterReleased` when that happens. Terminal rows
remain minimal tombstones so retries cannot recreate the same enrolment. A new
identity is a separate service-authorized registration, subject to clbs policy.

## Storage, replay and concurrency

`Storage` has five operations: load, compare/exchange, due expiries, pending
cleanup, and fixed community identity. Memory uses a shared mutex; libSQL uses
crlt immediate transactions. compare/exchange checks the whole previous record,
including a monotonically increasing revision. It replaces one row atomically;
no earlier revision is retained. An exact already-applied result succeeds
without a write. Other stale snapshots return Conflict, including an old
admission/denial after a later admitted/lapsed/admitted cycle. Pure no-ops also
validate the current revision. Invalid events leave the row unchanged.

Queries use the community/user primary key, community/subject unique index,
community/expiry/user index, or community/cleanup/user index. Maintenance is
bounded to 1–1000 rows. crlt enforces plans and tests use EXPLAIN QUERY PLAN.
Stored JSON has an explicit field set; indexed projections must agree with it
on reads. Backend/decode errors have fixed redacted text and never grant access.
Do not enable dependency SQL/HTTP debug tracing in production.

Migrations are owned by the composition service: append cnrl's `SCHEMA` to its
complete crlt history along with sibling schemas. Libraries do not independently
assign global migration versions. Credentials are passed to crlt by the service;
production cnrl code reads no environment variables or credentials.

## Composition obligations and open interfaces

crgs and cnrl expose independent transactions. The service must serialize the
crgs operation plus receipt against expiry/termination for the same member,
across all service instances, and reconcile lost responses before proceeding.
In particular, do not let expiry race an already committed crgs admission whose
receipt has not yet reached cnrl. Likewise, record a reservation receipt before
allowing a release that needs its skeleton. A stale receipt is rejected; cnrl
does not silently overwrite the newer state or claim distributed exactly-once
execution. A shared cross-crate transaction API is future composition work.

The service must give `cleanup` the register for the same community: crgs's
current Register API exposes no community identity getter. It must serialize
identity binding and enforce permanent bans on any attempted new identity.
Registration throttling belongs to cthl; credential signing to csgn; lost-key
detection to cpky/cmbr; access decisions and snapshot freshness to cvld/crbk.
No local substitute crypto, policy engine, handle checker, WebAuthn verifier or
legal verifier is implemented here.

## Acceptance

Stable Rust formatting, strict Clippy and tests run only on GitHub Actions.
Tests exercise both stores, actual libSQL files, persistence, isolation,
concurrent revisions, expiry boundaries, ownership-safe cleanup, real passkey
ceremonies, rulebook decisions, signed legal/self-ban records and failures.
An optional real-Turso test skips unless both environment credentials exist;
public CI has neither. No registry publication.

## Permanent no-return rule and pure reads

Product decision: an expired registration or loss of all passkeys permanently
ends this person's ability to join this community. The deterministic pseudonym
remains burned in the unique subject index. Changing the passkey UUID cannot
re-enrol that pseudonym. There is no delete/recycle/recovery API for the tombstone.
This includes missed pending deadlines, not only bans. cmbr's lobby must warn
before expiry and recommend a second device or synced passkey when only one
passkey remains. Uniqueness fingerprints at global issuance are never released.

`view(user, now)` is a pure read. It reflects a passed pending deadline without
committing a transition, and takes no write transaction. `get` and maintenance
remain explicit synchronization operations. `Storage::load_subject` reads the
permanent subject index for cmbr's authoritative credential facts. It never
creates a new identity or changes state. Both stores test no return after expiry
and all-passkey loss, including a different UUID, and prove views do not write.
The pinned cpky authentication carries the actual verified credential ID; cmbr
must recheck its current revocation before every authenticated action.
