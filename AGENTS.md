# cnrl agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run from the lane root (`<lane>/ws`); `cbuild <lane> ...` builds there.

Build and test (quote the verdict line, never infer from a pipe):
- `cbuild <lane> fmt -p cnrl -- --check` — must be clean
- `cbuild <lane> test -p cnrl --locked` — lib `2`, `failures` `13`, `interleaving` `6`, `lifecycle` `9`, `restrictions` `4`, `storage_boundaries` `3`, `transactions` `9`, `turso` `0` passed + `1` ignored (needs `TURSO_URL` + `TURSO_TOKEN`), doc `1`, exit 0; long, background it
- `cbuild <lane> clippy -p cnrl --locked --all-targets -- -D warnings` — exit 0
- Full gate (first-party refresh, live Turso run, coverage) runs in CI; see `.github/workflows/ci.yml`, `docs/COVERAGE.md`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Transition order enforced in both stores; skipped states refused
  -> `tests/failures.rs::memory_storage_enforces_transition_order`, `::sql_storage_enforces_transition_order`, `::storage_rejects_skipped_states`
- Retry `start` never extends a deadline or revives a terminal row
  -> `::reservations_cannot_extend_or_change_pending_claims`, `tests/interleaving.rs::a_competing_start_reloads_actual_advanced_state_without_rebinding_identity`
- One row per passkey-UUID/pseudonym; concurrent starts cannot rebind or duplicate
  -> `tests/interleaving.rs::real_concurrent_initial_reads_cannot_rebind_or_duplicate_an_identity`
- Pending deadline overrides late events; no return, no resurrection
  -> `tests/lifecycle.rs::pending_deadline_overrides_late_events_and_changed_settings`, `::no_return`, `::pure_expiry_views_and_no_return_hold_in_both_stores`
- `clbs` restrictions end or pause lifecycles; self-ban is always permanent
  -> `tests/restrictions.rs::self_ban_releases_pending_and_cleanup_survives_reopen`, `::permanent_legal_block_releases_the_enrolment`
- No gate data, history, login dates or activity logs persisted
  -> `tests/failures.rs::current_record_contains_no_gate_data_or_activity_history`

Pointers: `src/enrol.rs`, `src/model.rs`, `src/storage.rs`, `docs/CONTRACT.md`, `docs/COVERAGE.md`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking-exception; no GPL/AGPL-only deps.
