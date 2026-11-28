# GOAL — Optimization roadmap Phase 1 for rusty-conduit-ssh

## Goal
- Goal ID: 20261128-optimization-phase1
- Outcome: rusty-conduit-ssh release builds use thin LTO, one codegen unit, and stripped symbols; Linux glibc binaries cap malloc at two arenas unless `MALLOC_ARENA_MAX` is set; the startup banner reports `config::app_version()`; the contract test covers the four missing shared flags; releases abort when the tag disagrees with `Cargo.toml`, with the pure-Rust crypto check in CI; and the `ssh` child gets `SIGTERM` through `libc::kill`, dies with its parent on Linux, reconnects with jittered backoff, and is only reported ready while it is still running.
- Done when: `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && python3 scripts/check-pure-rust-crypto.py` exits 0, and every `## Verify` block of phase-0001 to phase-0003 passes.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0003

## Execution
- Execution mode: delegated
- Planner tier: Claude Code (claude-opus-5-5)
- Executor tier: agy --model gemini-4-neon-medium via the herdr-subagent skill (fallback: claude --model opus --effort medium via herdr-subagent while agy is rate-limited)
- Full verification: cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && python3 scripts/check-pure-rust-crypto.py

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261128-optimization-phase1
- Baseline commit: 28ed615207e9255c419a103972ff5e70c548f0cc
- Starting upstream at start: origin/main@28ed615207e9255c419a103972ff5e70c548f0cc
- Work upstream at start: none

## Phases
- [done] phase-0001 — Release profile and malloc arena cap
- [done] phase-0002 — Version banner, CLI contract rows, release tag guard, and pure-Rust crypto gate
- [done] phase-0003 — ssh child lifecycle: libc::kill, Linux parent-death signal, jittered backoff, post-ready liveness

## Handoff
- Current position: completed; accepted by the user 2026-11-28
- Next role: planner
- Next action: none
- Last verified evidence: Gate D → fmt/clippy clean, 185 passed (macOS and Linux), PURE_RUST_CRYPTO_OK
- Blockers: none

## Review
- Reviewed by: planner, Claude Code (claude-opus-5-5)
- Verification result: pass — cargo fmt --check, cargo clippy --all-targets --locked -D warnings, cargo test --locked (185 passed, 0 failed), python3 scripts/check-pure-rust-crypto.py → PURE_RUST_CRYPTO_OK; all phase-0001..0003 Verify commands exit 0; rust:1-bookworm (openssh-client) clippy --all-targets + cargo test → exit 0
- Diff reviewed: 28ed615..3ffb9ae, read in full; all 12 non-ledger paths within phase Scope: In (tests/reverse_proxy.rs added to phase-0003 scope by user decision); 9 commits, all Goal-ID, no merges or foreign commits
- Findings: none open; phase-0003 escalation (REVERSE_READY_GRACE vs reverse_only_mode_exits_cleanly_when_tunnel_is_lost) resolved by user decision and verified; deferred by plan: macOS/Windows parent-death watchdogs (B-03 remainder)

## Log
- created ledger with 3 phases; replaces the completed ledger 20261126-cli-consistency (kept in Git history)
- source plan: rusty-conduit-series/docs/OPTIMIZATION.md, roadmap Phase 1 (items P-01, P-02, B-09, B-10, M-05, B-03, B-11, P-12)
- sibling ledgers with the same Goal ID: rusty-conduit (runs first; canonical contract rows and release steps), rusty-conduit-switch, rusty-conduit-gui, and the rusty-conduit-series workspace
- user decisions: roadmap Phase 1 only; delegated to agy neon medium via herdr
- planner decisions: phase-0003 stays with the planner (unsafe `pre_exec`, signals, process lifecycle); the macOS and Windows parent-death watchdogs from B-03 are deferred — this Mac cannot compile Windows code, and macOS needs a wrapper-process design; the P-11 duplicate CA loads belong to the roadmap Phase 3 shared CLI support
- user approved the goal (Gate A) on 2026-11-28
- Gate B: isolated branch goal/20261128-optimization-phase1 created from main at baseline 28ed615207e9255c419a103972ff5e70c548f0cc; user asked to commit only and not start execution yet
- resumed 2026-11-28 by planner (claude-opus-5-5); evidence: branch and baseline consistent, HEAD = approve commit 6b318ff, clean tree, validator OK; origin/goal/20261128-optimization-phase1 holds the approve commit, so automated squash is prohibited
- Gate C: user started execution; executor agy neon medium, fallback claude opus medium while agy is rate-limited
- planner fixed phase-0002 rusty-conduit line refs (77-100 → 78-101) after rusty-conduit fcc6cd4; noted that phase-0003's `Command::new("kill")` grep also matches test helpers at src/ssh.rs:927/935 — to be fixed before phase-0003 starts
- delegated phase-0001 to agy (herdr-subagent)
- phase-0001 done by executor: added `[profile.release]` in `Cargo.toml`, added Linux glibc `cap_malloc_arenas()` in `src/main.rs`, and updated `docs/PERFORMANCE-AND-SIZING.md`; all automated Verify checks passed
- planner accepted phase-0001 (Verify re-run: 183 passed; diff in scope and verbatim; Linux Docker clippy exit 0); fixed phase-0003 kill-grep check; delegated phase-0002 to agy (herdr-subagent)
- phase-0002 done by executor: switched startup banner to `config::app_version()`, added 4 shared flag contract rows, added release tag version guard and pure-Rust crypto gate in CI/release workflows, copied `scripts/check-pure-rust-crypto.py`, and updated `DOX.md`; all Verify checks passed
- planner accepted phase-0002 (Verify re-run: 183 passed, PURE_RUST_CRYPTO_OK; diff in scope); began phase-0003
- phase-0003 escalation (settle broke reverse_only_mode_exits_cleanly_when_tunnel_is_lost): user approved widening scope to that test's sleep; phase-0003 done (macOS + Linux verified)
- Gate D passed; status awaiting-acceptance
- user accepted 2026-11-28; branch kept unsquashed (published on origin); user asked to squash-merge into main, delete the goal branch, and push
