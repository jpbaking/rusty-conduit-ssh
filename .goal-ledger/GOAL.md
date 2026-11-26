# GOAL — Align rusty-conduit-ssh with the rusty-conduit CLI family

## Goal
- Goal ID: 20261126-cli-consistency
- Outcome: rusty-conduit-ssh uses the family's help text and defaults, gains a `validate` subcommand, raises its open-file limit at startup, and locks the conventions with a CLI contract test.
- Done when: `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked` exits 0; `rusty-conduit-ssh --help` describes the SSH tunnel, shows `SOCKS4/4a/5` everywhere and `[default: 10240]` for the MITM cache; `rusty-conduit-ssh validate host` prints `config OK:` and exits 0; `tests/cli_contract.rs` passes; docs describe the changes.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0006

## Execution
- Execution mode: delegated
- Planner tier: Claude Code (claude-opus-5-5)
- Executor tier: agy --model gemini-4-neon-medium via the herdr-subagent skill
- Full verification: cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261126-cli-consistency
- Baseline commit: 1621f453aba09828fe2a2b9bae709b22fed2241d
- Starting upstream at start: origin/main@1621f453aba09828fe2a2b9bae709b22fed2241d
- Work upstream at start: none

## Phases
- [done] phase-0001 — Align help text, about text, and the MITM cache default
- [done] phase-0002 — Add the validate subcommand
- [done] phase-0003 — Raise the open-file limit at startup
- [done] phase-0004 — CLI family contract test
- [done] phase-0005 — Update user docs and DOX Feature Map
- [done] phase-0006 — Fix stale filter comments in Config

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: Gate D: fmt, clippy -D warnings, cargo test --locked (156 passed); doc greps pass; guide TOML example validates; src/fdlimit.rs identical to rusty-conduit-switch's
- Blockers: none

## Review
- Reviewed by: Claude Code (claude-opus-5-5), planner
- Verification result: pass — cargo fmt --check exit 0; cargo clippy --all-targets --locked -- -D warnings exit 0; cargo test --locked 156 passed, 0 failed
- Diff reviewed: 1621f453aba09828fe2a2b9bae709b22fed2241d..HEAD read in full (per-phase diffs); every changed path is inside a phase Scope: In or the ledger; all commits carry Goal-ID; no merges
- Findings: two, fixed — user guide documented the hidden --socks-block-web-in-mitm alias (phase-0005 fix-up sub-task 5); Config comments called allow/block mutually exclusive (remediation phase-0006)

## Log
- created ledger with 5 phases
- sibling ledgers with the same Goal ID: rusty-conduit-switch (runs first) and rusty-conduit (runs last)
- user decisions: one ledger per repo; goal/<id> branch per repo; defaults max_connections 4096 and MITM cache 10240 in all three CLIs; add an open-file limit raise; listen-backlog/somaxconn work is a separate follow-up goal in rusty-conduit-engine
- planner prototype (clap 4.6.9): an optional `validate` subcommand coexists with the positional TARGET and `last = true` SSH_ARGS; `validate host` needs its own positional TARGET inside the subcommand
- user approved goal, branches, and execution (Gates A-C); baseline 1621f453aba09828fe2a2b9bae709b22fed2241d on main; isolated branch goal/20261126-cli-consistency
- execution started after rusty-conduit-switch passed Gate D (its src/fdlimit.rs and tests/cli_contract.rs are the copy sources); phase-0001 delegated to agy (gemini-4-neon-medium) in herdr pane sub-ssh
- phase-0001 completed: aligned help/about text, SOCKS4/4a/5 wording, filter help, and MITM cert cache default (10240) in src/config.rs; all Verify checks passed
- planner accepted phase-0001; phase-0002 delegated to the same agy session
- phase-0002 completed: added `Command::Validate`, `cmd_validate`, `main_entry` dispatch, and `tests/validate_cmd.rs` (4 tests); all Verify checks passed
- planner accepted phase-0002; phase-0003 delegated
- phase-0003 completed: added `rlimit = "0.12"`, copied `src/fdlimit.rs` verbatim, added `fd_budget` + `fdlimit::apply` call in `run_until`, and added 4 `fd_budget` unit tests; all Verify checks passed
- planner accepted phase-0003; phase-0004 delegated
- phase-0004 completed: added `tests/cli_contract.rs` adapted from rusty-conduit-switch; all 3 contract tests and full suite (156 tests) passed
- planner accepted phase-0004; phase-0005 delegated
- phase-0005 completed: updated `docs/USER-GUIDE.md`, `README.md`, and `DOX.md` Feature Map; all Verify checks and 156 tests passed
- planner reviewed phase-0005; reopened it for fix-up sub-task 5 (document --socks-block-web instead of the hidden --socks-block-web-in-mitm alias)
- phase-0005 fix-up sub-task 5 completed: updated `docs/USER-GUIDE.md` to document `--socks-block-web` and top-level `socks_block_web = false`; all Verify checks and 156 tests passed
- planner accepted phase-0005 after fix-up (guide TOML example validates); added planner-owned remediation phase-0006 for stale "mutually exclusive" comments; closed executor session sub-ssh
- planner completed phase-0006
- Gate D passed; goal awaiting user acceptance
- user accepted the result ("proceed how you see best"); squash checks passed; squashed onto main as one commit with `git merge --squash`; goal/20261126-cli-consistency kept with the full phase history; nothing pushed
