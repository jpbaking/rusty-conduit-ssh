# phase-0006 — Fix stale filter comments in Config

- Status: done
- Owner: planner
- Depends on: phase-0005
- Goal: Make the `Config` field comments describe the allow/block lists as block-with-exceptions instead of mutually exclusive.
- Done when: `grep -n 'mutually exclusive' src/config.rs` prints nothing and the full verification passes.
- Pattern to follow: none

## Context
Planner review finding: `src/config.rs:756-771` documents the forward and reverse allow/block fields as mutually exclusive, but `HostFilter::from_lists` (`src/config.rs` `forward_filter` / `reverse_filter`) combines them as block-with-exceptions, which phase-0001 now documents in `--help`. Comment-only change.

## Scope
- In: `src/config.rs`
- Out: everything else

## Sub-tasks
1. [done] Replace the `(mutually exclusive with …)` doc comments on the forward `allow` and `block` fields of `Config` with `(exceptions to \`block\` when both are set)` and `(combine with \`allow\` to carve out exceptions)` — done when: `sed -n 756,759p src/config.rs | grep -c 'mutually exclusive'` prints `0`.
2. [done] Replace the same comments on `reverse_allow` and `reverse_block` with `(exceptions to \`reverse_block\` when both are set)` and `(combine with \`reverse_allow\` to carve out exceptions)` — done when: `grep -n 'mutually exclusive' src/config.rs` prints nothing.

## Verify
```sh
! grep -n 'mutually exclusive' src/config.rs
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

## Escalate when
- A test asserts on these comments → stop, set Status: needs-human — reason: name the test.

## Log
- (append-only, one line per event)
- planner split the single sub-task into forward and reverse (validator requires 2–9 sub-tasks); begin marker was committed before the split

- sub-tasks 1-2: four Config doc comments now describe block-with-exceptions
- verify: all 4 commands passed; closing phase-0006

## Evidence
- (append-only: command → observed result)
- `! grep -n 'mutually exclusive' src/config.rs` → no output (pass)
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked` → exit 0; 156 passed, 0 failed
