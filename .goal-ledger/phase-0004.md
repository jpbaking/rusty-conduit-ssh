# phase-0004 — CLI family contract test

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002, phase-0003
- Goal: Add `tests/cli_contract.rs`, adapted from rusty-conduit-switch's, which fails if a shared flag's name, value name, env var, help text, or default drifts from the family contract.
- Done when: `cargo test --locked --test cli_contract` passes 3 tests.
- Pattern to follow: `../rusty-conduit-switch/tests/cli_contract.rs` (read only: copy it, then apply the substitutions in sub-task 1)

## Context
All three tools carry the same contract table; only the env prefix, the crate name, the binary name, and three ssh-specific help strings differ. The table is the specification: if a row fails, an earlier phase missed a doc comment, which is an escalation, not something to fix by editing the table. The ssh strings differ because this tool has forward and reverse proxies: `--tcp-keepalive` applies to "forward and reverse" sockets, and `--allow` / `--block` say "for the forward proxy". The switch test's last test checks deprecated switch aliases, which do not exist here; replace those lines as listed.

## Scope
- In: `tests/cli_contract.rs` (new)
- Out: `src/`, `tests/common/mod.rs`, every other file under `tests/`, `docs/`, `README.md`, `DOX.md`

## Sub-tasks
1. [done] Copy `../rusty-conduit-switch/tests/cli_contract.rs` to `tests/cli_contract.rs` and make exactly these edits: `rusty_conduit_switch::config` → `rusty_conduit_ssh::config`; `RUSTY_CONDUIT_SWITCH_` → `RUSTY_CONDUIT_SSH_` (every occurrence); `CARGO_BIN_EXE_rusty-conduit-switch` → `CARGO_BIN_EXE_rusty-conduit-ssh`; the `tcp-keepalive` help → `Idle time before TCP keepalive probes start on forward and reverse client and upstream sockets, 0 = disabled [default: 60s]`; the `allow` help → `Allowlist of destinations for the forward proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated. When combined with --block, serves as exceptions to the blocklist`; the `block` help → `Blocklist of destinations for the forward proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated. Combine with --allow to carve out exceptions`. In `binary_help_and_exit_codes`, delete the two `deprecated alias must stay hidden` assertions, add `.env_remove("RUSTY_CONDUIT_SSH_TARGET")` next to the config `env_remove`, and add the argument `example.test` to the missing-config run so that it fails on the config file rather than the missing target — done when: `cargo test --locked --test cli_contract` compiles.
2. [done] Run `cargo fmt` and `cargo test --locked --test cli_contract`; record each failing assertion in `## Log` — done when: all 3 tests pass.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked --test cli_contract
cargo test --locked
! grep -n 'SWITCH' tests/cli_contract.rs
```

## Escalate when
- `../rusty-conduit-switch/tests/cli_contract.rs` does not exist → stop, set Status: needs-human — reason: the rusty-conduit-switch goal has not finished its phase-0004.
- Any `SHARED_FLAGS` row fails after the substitutions → stop, set Status: needs-human — reason: paste the assertion message (the fix belongs in `src/config.rs`, outside this phase).

## Log
- (append-only, one line per event)
- sub-task 1: adapted `../rusty-conduit-switch/tests/cli_contract.rs` into `tests/cli_contract.rs` with the specified ssh substitutions
- sub-task 2: ran `cargo fmt` and `cargo test --locked --test cli_contract`; all 3 tests passed with 0 failures

## Evidence
- (append-only: command → observed result)
- `cargo test --locked --test cli_contract --no-run` → exit 0 (compiled cleanly)
- `cargo fmt && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked --test cli_contract && cargo test --locked && ! grep -n 'SWITCH' tests/cli_contract.rs` → exit 0 (cli_contract: 3 passed; full suite: 156 passed: 102 unit + 54 integration, 0 failed; no `SWITCH` matches)
