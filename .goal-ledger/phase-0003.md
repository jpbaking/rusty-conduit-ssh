# phase-0003 — Raise the open-file limit at startup

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: At startup, raise the soft open-file limit when it cannot hold the forward plus reverse connection caps, and log a NOTICE when it still cannot.
- Done when: `cargo test --locked` passes, `diff ../rusty-conduit-switch/src/fdlimit.rs src/fdlimit.rs` prints nothing, and the `fd_budget` unit tests pass.
- Pattern to follow: `../rusty-conduit-switch/src/fdlimit.rs` (read only: copy it verbatim) and the `fdlimit::apply` call in `../rusty-conduit-switch/src/lib.rs` right after `log_startup`

## Context
The same `fdlimit` module ships in all three tools and must stay byte-identical; rusty-conduit-switch's goal already created it, so copy that file instead of writing a new one. Each proxied connection uses two descriptors, so the budget is `2 × connections + 64`. This tool runs up to two servers with separate caps: the forward proxy (`max_connections`, active when `cfg.forward_enabled()`) and the reverse proxy (`reverse_max_connections`, active when `cfg.reverse_enabled()`). The budget is the sum of the active caps; if any active cap is `0` (unlimited) the budget is `0`, which `fdlimit::apply` treats as "do not check".
The `rlimit` crate raises the soft limit toward the hard limit; the copied module already avoids lowering it.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `src/fdlimit.rs` (new), `src/lib.rs`
- Out: `src/config.rs`, `src/ssh.rs`, `src/net.rs`, `src/reverse.rs`, `tests/`, `docs/`, `README.md`, `DOX.md`

## Sub-tasks
1. [done] Add `[target.'cfg(unix)'.dependencies]` with `rlimit = "0.12"` to `Cargo.toml` after the `[dependencies]` section and before `[dev-dependencies]`; run `cargo build` (without `--locked`) once — done when: `cargo build --locked` succeeds and `git diff --stat Cargo.lock` shows only `rlimit` (and possibly `libc`) added.
2. [done] Copy `../rusty-conduit-switch/src/fdlimit.rs` to `src/fdlimit.rs` unchanged and add `pub mod fdlimit;` next to the other `pub mod` lines in `src/lib.rs` (near line 10) — done when: `diff ../rusty-conduit-switch/src/fdlimit.rs src/fdlimit.rs` prints nothing and `cargo test --locked --lib fdlimit` passes.
3. [done] In `src/lib.rs` add `fn fd_budget(cfg: &Config) -> (usize, &'static str)` returning: forward and reverse both active → `(0, "--max-connections + --reverse-max-connections")` if either cap is 0, else `(cfg.max_connections + cfg.reverse_max_connections, "--max-connections + --reverse-max-connections")`; only reverse active → `(cfg.reverse_max_connections, "--reverse-max-connections")`; otherwise → `(cfg.max_connections, "--max-connections")`. Give it the doc `/// Connections the open-file limit must hold, and the flag(s) to name in the NOTICE.` — done when: `cargo build --locked` succeeds.
4. [done] In `run_until` (`src/lib.rs:134`), on the line right after `log_startup(&cfg, &logger);`, add `let (fd_connections, fd_flag) = fd_budget(&cfg);` and `fdlimit::apply(&logger, fd_connections, fd_flag);` — done when: `cargo build --locked` succeeds.
5. [done] Unit tests in the `mod tests` of `src/lib.rs`: build configs with `Config { ..Config::default() }` and assert `fd_budget` for (a) forward only, defaults → `(4096, "--max-connections")`; (b) forward plus reverse with `reverse_http_port: 9`, `reverse_max_connections: 10` → `(4106, "--max-connections + --reverse-max-connections")`; (c) the same with `max_connections: 0` → `(0, …)`; (d) reverse only (`http_port: 0`, `socks_port: 0`, `reverse_socks_port: 9`) → `(cfg.reverse_max_connections, "--reverse-max-connections")` — done when: `cargo test --locked --lib fd_budget` passes 4 tests.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
diff ../rusty-conduit-switch/src/fdlimit.rs src/fdlimit.rs
grep -n 'fdlimit::apply(&logger, fd_connections, fd_flag);' src/lib.rs
```

## Escalate when
- `../rusty-conduit-switch/src/fdlimit.rs` does not exist → stop, set Status: needs-human — reason: the rusty-conduit-switch goal has not finished its phase-0003.
- `Config` has no `Default` impl or `forward_enabled()` / `reverse_enabled()` behave differently from the ports-based rule above → stop, set Status: needs-human — reason: paste the relevant code.
- `Cargo.lock` changes more than adding `rlimit` (and possibly `libc`) → stop, set Status: needs-human — reason: paste `git diff --stat Cargo.lock`.

## Log
- (append-only, one line per event)
- sub-task 1: added `[target.'cfg(unix)'.dependencies]` `rlimit = "0.12"` to `Cargo.toml` and updated `Cargo.lock`
- sub-task 2: copied `../rusty-conduit-switch/src/fdlimit.rs` to `src/fdlimit.rs` unchanged and exported `pub mod fdlimit;` in `src/lib.rs`
- sub-task 3: added `fd_budget(cfg: &Config) -> (usize, &'static str)` in `src/lib.rs`
- sub-task 4: called `fd_budget` and `fdlimit::apply` in `run_until` right after `log_startup` in `src/lib.rs`
- sub-task 5: added 4 `fd_budget` unit tests to `mod tests` in `src/lib.rs`

## Evidence
- (append-only: command → observed result)
- `cargo build && cargo build --locked && git diff --stat Cargo.lock` → exit 0; `Cargo.lock | 10 ++++++++++` (only `rlimit 0.12.0` added)
- `diff ../rusty-conduit-switch/src/fdlimit.rs src/fdlimit.rs` → exit 0 (no diff); `cargo test --locked --lib fdlimit` → exit 0 (4 passed, 0 failed)
- `cargo build --locked` (after sub-task 3) → exit 0
- `cargo build --locked` (after sub-task 4) → exit 0 (no warnings)
- `cargo test --locked --lib fd_budget` → exit 0 (4 passed, 0 failed)
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked` → exit 0 (153 passed: 102 unit + 51 integration, 0 failed)
- `diff ../rusty-conduit-switch/src/fdlimit.rs src/fdlimit.rs` → exit 0 (no diff)
- `grep -n 'fdlimit::apply(&logger, fd_connections, fd_flag);' src/lib.rs` → `156:    fdlimit::apply(&logger, fd_connections, fd_flag);`
