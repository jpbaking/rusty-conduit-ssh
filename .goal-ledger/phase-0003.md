# phase-0003 — ssh child lifecycle: libc::kill, Linux parent-death signal, jittered backoff, post-ready liveness

- Status: done
- Owner: planner
- Depends on: phase-0002
- Goal: Stop `ssh` with `libc::kill` instead of spawning `/bin/kill`, make the `ssh` child die with this process on Linux, spread reconnects with ±20% jitter, and report the tunnel ready only while `ssh` is still running (after a short settle when `-R` forwards are configured).
- Done when: every command in `## Verify` exits 0, and the planner's Linux container check (manual line in `## Verify`) passes.
- Pattern to follow: `../rusty-conduit-gui/crates/conduit-openssh/src/orphan.rs:14-53` (`guard_command` + `set_parent_death_signal`: `PR_SET_PDEATHSIG(SIGTERM)` in `pre_exec`, then a `getppid` check that closes the race where the parent died first)

## Context
B-03: `kill_on_drop(true)` only works while this process runs its destructors; on `SIGKILL` or the OOM killer, `ssh -N -D -R` is reparented to PID 1 and holds its remote `-R` ports, so a restarted instance fails with `ExitOnForwardFailure=yes`. Linux `PR_SET_PDEATHSIG` fires when the spawning *thread* exits. `run_attempt` spawns from a Tokio runtime worker (or the `block_on` thread), and those live as long as the runtime, so a direct `pre_exec` is enough here. The GUI needs a dedicated thread only because it spawns from the blocking pool.
P-12: `request_terminate` (`src/ssh.rs:564-578`) forks `/bin/kill`; `libc` is already a Unix dependency. Reconnects of many instances retry in lockstep, so add ±20% jitter to the *sleep* while the backoff state (`next_delay`, `src/ssh.rs:319-321`) and its tests stay unchanged.
B-11: the `-D` port can be answered by another local SOCKS5 server between `pick_loopback_port` and `ssh` binding it, and with `-R` the `-D` probe can pass before sshd rejects `tcpip-forward`. In both cases `ssh` exits on its own. Checking that the child is still alive (and, with `-R`, waiting a 1 s settle) before `TunnelState::Ready` stops a false "ready". `REVERSE_STABLE_UPTIME` stays as it is.
Deferred by plan: macOS and Windows parent-death watchdogs.
Escalation answered (user, 2026-11-28): the 1 s `REVERSE_READY_GRACE` made `tests/reverse_proxy.rs::reverse_only_mode_exits_cleanly_when_tunnel_is_lost` fail (it killed `ssh` 300 ms after the reverse proxy listened, before readiness, so `--no-reconnect` exited 1). Keep the grace; widen scope to that test and raise its sleep to 1500 ms with a comment pointing at the grace.

## Scope
- In: `src/ssh.rs`, `DOX.md` (SSH tunnel supervisor Feature Map line only), `docs/USER-GUIDE-ADVANCED.md` (the **Backoff.** paragraph only), `tests/reverse_proxy.rs` (the readiness sleep in `reverse_only_mode_exits_cleanly_when_tunnel_is_lost` only; user-approved 2026-11-28)
- Out: `src/lib.rs`, `src/net.rs`, `src/reverse.rs`, `Cargo.toml`, `Cargo.lock`, every other file under `tests/`

## Sub-tasks
1. [done] Replace the `#[cfg(unix)] async fn request_terminate` (system `kill`) with a synchronous `#[cfg(unix)] fn request_terminate(child: &Child) -> bool`: `child.id()` → `libc::pid_t::try_from` → `unsafe { libc::kill(pid, libc::SIGTERM) == 0 }` with a `// SAFETY:` comment; make the `#[cfg(not(unix))]` variant synchronous too; drop the `.await` in `terminate`; update the doc comment (no longer "avoids a libc dependency") — done when: `sed -n '1,/^#\[cfg(test)\]/p' src/ssh.rs | grep -c 'Command::new("kill")'` prints `0` (the test helpers `kill_hard`/`is_alive` keep their `std::process::Command::new("kill")`) and `cargo test --locked --lib ssh::tests::process` passes (covers `shutdown_sends_sigterm_and_reaps_child` and `escalates_to_kill_when_sigterm_is_ignored`).
2. [done] Add `#[cfg(target_os = "linux")]` parent-death guarding to the `ssh` command in `run_attempt`: build the `Command` into a `let mut command`, then apply a `guard_parent_death(&mut command)` helper that copies `orphan.rs:14-53` (record `getpid()` before spawning; in `pre_exec`, `prctl(PR_SET_PDEATHSIG, SIGTERM)` then fail with `ESRCH` if `getppid()` differs), with `// SAFETY:` comments; it is a no-op on other targets. Keep `kill_on_drop(true)` — done when: `cargo clippy --all-targets --locked -- -D warnings` and `cargo test --locked` pass on macOS, and the manual Linux check passes.
3. [done] Add `fn jittered(delay: Duration) -> Duration` returning `delay.mul_f64(0.8 + 0.4 * frac)`, where `frac` in `[0, 1]` comes from `std::collections::hash_map::RandomState::new().hash_one(std::time::SystemTime::now())` (no new dependency). In the reconnect loop, compute `let wait = jittered(delay);` once, and use `wait` in both the `reconnecting in ...` log line and `tokio::time::sleep`. Add unit test `jitter_stays_within_twenty_percent`: 200 calls with 10 s all fall in `[8 s, 12 s]`, and they are not all equal — done when: `cargo test --locked --lib jitter` passes and `backoff_doubles_and_caps` still passes unchanged.
4. [done] In `run_attempt`, after `wait_for_socks(addr)` wins and before `state.send_replace(TunnelState::Ready(addr))`, add a `biased` `tokio::select!` over `stop.cancelled()` (terminate, return `Attempt::Stopped`), `child.wait()` (return `dropped(exit_reason(status), false)`), and `tokio::time::sleep(settle)`, where `settle` is `Duration::ZERO` without reverse forwards and the new `const REVERSE_READY_GRACE: Duration = Duration::from_secs(1)` with them. Comment why (the reused-port and late `-R` rejection cases). Add a `process` test: a mock `ssh` that exits 0.3 s after start while the test's `socks_listener()` answers, with one reverse forward configured, never publishes `TunnelState::Ready` before the first `Disconnected`/reconnect — done when: the new test passes and `ready_only_after_socks_listener_answers` still passes.
5. [done] Docs pass: in `DOX.md`'s **SSH tunnel supervisor** Feature Map line, mention the Linux parent-death signal, `libc::kill` `SIGTERM`, jittered backoff, and the post-ready liveness check; in `docs/USER-GUIDE-ADVANCED.md`'s **Backoff.** paragraph, add that each wait is randomized by ±20% so many instances do not retry in lockstep — done when: `grep -c 'PDEATHSIG\|parent-death' DOX.md` and `grep -c '20%' docs/USER-GUIDE-ADVANCED.md` each print at least `1`.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
python3 scripts/check-pure-rust-crypto.py
test "$(sed -n '1,/^#\[cfg(test)\]/p' src/ssh.rs | grep -c 'Command::new("kill")')" = 0
git diff --exit-code -- Cargo.toml Cargo.lock src/lib.rs src/net.rs src/reverse.rs tests ':(exclude)tests/reverse_proxy.rs'
```
- manual (planner, needs Docker): `docker run --rm -v "$PWD":/src -w /src rust:1-bookworm sh -c 'apt-get update -qq && apt-get install -y -qq openssh-client >/dev/null && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked'` exits 0, which compiles and runs the Linux-only path.

## Escalate when
- Docker is unavailable for the manual Linux check → set Status: needs-human — reason: ask the user to start Docker Desktop or accept CI-only Linux verification.
- A `process` test becomes flaky (passes and fails across 3 runs) → stop, set Status: needs-human — reason: name the test and paste both outcomes.
- The settle step changes the timing an existing test asserts → stop, set Status: needs-human — reason: name the test.

## Log
- (append-only, one line per event)
- planner: scoped the `Command::new("kill")` check to non-test code — the test helpers at src/ssh.rs:927/935 legitimately use it, so the whole-file count could never reach 0
- planner begins phase-0003 (solo, planner-owned)
- sub-task 1: `request_terminate` is now synchronous and sends `SIGTERM` with `libc::kill`; `terminate` drops the `.await`
- sub-task 2: `guard_parent_death` + `set_parent_death_signal` (copied from conduit-openssh orphan.rs) applied to the `ssh` command on Linux; no-op elsewhere; `kill_on_drop(true)` kept
- sub-task 3: `jittered()` with `RECONNECT_JITTER = 0.2`; reconnect log and sleep both use the jittered wait (log rounded to ms); `next_delay` unchanged
- sub-task 4: `REVERSE_READY_GRACE = 1s` settle select before `TunnelState::Ready`; new test `reverse_tunnel_that_exits_within_grace_is_never_ready` (mock gains `with_body`)
- escalation hit: settle broke `reverse_only_mode_exits_cleanly_when_tunnel_is_lost` (exit 1 vs 0) on macOS and Linux; asked the user; answer recorded in Context; fixed the test's sleep (300 → 1500 ms)
- sub-task 5: DOX Feature Map line and USER-GUIDE-ADVANCED Backoff paragraph updated
- phase-0003 verified and closed (macOS and Linux)

## Evidence
- (append-only: command → observed result)
- `cargo test --locked --lib jitter` → 1 passed; `cargo test --locked --lib backoff_doubles_and_caps` → 1 passed (unchanged)
- `cargo test --locked --lib ssh::tests::process` ×3 → 10 passed each run (incl. new `reverse_tunnel_that_exits_within_grace_is_never_ready`, `ready_only_after_socks_listener_answers`, `shutdown_sends_sigterm_and_reaps_child`, `escalates_to_kill_when_sigterm_is_ignored`)
- first Linux run: `reverse_only_mode_exits_cleanly_when_tunnel_is_lost` FAILED (ExitCode 1 vs 0), reproduced on macOS → escalated; after the approved test fix `cargo test --locked --test reverse_proxy` ×3 → 11 passed each
- `cargo fmt --check` → exit 0; `cargo clippy --all-targets --locked -- -D warnings` → exit 0; `cargo test --locked` → 185 passed, 0 failed; `python3 scripts/check-pure-rust-crypto.py` → PURE_RUST_CRYPTO_OK
- non-test `Command::new("kill")` count → 0; `git diff --exit-code -- Cargo.toml Cargo.lock src/lib.rs src/net.rs src/reverse.rs tests ':(exclude)tests/reverse_proxy.rs'` → exit 0
- `grep -c 'PDEATHSIG\|parent-death' DOX.md` → 1; `grep -c '20%' docs/USER-GUIDE-ADVANCED.md` → 1
- manual Linux: rust:1-bookworm + openssh-client + clippy: `cargo clippy --all-targets --locked -- -D warnings && cargo test --locked` → exit 0, 185 passed, 0 failed
