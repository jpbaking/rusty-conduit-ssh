# phase-0001 — Align help text, about text, and the MITM cache default

- Status: done
- Owner: executor
- Depends on: none
- Goal: Make the ssh tool's `--help` describe the SSH tunnel, use the family's wording for shared flags, and default the MITM cert cache to 10240.
- Done when: `cargo test --locked` passes and the `--help` checks in `## Verify` pass.
- Pattern to follow: `../rusty-conduit/src/config.rs:137-153` (read only: the two-line `--allow` / `--block` doc comments to imitate)

## Context
rusty-conduit is the reference. The ssh tool copied rusty-conduit's description, so its `--help` never mentions SSH; it says `SOCKS4/5` in places where the family now says `SOCKS4/4a/5`; and its `--allow`/`--block` help leaves out that the two combine as block-with-exceptions (the code already does this: `HostFilter::from_lists` in `src/config.rs:1173-1180`). The user decided the MITM cache default is 10240 in all three tools. clap strips a trailing period from a one-paragraph doc comment, so the rendered help has no final period.
Only text and one default change in this phase; no behaviour, flag name, or env var changes.

## Scope
- In: `src/config.rs`
- Out: `src/lib.rs`, `src/ssh.rs`, `src/net.rs`, `src/reverse.rs`, `tests/`, `docs/`, `README.md`, `DOX.md`

## Sub-tasks
1. [done] Description: in the `#[command(...)]` at `src/config.rs:192-198` set `about` to `Lightweight HTTP/HTTPS and SOCKS4/4a/5 proxy that sends all upstream traffic and DNS through an auto-reconnecting ssh -D tunnel, with optional HTTPS MITM inspection` and the first sentence of `long_about` to the same text followed by `.`; keep the `Precedence:` paragraph — done when: `cargo run -q -- --help | head -1` prints that sentence.
2. [done] SOCKS wording: replace `SOCKS4/5` with `SOCKS4/4a/5` in every doc comment and comment in `src/config.rs` (find them with `grep -n 'SOCKS4/5' src/config.rs`; expected at lines 35, 224, 364, 395, 590) — done when: `grep -c 'SOCKS4/5' src/config.rs` prints `0`.
3. [done] Filter help: make the forward `--allow` doc comment the two lines `Allowlist of destinations for the forward proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated.` / `When combined with --block, serves as exceptions to the blocklist.`; forward `--block`: `Blocklist of destinations for the forward proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated.` / `Combine with --allow to carve out exceptions.`; `--reverse-allow`: `Allowlist of destinations for the reverse proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated.` / `When combined with --reverse-block, serves as exceptions to the reverse blocklist.`; `--reverse-block`: `Blocklist of destinations for the reverse proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated.` / `Combine with --reverse-allow to carve out exceptions.` — done when: `cargo run -q -- --help | grep -c 'carve out exceptions'` prints `2`.
4. [done] Default: set `DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES` (`src/config.rs:50`) to `10_240`; change `[default: 10000]` to `[default: 10240]` in the `--mitm-cert-cache-max-entries` doc comment (around line 356); in the unit test near `src/config.rs:1949-1952` change `10_000` to `10_240` and `mitm_cert_cache_max_entries=10000` to `mitm_cert_cache_max_entries=10240` — done when: `grep -nE '10_000|10000' src/config.rs` prints nothing.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run -q -- --help | head -1 | grep -F 'auto-reconnecting ssh -D tunnel'
cargo run -q -- --help | grep -F '[default: 10240]'
! cargo run -q -- --help | grep -F 'SOCKS4/5'
```

## Escalate when
- A test outside `src/config.rs` asserts the old `--help` text, the old description, or `10000` → stop, set Status: needs-human — reason: name the test and the assertion.
- `grep -n 'SOCKS4/5' src/config.rs` finds more or other lines than the five listed → change them all, and note the extra lines in `## Log`; stop only if one of them is inside a string a test compares against.

## Log
- (append-only, one line per event)
- sub-task 1: updated `about` and `long_about` in `src/config.rs:192-198` to describe the auto-reconnecting ssh -D tunnel
- sub-task 2: replaced all 5 `SOCKS4/5` occurrences in `src/config.rs` (lines 35, 224, 364, 395, 590) with `SOCKS4/4a/5`
- sub-task 3: updated `--allow`, `--block`, `--reverse-allow`, and `--reverse-block` doc comments in `src/config.rs` to two-line form explaining block-with-exceptions
- sub-task 4: changed `DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES` to `10_240`, doc comment to `[default: 10240]`, and `caps_defaults` unit test assertions in `src/config.rs`

## Evidence
- (append-only: command → observed result)
- `cargo run -q -- --help | head -1` → `Lightweight HTTP/HTTPS and SOCKS4/4a/5 proxy that sends all upstream traffic and DNS through an auto-reconnecting ssh -D tunnel, with optional HTTPS MITM inspection.`
- `grep -c 'SOCKS4/5' src/config.rs` → `0`
- `cargo run -q -- --help | grep -c 'carve out exceptions'` → `2`
- `! grep -nE '10_000|10000' src/config.rs` → exit 0 (no matches)
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked` → exit 0 (all 141 tests passed: 94 unit + 47 integration)
- `cargo run -q -- --help | head -1 | grep -F 'auto-reconnecting ssh -D tunnel'` → exit 0 (matched)
- `cargo run -q -- --help | grep -F '[default: 10240]'` → exit 0 (matched `[default: 10240]`)
- `! cargo run -q -- --help | grep -F 'SOCKS4/5'` → exit 0 (no matches)
