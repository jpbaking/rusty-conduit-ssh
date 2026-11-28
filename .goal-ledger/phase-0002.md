# phase-0002 — Version banner, CLI contract rows, release tag guard, and pure-Rust crypto gate

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Log the tag-driven version at startup, lock four shared flags in the contract test, guard releases against a tag that disagrees with `Cargo.toml`, and run the pure-Rust crypto check in CI.
- Done when: every command in `## Verify` exits 0.
- Pattern to follow: `../rusty-conduit/src/lib.rs:48` (startup banner using `config::app_version()`), `../rusty-conduit/.github/workflows/release.yml:78-101` (the "Derive release version" and "Build release binary" steps), `../rusty-conduit-engine/.github/workflows/ci.yml:26` (crypto check step)

## Context
The banner uses `env!("CARGO_PKG_VERSION")`, so it drops the `-dev` and pre-release suffixes that `--version` (via `config::app_version()`) reports. rusty-conduit already does this correctly.
This repo's `--mitm-insecure-host`, `--mitm-bypass-host`, `--mitm-insecure`, and `--error-page` help already matches rusty-conduit's canonical wording (the planner compared `src/config.rs:407-448`), so only the test changes.
Only rusty-conduit's `release.yml` aborts when the `vX.Y.Z` tag does not match the `Cargo.toml` version. Its two steps (derive the version and check it, then one bash build step that works on every runner, Git Bash included on Windows) replace this repo's separate Unix and Windows build steps. Nothing else in `release.yml` changes.
The crypto check script is generic; copy it unchanged from the engine. If a new contract row's help assertion fails, stop and escalate: the strings below are the family's canonical text and were copied from rusty-conduit.

## Scope
- In: `src/lib.rs` (`log_startup` only), `tests/cli_contract.rs`, `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `scripts/check-pure-rust-crypto.py` (new), `DOX.md` (Verification and release text only)
- Out: `src/config.rs`, `src/ssh.rs`, `src/net.rs`, `src/reverse.rs`, `Cargo.toml`, `Cargo.lock`, `Dockerfile`, `docs/`

## Sub-tasks
1. [done] In `src/lib.rs` `log_startup` (lines 106-110), replace the multi-line `logger.info(format!("rusty-conduit-ssh v{} starting", env!("CARGO_PKG_VERSION")));` call with exactly `logger.info(format!("rusty-conduit-ssh v{} starting", config::app_version()));` — done when: `grep -c 'CARGO_PKG_VERSION' src/lib.rs` prints `0` and `cargo build --locked` succeeds.
2. [done] In `tests/cli_contract.rs` `SHARED_FLAGS`, insert these three rows directly after the `("mitm-cert-cache-max-entries", ...)` row, exactly: (block 1 below) and this row directly after the `("socks-block-web", ...)` row, exactly: (block 2 below) — done when: `cargo test --locked --test cli_contract` passes.
   Block 1:
   ```rust
       ("mitm-insecure-host", Some("RULE"), "Accept invalid/self-signed upstream TLS certificates under MITM for matching destinations (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated"),
       ("mitm-bypass-host", Some("RULE"), "Exclude matching destinations (IP, CIDR, FQDN, or *.domain) from MITM interception: they get an opaque CONNECT tunnel instead; repeatable or comma-separated"),
       ("mitm-insecure", None, "UNSAFE blind trust: skip upstream TLS certificate verification for ALL MITM targets"),
   ```
   Block 2:
   ```rust
       ("error-page", Some("PATH"), "HTML template file for proxy-generated HTTP error pages (placeholders: {{status}}, {{reason}}, {{message}}, {{target}}) [default: built-in page]"),
   ```
3. [done] In `.github/workflows/release.yml`, delete every line from the comment line containing ``--version` reports the tag`` (line 77) up to, but not including, the line `      - name: Package archive (Unix)`. In their place paste lines 78-101 of `../rusty-conduit/.github/workflows/release.yml` (its comment, the `Derive release version` step, the `Build release binary` step, and the blank line after it) unchanged — done when: `diff <(awk '/reports the tag/,/Package archive \(Unix\)/' ../rusty-conduit/.github/workflows/release.yml) <(awk '/reports the tag/,/Package archive \(Unix\)/' .github/workflows/release.yml)` prints nothing and exits 0, and `grep -c 'does not match Cargo.toml version' .github/workflows/release.yml` prints `1`.
4. [done] Run `mkdir -p scripts && cp ../rusty-conduit-engine/scripts/check-pure-rust-crypto.py scripts/ && chmod 755 scripts/check-pure-rust-crypto.py`. Then insert `      - run: python3 scripts/check-pure-rust-crypto.py` directly after `      - run: cargo clippy --all-targets --locked -- -D warnings` in `.github/workflows/ci.yml` (`lint` job), and directly after `      - run: cargo test --locked` in `.github/workflows/release.yml` (`verify` job) — done when: `python3 scripts/check-pure-rust-crypto.py` prints `PURE_RUST_CRYPTO_OK` and `grep -c 'check-pure-rust-crypto.py'` prints `1` for each workflow file.
5. [done] In `DOX.md`, wherever the Verification commands are listed (`cargo fmt --check`, `cargo clippy ...`, `cargo test --locked`), add `python3 scripts/check-pure-rust-crypto.py` after `cargo test --locked`; and where `DOX.md` describes `release.yml`, add that the tag's `X.Y.Z` base must equal the `Cargo.toml` version or the build fails (wording as in `../rusty-conduit/DOX.md`, which says "the tag's `X.Y.Z` base must equal the `Cargo.toml` version (the build fails otherwise)") — done when: `grep -c 'check-pure-rust-crypto.py' DOX.md` and `grep -c 'base must equal the' DOX.md` each print at least `1`.
6. [done] Fix-up: wrap the `logger.info(format!(...))` call in `src/lib.rs` `log_startup` to match `rustfmt` output so `cargo fmt --check` passes — done when: `cargo fmt --check` exits 0.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
python3 scripts/check-pure-rust-crypto.py
test "$(grep -c 'CARGO_PKG_VERSION' src/lib.rs)" = 0
diff <(awk '/reports the tag/,/Package archive \(Unix\)/' ../rusty-conduit/.github/workflows/release.yml) <(awk '/reports the tag/,/Package archive \(Unix\)/' .github/workflows/release.yml)
test "$(grep -c 'check-pure-rust-crypto.py' .github/workflows/ci.yml)" = 1
test "$(grep -c 'check-pure-rust-crypto.py' .github/workflows/release.yml)" = 1
ruby -ryaml -e 'ARGV.each { |f| YAML.load_file(f) }' .github/workflows/ci.yml .github/workflows/release.yml
git diff --exit-code -- src/config.rs src/ssh.rs src/net.rs src/reverse.rs Cargo.toml Cargo.lock Dockerfile docs
```

## Escalate when
- A contract row fails (help text, value name, env var, or visibility) → stop, set Status: needs-human — reason: paste the failing assertion.
- An existing test asserts the old banner text → stop, set Status: needs-human — reason: name the test and paste its assertion.
- `python3 scripts/check-pure-rust-crypto.py` reports a banned crate → stop, set Status: needs-human — reason: paste its output.

## Log
- (append-only, one line per event)
- planner: before delegation, shifted the rusty-conduit release.yml line refs from 77-100 to 78-101 (rusty-conduit gained the crypto-check step in its verify job at fcc6cd4); the awk-based done-when check is unchanged
- executor: sub-task 1 done — updated `log_startup` in `src/lib.rs` to use `config::app_version()`
- executor: sub-task 2 done — added 4 shared flag rows (`mitm-insecure-host`, `mitm-bypass-host`, `mitm-insecure`, `error-page`) to `tests/cli_contract.rs`
- executor: sub-task 3 done — replaced release build steps in `.github/workflows/release.yml` with `Derive release version` + `Build release binary` from `../rusty-conduit/.github/workflows/release.yml`
- executor: sub-task 4 done — copied `scripts/check-pure-rust-crypto.py` from `../rusty-conduit-engine/scripts/` and wired it into `.github/workflows/ci.yml` (`lint`) and `.github/workflows/release.yml` (`verify`)
- executor: sub-task 5 done — added `python3 scripts/check-pure-rust-crypto.py` to Verification and tag base check note to release description in `DOX.md`
- executor: Verify failed on `cargo fmt --check` for `src/lib.rs:107`; added fix-up sub-task 6
- executor: sub-task 6 done — wrapped `logger.info(format!(...))` in `src/lib.rs` `log_startup` per `rustfmt`; all Verify checks pass

## Evidence
- (append-only: command → observed result)
- `grep -c 'CARGO_PKG_VERSION' src/lib.rs; cargo build --locked` → `0` and `Finished dev profile [unoptimized + debuginfo] target(s) in 4.18s` (exit 0)
- `cargo test --locked --test cli_contract` → `test result: ok. 3 passed; 0 failed` (exit 0)
- `diff <(awk '/reports the tag/,/Package archive \(Unix\)/' ../rusty-conduit/.github/workflows/release.yml) <(awk '/reports the tag/,/Package archive \(Unix\)/' .github/workflows/release.yml) && grep -c 'does not match Cargo.toml version' .github/workflows/release.yml` → empty diff and `1` (exit 0)
- `python3 scripts/check-pure-rust-crypto.py && grep -c 'check-pure-rust-crypto.py' .github/workflows/ci.yml .github/workflows/release.yml` → `PURE_RUST_CRYPTO_OK`, `ci.yml:1`, `release.yml:1` (exit 0)
- `grep -c 'check-pure-rust-crypto.py' DOX.md && grep -c 'base must equal the' DOX.md` → `1` and `1` (exit 0)
- `cargo fmt --check` → exit 1 (diff in `src/lib.rs:104`, wants multi-line `logger.info(format!(...))`)
- full `## Verify` block (`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `python3 scripts/check-pure-rust-crypto.py`, `grep`/`diff`/`ruby -ryaml`/`git diff --exit-code`) → `PURE_RUST_CRYPTO_OK`, `ALL_VERIFY_OK` (all tests passed, exit 0)
