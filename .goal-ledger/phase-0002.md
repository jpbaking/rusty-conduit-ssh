# phase-0002 — Add the validate subcommand

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: `rusty-conduit-ssh validate [TARGET]` loads, merges, and validates the configuration exactly as startup does, without starting ssh or any listener, and exits 0 or 1.
- Done when: `cargo test --locked` passes, including the new `tests/validate_cmd.rs`.
- Pattern to follow: `../rusty-conduit-switch/src/lib.rs:268-300` (read only: `cmd_validate` writing `config OK:` / `config invalid:` to injected writers) and `../rusty-conduit-switch/src/lib.rs:421-427` (dispatch in `main_entry`); `../rusty-conduit-switch/tests/routing_rules.rs:890-926` (binary test)

## Context
rusty-conduit-switch already has `validate`; the family now gets it in all three tools with the same output: success prints `config OK: <config path or none> ...` to stdout followed by any NOTICE lines and exits 0; failure prints `config invalid: <error>` to stderr and exits 1. Unlike the switch, a config file is optional here (everything can come from flags and env).
The planner prototyped this with clap 4.6.9: an optional subcommand works next to the positional `TARGET` and the `last = true` `SSH_ARGS`. `rusty-conduit-ssh myhost` still means TARGET=myhost and `rusty-conduit-ssh validate` selects the subcommand. Because `validate myhost` is rejected unless the subcommand has its own positional, give `Validate` a `target` positional. A host alias literally named `validate` must now be passed as `--target validate`; the docs phase records that.
`--config` must be `global = true` so `validate --config x.toml` works.

## Scope
- In: `src/config.rs`, `src/lib.rs`, `tests/validate_cmd.rs` (new)
- Out: `src/ssh.rs`, `src/net.rs`, `src/reverse.rs`, `tests/common/mod.rs`, every other file under `tests/`, `docs/`, `README.md`, `DOX.md`

## Sub-tasks
1. [done] In `src/config.rs`: import `Subcommand` from clap (line 21); add `#[derive(Debug, Clone, PartialEq, Eq, Subcommand)] pub enum Command { Validate { target: Option<String> } }` above `CliArgs`, with doc `/// Subcommands. Without one, the proxy runs.`, the variant doc `/// Validate the configuration (flags, environment, and --config file) and exit 0/1`, and on `target` the doc `/// SSH destination to validate with (same as the positional TARGET)` plus `#[arg(value_name = "TARGET")]`; add `#[command(subcommand)] pub command: Option<Command>,` as the first field of `CliArgs`; add `global = true` to the `--config` `#[arg(...)]` — done when: `cargo build` succeeds and `cargo run -q -- validate --help` exits 0.
2. [done] In `src/lib.rs`: add `use std::io::Write;` and `pub fn cmd_validate(mut cli: CliInput, out: &mut dyn Write, err: &mut dyn Write) -> u8`. If the parsed command is `Some(Command::Validate { target: Some(t) })`, set `cli.args.target = Some(t)`. Call `load_config(cli)`. On `Ok(cfg)` write `config OK: {path} target={target}` where `path` is `cfg.config_path` displayed or `none` and `target` is `cfg.ssh_target` or `none`, then each `cfg.notices()` entry on its own line, and return `0`. On `Err((e, _))` write `config invalid: {e}` to `err` and return `EXIT_FATAL`. Give it the doc `/// \`validate [TARGET]\`: exit 0 when the configuration is valid, 1 otherwise.` — done when: `cargo build` succeeds.
3. [done] In `main_entry` (`src/lib.rs:369`), right after `let cli = CliInput::parse();`, add: if `cli.args.command` is `Some(Command::Validate { .. })`, return `ExitCode::from(cmd_validate(cli, &mut std::io::stdout(), &mut std::io::stderr()))` — done when: `cargo run -q -- validate example.test` prints a line starting `config OK: none target=example.test` and exits 0, and `cargo run -q -- validate` prints `config invalid: missing SSH target` to stderr and exits 1.
4. [done] Create `tests/validate_cmd.rs` with three tests that run `env!("CARGO_BIN_EXE_rusty-conduit-ssh")` with `RUSTY_CONDUIT_SSH_TARGET` and `RUSTY_CONDUIT_SSH_CONFIG` removed from the environment: (a) `validate example.test` → exit 0, stdout contains `config OK: none target=example.test`; (b) `validate` → exit 1, stderr contains `config invalid:` and `missing SSH target`; (c) a TOML file written under `std::env::temp_dir()` containing `http_port = "nope"` passed as `validate example.test --config <file>` → exit 1, stderr contains `config invalid:`. Also (d) `example.test --no-such-flag` exits 2. Use the binary-test shape from the switch pattern; this file needs no `tests/common` helpers — done when: `cargo test --locked --test validate_cmd` passes 4 tests.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run -q -- validate example.test | grep -F 'config OK: none target=example.test'
cargo run -q -- --help | grep -F 'validate'
```

## Escalate when
- Adding the subcommand changes how any existing test parses a positional TARGET or `-- SSH_ARGS` (a test in `tests/` or `src/` starts failing) → stop, set Status: needs-human — reason: name the test and paste the clap error.
- clap rejects `global = true` on `--config` together with the positional or `last = true` args → stop, set Status: needs-human — reason: paste the clap debug-assert message.
- `load_config` turns out to start ssh, bind a port, or touch the network → stop, set Status: needs-human — reason: name the call that does it.

## Log
- (append-only, one line per event)
- sub-task 1: added `Command::Validate { target }` subcommand, `CliArgs.command`, and `global = true` on `--config` in `src/config.rs`
- sub-task 2: added `cmd_validate` in `src/lib.rs` with `config OK:` / `config invalid:` output and notices
- sub-task 3: wired `Command::Validate` dispatch in `main_entry` (`src/lib.rs`)
- sub-task 4: created `tests/validate_cmd.rs` with 4 binary tests covering valid target, missing target, invalid TOML config, and unknown flag exit code 2

## Evidence
- (append-only: command → observed result)
- `cargo build && cargo run -q -- validate --help` → exit 0; printed `Usage: rusty-conduit-ssh validate [OPTIONS] [TARGET]` with `--config <PATH>`
- `cargo build` → exit 0
- `cargo run -q -- validate example.test` → exit 0, stdout `config OK: none target=example.test`; `cargo run -q -- validate` → exit 1, stderr `config invalid: missing SSH target: pass [TARGET], --target, RUSTY_CONDUIT_SSH_TARGET, or ssh.target`
- `cargo test --locked --test validate_cmd` → exit 0 (4 passed, 0 failed)
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked` → exit 0 (145 passed: 94 unit + 51 integration, 0 failed)
- `cargo run -q -- validate example.test | grep -F 'config OK: none target=example.test'` → exit 0 (matched)
- `cargo run -q -- --help | grep -F 'validate'` → exit 0 (matched `validate  Validate the configuration (flags, environment, and --config file) and exit 0/1`)
