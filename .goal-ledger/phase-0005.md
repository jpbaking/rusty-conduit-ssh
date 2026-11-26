# phase-0005 — Update user docs and DOX Feature Map

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002, phase-0003, phase-0004
- Goal: Make `README.md`, `docs/USER-GUIDE.md`, and `DOX.md` describe the new default, the `validate` subcommand, the block-with-exceptions filter rule, and the open-file limit behaviour.
- Done when: every command in `## Verify` exits 0.
- Pattern to follow: `../rusty-conduit-switch/docs/USER-GUIDE.md` (read only: its `validate` section and its `### Open-file limit` subsection, for wording)

## Context
Phases 0001–0004 changed: MITM cache default 10000 → 10240; `SOCKS4/5` → `SOCKS4/4a/5` in help; `--allow` + `--block` (and `--reverse-allow` + `--reverse-block`) together act as block-with-exceptions; new `rusty-conduit-ssh validate [TARGET]` prints `config OK: <path|none> target=<target>` and exits 0, or prints `config invalid: <error>` to stderr and exits 1; a host alias literally named `validate` must now be passed as `--target validate`; startup raises the soft open-file limit and logs `NOTICE: open-file limit is …` if it still cannot hold the forward plus reverse caps (needs `2 × connections + 64`).
In `DOX.md`, edit only the `## Project Contracts` and `## Feature Map` sections; the rest of that file is framework text. `README.md` and `docs/USER-GUIDE.md` ship in release archives, so keep them self-contained (no links to other repositories).

## Scope
- In: `README.md`, `docs/USER-GUIDE.md`, `DOX.md`
- Out: `src/`, `tests/`, `Dockerfile`, every file outside this repository

## Sub-tasks
1. [done] `docs/USER-GUIDE.md`: change `10000` to `10240` (the reference row near line 94 and the TOML example near line 158); replace `SOCKS4/5` with `SOCKS4/4a/5`; in the `--allow` / `--block` and `--reverse-allow` / `--reverse-block` rows, say that combining them blocks the blocklist except the allowlist entries — done when: `grep -nE '10000|SOCKS4/5' docs/USER-GUIDE.md` prints nothing.
2. [done] `docs/USER-GUIDE.md`: add a `## Checking a configuration` section before the exit-codes paragraph (near line 259) that shows `rusty-conduit-ssh validate myhost --config proxy.toml`, the two output forms, the exit codes, and the `--target validate` note; add an `### Open-file limit` subsection to the security or tuning part of the guide stating the `2 × connections + 64` rule (forward plus reverse caps), that the tool raises its soft limit at startup, and the NOTICE it logs otherwise — done when: `grep -n 'Checking a configuration' docs/USER-GUIDE.md` and `grep -n 'Open-file limit' docs/USER-GUIDE.md` both print a line.
3. [done] `README.md`: in `### Common variations` (near line 61) add `# Check a configuration without starting ssh` followed by `rusty-conduit-ssh validate myhost --config proxy.toml`; replace any `SOCKS4/5` with `SOCKS4/4a/5` — done when: `grep -n 'validate myhost' README.md` prints a line.
4. [done] `DOX.md` `## Feature Map`: add `- **\`validate\` subcommand** — loads and validates the configuration without starting ssh and exits 0/1. Start: \`src/lib.rs\` (\`cmd_validate\`). Files: \`src/config.rs\` (\`Command\`), \`tests/validate_cmd.rs\`.`, `- **Open-file limit** — raises the soft \`RLIMIT_NOFILE\` at startup and logs a NOTICE when it cannot hold the forward plus reverse caps. Start: \`src/fdlimit.rs\`. Files: \`src/lib.rs\` (\`fd_budget\`, \`run_until\`), \`Cargo.toml\` (\`rlimit\`).`, and `- **CLI family contract** — test that shared flags keep the family's names, value names, env vars, help text, and defaults. Start: \`tests/cli_contract.rs\`.`; in the **CLI entry and app lifecycle** bullet add `, dispatches \`validate\`` after `parses CLI/env` — done when: `grep -c 'cmd_validate\|fdlimit.rs\|cli_contract.rs' DOX.md` prints at least `3`.
5. [done] Planner fix-up (review finding): `docs/USER-GUIDE.md` still documents the hidden alias as the main flag. Replace the `--socks-block-web-in-mitm` row of the MITM table (near line 95) with exactly `| \`--socks-block-web\` | \`SOCKS_BLOCK_WEB\` | \`socks_block_web\` | \`false\` | Reject HTTP/HTTPS traffic over SOCKS4/4a/5 (works with or without MITM). The old names \`--socks-block-web-in-mitm\` and \`mitm.socks_block_web\` still work |`; in the TOML example move the line `socks_block_web = false` out of `[mitm]` (near line 158) to the top-level keys, directly after the first top-level `max_connections` line; in the MITM section (near line 331) replace `add \`--socks-block-web-in-mitm\`` with `add \`--socks-block-web\``; leave the log status name `blocked_web_in_mitm` unchanged — done when: `grep -n 'socks-block-web-in-mitm' docs/USER-GUIDE.md README.md | grep -v 'still work'` prints nothing.

## Verify
```sh
! grep -rnE '10000|SOCKS4/5' README.md docs
grep -n 'Checking a configuration' docs/USER-GUIDE.md
grep -n 'Open-file limit' docs/USER-GUIDE.md
grep -n -- '--target validate' docs/USER-GUIDE.md
grep -n 'validate myhost' README.md
grep -n 'cmd_validate' DOX.md
grep -n 'fdlimit.rs' DOX.md
! grep -n 'socks-block-web-in-mitm' docs/USER-GUIDE.md README.md | grep -v 'still work'
cargo test --locked
```

## Escalate when
- A doc describes behaviour that the code from phases 0001–0004 contradicts → stop, set Status: needs-human — reason: quote the doc line and what the code does.
- The user guide has no exit-codes paragraph near line 259 or no security/tuning section to hold the subsection → put the new text at the end of the guide, and note where in `## Log`.

## Log
- (append-only, one line per event)
- sub-task 1: updated `docs/USER-GUIDE.md` defaults (`10000` → `10240`), `SOCKS4/5` → `SOCKS4/4a/5`, and allow/block descriptions
- sub-task 2: added `## Checking a configuration` before the exit-codes paragraph and `### Open-file limit` under `## 9. Security checklist` in `docs/USER-GUIDE.md`
- sub-task 3: added `validate` example to `### Common variations` in `README.md` (no `SOCKS4/5` occurrences present)
- sub-task 4: updated `DOX.md` `## Feature Map` with `validate` subcommand, Open-file limit, CLI family contract, and updated CLI entry bullet

- planner review reopened phase-0005: docs/USER-GUIDE.md documents --socks-block-web-in-mitm (hidden alias, MITM-only wording) instead of --socks-block-web; added fix-up sub-task 5
- sub-task 5: updated `docs/USER-GUIDE.md` MITM table row, moved `socks_block_web = false` to top-level TOML keys after `max_connections = 4096`, and updated MITM section to `--socks-block-web` (kept `blocked_web_in_mitm` log status)

## Evidence
- (append-only: command → observed result)
- `! grep -nE '10000|SOCKS4/5' docs/USER-GUIDE.md` → exit 0 (no matches)
- `grep -n 'Checking a configuration' docs/USER-GUIDE.md && grep -n 'Open-file limit' docs/USER-GUIDE.md` → `259:## Checking a configuration`, `406:### Open-file limit`
- `grep -n 'validate myhost' README.md` → `84:rusty-conduit-ssh validate myhost --config proxy.toml`
- `grep -c 'cmd_validate\|fdlimit.rs\|cli_contract.rs' DOX.md` → `3`
- `! grep -rnE '10000|SOCKS4/5' README.md docs` → exit 0 (no matches)
- `grep -n -- '--target validate' docs/USER-GUIDE.md` → `269:- If you have an SSH host alias literally named \`validate\`, pass it with \`--target validate\` so it is not parsed as the subcommand.`
- `cargo test --locked` → exit 0 (156 passed: 102 unit + 54 integration, 0 failed)
- `! (grep -n 'socks-block-web-in-mitm' docs/USER-GUIDE.md README.md | grep -v 'still work')` → exit 0 (no non-alias matches)
- re-ran full `## Verify` including `cargo test --locked` → exit 0 (156 passed: 102 unit + 54 integration, 0 failed)
