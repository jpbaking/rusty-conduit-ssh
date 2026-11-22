# User Guide

This guide covers configuring and operating `rusty-conduit-ssh`. For an overview and quick start, see the [README](../README.md).

---

## 1. How configuration works

Settings are merged with strict precedence:

**CLI flags > `RUSTY_CONDUIT_SSH_*` environment variables > `--config` TOML file > built-in defaults**

- An SSH target is required. Give it as the positional `TARGET`, `--target`, `RUSTY_CONDUIT_SSH_TARGET`, or `ssh.target`.
- The positional `TARGET` and `--target` cannot be used together on the command line.
- Durations use human-readable forms such as `500ms`, `15s`, `30m`, or `1h`.
- Boolean environment variables accept values such as `true`/`false`, `1`/`0`, `yes`/`no`, and `on`/`off`. Setting one to a false value overrides `true` in the TOML file.
- Unknown TOML keys are rejected at startup.
- Extra `ssh` arguments given after `--` **replace** `ssh.extra_args`. They are not appended to it.

---

## 2. CLI, environment, and TOML reference

Environment variable names below omit the `RUSTY_CONDUIT_SSH_` prefix. For example, `BIND` means `RUSTY_CONDUIT_SSH_BIND`.

### General and listeners

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `[TARGET]`, `--target <TARGET>` | `TARGET` | `ssh.target` | required | SSH destination: host, `user@host`, or `~/.ssh/config` alias |
| `--config <PATH>` | `CONFIG` | n/a | none | TOML configuration file |
| `--bind <IP>` | `BIND` | `bind` | `127.0.0.1` | IPv4 or IPv6 listener address |
| `--http-port <PORT>` | `HTTP_PORT` | `http_port` | `3128` | HTTP/HTTPS port, `0` disables |
| `--socks-port <PORT>` | `SOCKS_PORT` | `socks_port` | `1080` | SOCKS4/5 port, `0` disables |
| `--max-connections <N>` | `MAX_CONNECTIONS` | `max_connections` | `4096` | Concurrent client cap, `0` = unlimited. Excess connections are closed immediately |

At least one listener must be enabled. Setting both ports to the same non-zero value serves all protocols on that port.

### SSH tunnel

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--ssh-bin <PATH>` | `SSH_BIN` | `ssh.bin` | `ssh` | Path or name of the `ssh` executable |
| `--ssh-socks-bind <IP>` | `SSH_SOCKS_BIND` | `ssh.socks_bind` | `127.0.0.1` | Local bind address for `ssh -D` |
| `--ssh-socks-port <PORT>` | `SSH_SOCKS_PORT` | `ssh.socks_port` | `0` | Local `ssh -D` port, `0` = ephemeral |
| `--ssh-ip-version <VERSION>` | `SSH_IP_VERSION` | `ssh.ip_version` | `4` | `4`, `6`, or `auto` |
| `-p`, `--ssh-port <PORT>` | `SSH_PORT` | `ssh.port` | from ssh | Remote SSH port (`ssh -p`) |
| `-i`, `--ssh-identity <PATH>` | `SSH_IDENTITY` | `ssh.identity` | from ssh | Identity file (`ssh -i`) |
| `-F`, `--ssh-config <PATH>` | `SSH_CONFIG` | `ssh.config` | from ssh | SSH client config (`ssh -F`) |
| `-J`, `--ssh-jump <HOST>` | `SSH_JUMP` | `ssh.jump` | from ssh | Jump host(s) (`ssh -J`) |
| `--ssh-server-alive-interval <DURATION>` | `SSH_SERVER_ALIVE_INTERVAL` | `ssh.server_alive_interval` | `15s` | `ServerAliveInterval`, rounded up to whole seconds |
| `--ssh-server-alive-count-max <N>` | `SSH_SERVER_ALIVE_COUNT_MAX` | `ssh.server_alive_count_max` | `3` | `ServerAliveCountMax` |
| `--no-reconnect` | `NO_RECONNECT` | `ssh.no_reconnect` | `false` | Exit when the tunnel drops |
| `--reconnect-initial-delay <DURATION>` | `RECONNECT_INITIAL_DELAY` | `ssh.reconnect_initial_delay` | `1s` | Delay before the first reconnect |
| `--reconnect-max-delay <DURATION>` | `RECONNECT_MAX_DELAY` | `ssh.reconnect_max_delay` | `30s` | Backoff ceiling, must be at least the initial delay |
| `--ssh-startup-timeout <DURATION>` | `SSH_STARTUP_TIMEOUT` | `ssh.startup_timeout` | `30s` | Time allowed for each tunnel attempt to become ready |
| `-- <SSH_ARGS>...` | n/a | `ssh.extra_args` | none | Extra arguments passed to `ssh` verbatim |

### HTTPS MITM

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--mitm-ca-cert <PATH>` | `MITM_CA_CERT` | `mitm.ca_cert` | none | PEM CA certificate, requires the key |
| `--mitm-ca-key <PATH>` | `MITM_CA_KEY` | `mitm.ca_key` | none | PEM CA private key, requires the certificate |
| `--mitm-ca-p12 <PATH>` | `MITM_CA_P12` | `mitm.ca_p12` | none | PKCS#12 CA bundle, cannot be combined with PEM |
| `--mitm-ca-passphrase <STR>` | `MITM_CA_PASSPHRASE` | `mitm.ca_passphrase` | none | CA passphrase. Prefer the env var or a file |
| `--mitm-ca-passphrase-file <PATH>` | `MITM_CA_PASSPHRASE_FILE` | `mitm.ca_passphrase_file` | none | File holding the passphrase, trailing newline trimmed |
| `--mitm-cert-ttl <DURATION>` | `MITM_CERT_TTL` | `mitm.cert_ttl` | `1h` | Leaf certificate TTL, minimum `10s` |
| `--mitm-cert-cache-max-entries <N>` | `MITM_CERT_CACHE_MAX_ENTRIES` | `mitm.cert_cache_max_entries` | `10000` | Leaf cache cap, `0` = unlimited |
| `--socks-block-web-in-mitm` | `SOCKS_BLOCK_WEB_IN_MITM` | `mitm.socks_block_web` | `false` | With MITM on, reject HTTP/HTTPS over SOCKS |

### Logging

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--log-level <LEVEL>` | `LOG_LEVEL` | `logging.level` | `INFO` | `QUIET`, `FATAL`, `ERROR`, `INFO`, `DEBUG`, `VERBOSE` (case-insensitive) |
| `--log-format <FMT>` | `LOG_FORMAT` | `logging.format` | `text` | Access/SOCKS log format: `text` (logfmt) or `json` (NDJSON) |
| `--http-access-log <PATH>` | `HTTP_ACCESS_LOG` | `logging.http_access_log` | none | HTTP/HTTPS access log file (append) |
| `--socks-log <PATH>` | `SOCKS_LOG` | `logging.socks_log` | none | SOCKS connection log file (append) |

Diagnostics go to `stderr`. At `DEBUG` and `VERBOSE`, access and SOCKS records are also written to `stdout`.

---

## 3. Example `config.toml`

Run it with `rusty-conduit-ssh --config config.toml`.

```toml
bind = "127.0.0.1"
http_port = 3128
socks_port = 1080
max_connections = 4096

[ssh]
target = "my-bastion"
bin = "ssh"
socks_bind = "127.0.0.1"
socks_port = 0
ip_version = 4
# port = 22
# identity = "/home/me/.ssh/id_ed25519"
# config = "/home/me/.ssh/config"
# jump = "jump.example.com"
server_alive_interval = "15s"
server_alive_count_max = 3
no_reconnect = false
reconnect_initial_delay = "1s"
reconnect_max_delay = "30s"
startup_timeout = "30s"
# extra_args = ["-C", "-o", "BatchMode=yes"]

[mitm]
# Use either ca_cert + ca_key, or ca_p12.
# ca_cert = "/etc/rusty-conduit-ssh/ca.pem"
# ca_key = "/etc/rusty-conduit-ssh/ca.key"
# ca_p12 = "/etc/rusty-conduit-ssh/ca.p12"
# Use at most one passphrase source.
# ca_passphrase = "change-me"
# ca_passphrase_file = "/etc/rusty-conduit-ssh/ca.pass"
cert_ttl = "1h"
cert_cache_max_entries = 10000
socks_block_web = false

[logging]
level = "INFO"
format = "text"
# http_access_log = "/var/log/rusty-conduit-ssh/access.log"
# socks_log = "/var/log/rusty-conduit-ssh/socks.log"
```

---

## 4. SSH authentication and `~/.ssh/config`

`rusty-conduit-ssh` launches your system `ssh` with this shape:

```text
ssh -N -T -4 -D 127.0.0.1:<port> \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    [-p PORT] [-i IDENTITY] [-F CONFIG] [-J JUMP] [extra args] -- TARGET
```

Keep host details in `~/.ssh/config` and pass the alias:

```sshconfig
Host my-bastion
    HostName bastion.example.com
    User deploy
    IdentityFile ~/.ssh/id_ed25519
    ProxyJump jump.example.com
```

```sh
rusty-conduit-ssh my-bastion
```

- **`ssh-agent` and FIDO2 keys** work as they do with plain `ssh`.
- **Interactive prompts** work because `ssh` inherits your terminal's stdin and stderr. Each attempt must finish within `--ssh-startup-timeout`, so raise it if you need longer to type a password or touch a key:

  ```sh
  rusty-conduit-ssh my-bastion --ssh-startup-timeout 2m
  ```

- **Unattended runs** (systemd, containers) have nobody to answer a prompt. Use key-based auth and make `ssh` fail fast:

  ```sh
  rusty-conduit-ssh my-bastion -- -o BatchMode=yes
  ```

- **Extra `-o` options cannot override the options above.** `ssh` keeps the first value it sees for an option, and the generated options come first. Use `--ssh-server-alive-interval` and `--ssh-server-alive-count-max` to change keepalives.
- **Extra arguments are never logged**, because they may contain sensitive values. Only their count appears in the startup summary.

---

## 5. Reconnect and keepalive tuning

**Detecting a dead link.** `ssh` exits after about `interval × count` of silence, which is 45 seconds by default. For faster detection on a reliable network:

```sh
rusty-conduit-ssh my-bastion \
  --ssh-server-alive-interval 5s \
  --ssh-server-alive-count-max 2
```

Very low values can cause false disconnects on lossy links.

**Backoff.** After a drop, the delay starts at `--reconnect-initial-delay` and doubles up to `--reconnect-max-delay` (by default 1s, 2s, 4s, and so on up to 30s). It resets once a tunnel has become ready.

**What clients see:**

| Situation | Behavior |
| :--- | :--- |
| First connection at startup | Retries until `--ssh-startup-timeout`, then exits with code `1`. Listeners are not open yet |
| Tunnel drops while running | Established connections end. Listeners stay open |
| New request while the tunnel is down | Fails immediately: HTTP clients get `502 Bad Gateway`, SOCKS clients get a failure reply |
| Upstream connect times out | HTTP clients get `504 Gateway Timeout` |
| Tunnel returns | New connections work with no client changes |

**`--no-reconnect`.** The process exits when the tunnel drops. It exits with code `1` if the tunnel never became ready, and `0` if it drops after startup, following an orderly drain.

**Shutdown.** `Ctrl+C` or `SIGTERM` stops new connections and drains active ones for up to 5 seconds. `ssh` then receives `SIGTERM` and is killed if it has not exited within 3 seconds.

**Exit codes:** `0` for a clean exit, `1` for a fatal startup or runtime error, and `2` for a command-line usage error.

---

## 6. DNS behavior

- HTTP, HTTPS, SOCKS4a, and SOCKS5-with-domain requests pass the **hostname** through the tunnel, and it is resolved on the SSH target.
- Plain SOCKS4 carries only an IP address, so the client has already resolved the name. Use SOCKS4a or SOCKS5 with remote DNS instead:
  - `curl --socks5-hostname` or `socks5h://`
  - `curl --socks4a` or `socks4a://`
  - Firefox's *Proxy DNS when using SOCKS v5* setting
- The SSH target's own hostname is resolved locally by `ssh`, unless a jump host or `ProxyCommand` changes how it connects.

---

## 7. Optional HTTPS MITM

MITM is **off** until you supply a CA, and a CA is never generated for you. Only inspect traffic you are authorized to inspect, and keep the CA private key protected, because anyone holding it can impersonate sites to clients that trust it.

### Create a CA

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca.key -out ca.pem -days 365 \
  -subj "/CN=rusty-conduit-ssh local CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
chmod 600 ca.key
```

### Run with the CA

```sh
# PEM
rusty-conduit-ssh my-bastion --mitm-ca-cert ca.pem --mitm-ca-key ca.key

# PKCS#12, with the passphrase in the environment
RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE='secret' \
  rusty-conduit-ssh my-bastion --mitm-ca-p12 ca.p12
```

Test it by trusting the CA for one request:

```sh
curl --cacert ca.pem -x http://127.0.0.1:3128 https://example.com/
```

### Supported CA formats

- **PEM certificate:** the CA certificate, optionally followed by intermediates.
- **PEM key:** PKCS#8, PKCS#1 RSA, SEC1 EC, or passphrase-encrypted PKCS#8. Legacy `Proc-Type: 4,ENCRYPTED` keys are rejected, so convert them to PKCS#8 first.
- **PKCS#12:** `.p12` or `.pfx`. Without a configured passphrase, an empty one is used.

The CA is checked at startup, before SSH authentication. An unparsable or expired certificate, or a key that does not match it, is a fatal error.

### How interception behaves

- MITM applies to HTTPS requests made through the **HTTP proxy** with `CONNECT`. HTTP/1.1 and HTTP/2 are supported.
- Upstream certificates are verified against the platform trust store.
- Leaf certificates are cached in memory only, bounded by `--mitm-cert-ttl` and `--mitm-cert-cache-max-entries`.
- SOCKS traffic is not intercepted. To stop web traffic bypassing inspection over SOCKS, add `--socks-block-web-in-mitm`. Blocked sessions are closed and logged with `status=blocked_web_in_mitm`, while non-web protocols such as SSH or Postgres pass through.

---

## 8. Security checklist

- Keep `--bind` on loopback unless a firewall restricts access. v1 has **no proxy authentication**, and a non-loopback bind logs a security notice at startup.
- Keep `--ssh-socks-bind` on loopback. The `ssh -D` listener is also unauthenticated and reaches everything the SSH target can reach.
- Prefer `RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE` or `--mitm-ca-passphrase-file` over `--mitm-ca-passphrase`, which is visible in process listings and shell history.
- Keep `--max-connections` bounded on shared hosts.
