# Advanced User Guide & Configuration Reference

This guide covers configuring and operating `rusty-conduit-ssh` in depth: configuration precedence and the full reference, SSH launch details, reconnect and keepalive tuning, DNS behavior, HTTPS MITM, the reverse proxy, logging, custom proxy error pages, and a security checklist.

- New to `rusty-conduit-ssh`? Start with the **[Basic User Guide](USER-GUIDE-BASIC.md)**.
- For RAM/CPU budgets, `ulimit -n` and `somaxconn` limits, and cap mechanics, see **[Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md)**.
- For creating and trusting a private CA, see the **[MITM CA Guide](MITM-CA-GUIDE.md)**.
- For containers and Compose, see the **[Docker Guide](DOCKER-GUIDE.md)**.

---

## 1. Configuration precedence and reference

Settings are merged with strict precedence:

**CLI flags > `RUSTY_CONDUIT_SSH_*` environment variables > `--config` TOML file > built-in defaults**

- An SSH target is required. Give it as the positional `TARGET`, `--target`, `RUSTY_CONDUIT_SSH_TARGET`, or `ssh.target`.
- The positional `TARGET` and `--target` cannot be used together on the command line.
- Durations use human-readable forms such as `500ms`, `15s`, `30m`, or `1h`.
- Boolean environment variables accept values such as `true`/`false`, `1`/`0`, `yes`/`no`, and `on`/`off`. Setting one to a false value overrides `true` in the TOML file.
- Unknown TOML keys are rejected at startup.
- Extra `ssh` arguments given after `--` **replace** `ssh.extra_args`. They are not appended to it.

Environment variable names below omit the `RUSTY_CONDUIT_SSH_` prefix. For example, `BIND` means `RUSTY_CONDUIT_SSH_BIND`.

### General and listeners

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `[TARGET]`, `--target <TARGET>` | `TARGET` | `ssh.target` | required | SSH destination: host, `user@host`, or `~/.ssh/config` alias |
| `--config <PATH>` | `CONFIG` | n/a | none | TOML configuration file |
| `-V`, `--version` | n/a | n/a | n/a | Print the version and exit. Release builds print the release tag without its `v` (for example `2.3.0` or `2.3.0-beta.1`); local source builds print `<crate version>-dev` |
| `--bind <IP>` | `BIND` | `bind` | `127.0.0.1` | IPv4 or IPv6 listener address |
| `--http-port <PORT>` | `HTTP_PORT` | `http_port` | `3128` | HTTP/HTTPS port, `0` disables |
| `--socks-port <PORT>` | `SOCKS_PORT` | `socks_port` | `1080` | SOCKS4/4a/5 port, `0` disables |
| `--max-connections <N>` | `MAX_CONNECTIONS` | `max_connections` | `4096` | Concurrent forward proxy clients, HTTP and SOCKS combined, `0` = unlimited. Excess connections are closed immediately. Also the reverse cap unless `--reverse-max-connections` is set |
| `--tcp-keepalive <DURATION>` | `TCP_KEEPALIVE` | `tcp_keepalive` | `60s` | Idle time before TCP keepalive probes start, on forward and reverse client sockets and reverse upstream sockets. `0` disables; otherwise `1s` to `32767s` |
| `--tcp-keepalive-interval <DURATION>` | `TCP_KEEPALIVE_INTERVAL` | `tcp_keepalive_interval` | `10s` | Time between unanswered keepalive probes, `1s` to `32767s` |
| `--tcp-keepalive-retries <N>` | `TCP_KEEPALIVE_RETRIES` | `tcp_keepalive_retries` | `5` | Unanswered probes before the OS closes the connection, `1` to `127` |

At least one forward or reverse listener must be enabled. Setting both ports to the same non-zero value serves all protocols on that port.

### Reverse proxy

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--reverse-bind <IP>` | `REVERSE_BIND` | `reverse.bind` | `127.0.0.1` | Bind address on the SSH target for `ssh -R` |
| `--reverse-http-port <PORT>` | `REVERSE_HTTP_PORT` | `reverse.http_port` | `0` | HTTP/HTTPS port on the SSH target, `0` disables |
| `--reverse-socks-port <PORT>` | `REVERSE_SOCKS_PORT` | `reverse.socks_port` | `0` | SOCKS4/4a/5 port on the SSH target, `0` disables |
| `--reverse-max-connections <N>` | `REVERSE_MAX_CONNECTIONS` | `reverse.max_connections` | same as `--max-connections` | Concurrent reverse proxy clients, HTTP and SOCKS combined, `0` = unlimited. Excess connections are closed immediately |
| `--reverse-allow <RULE>` | `REVERSE_ALLOW` | `reverse.allow` | none | Reverse allowlist (IP, CIDR, FQDN, or `*.domain`); when combined with `--reverse-block`, serves as exceptions to the reverse blocklist |
| `--reverse-block <RULE>` | `REVERSE_BLOCK` | `reverse.block` | none | Reverse blocklist (IP, CIDR, FQDN, or `*.domain`); combine with `--reverse-allow` to block the blocklist except the allowlist entries |

### Destination filtering (forward proxy)

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--allow <RULE>` | `ALLOW` | `allow` | none | Forward allowlist (IP, CIDR, FQDN, or `*.domain`); when combined with `--block`, serves as exceptions to the blocklist |
| `--block <RULE>` | `BLOCK` | `block` | none | Forward blocklist (IP, CIDR, FQDN, or `*.domain`); combine with `--allow` to block the blocklist except the allowlist entries |

CLI flags may be repeated or comma-separated (e.g. `--reverse-block 127.0.0.0/8,::1,*.internal`). Wildcards use a leading `*.` prefix and match subdomains only (`*.example.com` matches `api.example.com`, not bare `example.com`). Blocked requests return HTTP `403 Forbidden`, SOCKS5 `0x02` (`not_allowed`), or SOCKS4 `0x5B`. On the **reverse** path, hostnames are resolved locally before connecting so IP/CIDR rules also catch hostnames that resolve to blocked IPs (e.g. `localhost` → `127.0.0.1`). On the **forward** path, DNS remains remote-only, so FQDN rules match domain requests and IP/CIDR rules match literal IP requests.

See [Reverse proxy](#7-reverse-proxy-ssh--r) for behavior and security guidance.

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
| `--mitm-cert-cache-max-entries <N>` | `MITM_CERT_CACHE_MAX_ENTRIES` | `mitm.cert_cache_max_entries` | `10240` | Leaf cache cap, `0` = unlimited |
| `--mitm-insecure-host <RULE>` | `MITM_INSECURE_HOST` | `mitm.insecure_hosts` | none | Under MITM, accept invalid/self-signed upstream TLS certs for matching destinations (IP, CIDR, FQDN, or `*.domain`; same syntax as `--allow`). Repeatable or comma-separated; CLI/env replaces the TOML list. An invalid rule is a fatal error |
| `--mitm-bypass-host <RULE>` | `MITM_BYPASS_HOST` | `mitm.bypass_hosts` | none | Under MITM, never intercept matching destinations (IP, CIDR, FQDN, or `*.domain`; same syntax as `--allow`): their `CONNECT` stays an opaque end-to-end TLS tunnel. Use it for certificate-pinned or sensitive sites. Repeatable or comma-separated; CLI/env replaces the TOML list. An invalid rule is a fatal error |
| `--mitm-insecure` | `MITM_INSECURE` | `mitm.insecure` | `false` | **Unsafe** blind trust: skip upstream TLS certificate verification for ALL MITM targets. Enabled if set in CLI/env **or** TOML; takes precedence over `--mitm-insecure-host` |
| `--socks-block-web` | `SOCKS_BLOCK_WEB` | `socks_block_web` | `false` | Reject HTTP/HTTPS traffic over SOCKS4/4a/5 (works with or without MITM). |

### Error pages

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--error-page <PATH>` | `ERROR_PAGE` | `error_page` | built-in page | HTML template for proxy-generated HTTP error pages on the forward and reverse proxies (placeholders `{{status}}`, `{{reason}}`, `{{message}}`, `{{target}}`). Upstream responses are never altered. An unreadable file is a fatal error. See [Custom proxy error pages](#9-custom-proxy-error-pages) |

### Logging

| CLI flag | Env (after prefix) | TOML key | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--log-level <LEVEL>` | `LOG_LEVEL` | `logging.level` | `INFO` | `QUIET`, `FATAL`, `ERROR`, `INFO`, `DEBUG`, `VERBOSE` (case-insensitive) |
| `--log-format <FMT>` | `LOG_FORMAT` | `logging.format` | `text` | Access/SOCKS log format: `text` (logfmt) or `json` (NDJSON) |
| `--http-access-log <PATH>` | `HTTP_ACCESS_LOG` | `logging.http_access_log` | none | HTTP/HTTPS access log file (append) |
| `--socks-log <PATH>` | `SOCKS_LOG` | `logging.socks_log` | none | SOCKS connection log file (append) |

Diagnostics go to `stderr`. At `DEBUG` and `VERBOSE`, access and SOCKS records are also written to `stdout`. Every HTTP and SOCKS record includes `direction=forward` (local → SSH target via `-D`) or `direction=reverse` (SSH target → local via `-R`).

### Checking a configuration

Use the `validate` subcommand to load, merge, and validate CLI flags, environment variables, and `--config` without connecting to the SSH server or binding any listener:

```sh
rusty-conduit-ssh validate myhost --config proxy.toml
rusty-conduit-ssh --http-port 8080 validate myhost --config proxy.toml
```

Other flags go before the subcommand; only `--config` may follow it.

- On success, it prints `config OK: <path|none> target=<target>` (followed by any startup `NOTICE:` and MITM `WARN:` lines) to `stdout` and exits `0`.
- On failure, it prints `config invalid: <error>` to `stderr` and exits `1`.
- It also checks what startup checks before launching `ssh`: the MITM CA (files, passphrase, validity, and that the key matches the certificate), that each log file can be opened (without creating it), that the `--error-page` template can be read, that the `ssh` program exists, that the `-i` key and `-F` config can be read, and that `ssh -G` accepts the configuration for the target. `ssh -G` evaluates the SSH config and exits without connecting. It prints the open-file `NOTICE` startup would log, too.
- `--settings-only` skips those checks, for checking a config away from the host it runs on, for example in CI: `rusty-conduit-ssh validate myhost --settings-only --config proxy.toml`.
- If you have an SSH host alias literally named `validate`, pass it with `--target validate` so it is not parsed as the subcommand.

Startup runs the same checks before it launches `ssh`. A missing key, an unreadable or broken SSH config, an unreadable `--error-page` file, or a bad CA stops the proxy at once with one `FATAL` line, instead of turning into failed logins and reconnects against the SSH server.

**Exit codes:** `0` for a clean exit, `1` for a fatal startup or runtime error, and `2` for a command-line usage error.

---

## 2. Example `config.toml`

Run it with `rusty-conduit-ssh --config config.toml`.

```toml
bind = "127.0.0.1"
http_port = 3128
socks_port = 1080
max_connections = 4096
socks_block_web = false
# Optional custom HTML template for proxy-generated error pages (default: built-in page):
# error_page = "/etc/rusty-conduit-ssh/error.html"
tcp_keepalive = "60s"          # "0" disables
tcp_keepalive_interval = "10s"
tcp_keepalive_retries = 5

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

[reverse]
# Ports on the SSH target. 0 disables; equal non-zero ports share one listener.
bind = "127.0.0.1"
http_port = 0
socks_port = 0
# Unset: the top-level max_connections applies here too.
# max_connections = 64

[mitm]
# Use either ca_cert + ca_key, or ca_p12.
# ca_cert = "/etc/rusty-conduit-ssh/ca.pem"
# ca_key = "/etc/rusty-conduit-ssh/ca.key"
# ca_p12 = "/etc/rusty-conduit-ssh/ca.p12"
# Use at most one passphrase source.
# ca_passphrase = "change-me"
# ca_passphrase_file = "/etc/rusty-conduit-ssh/ca.pass"
cert_ttl = "1h"
cert_cache_max_entries = 10240
# Skip upstream TLS verification only for these lab / self-signed origins:
# insecure_hosts = ["dev.internal", "*.lab.example", "10.20.0.0/16"]
# Never intercept these destinations (opaque CONNECT tunnel instead):
# bypass_hosts = ["bank.example", "*.pinned.example", "203.0.113.0/24"]
# UNSAFE: skip upstream TLS verification for every destination:
# insecure = false

[logging]
level = "INFO"
format = "text"
# http_access_log = "/var/log/rusty-conduit-ssh/access.log"
# socks_log = "/var/log/rusty-conduit-ssh/socks.log"
```

---

## 3. SSH launch and authentication

`rusty-conduit-ssh` launches your system `ssh` with this shape:

```text
ssh -N -T -4 -D 127.0.0.1:<port> \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    [-R REMOTE_IP:REMOTE_PORT:127.0.0.1:LOCAL_PORT ...] \
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

## 4. Reconnect and keepalive tuning

**Detecting a dead link.** `ssh` exits after about `interval × count` of silence, which is 45 seconds by default. For faster detection on a reliable network:

```sh
rusty-conduit-ssh my-bastion \
  --ssh-server-alive-interval 5s \
  --ssh-server-alive-count-max 2
```

Very low values can cause false disconnects on lossy links.

**Long silent connections.** Once a tunnel, SOCKS relay, or HTTP connection is established, no idle or total-lifetime timeout applies. A connection stays open for as long as both peers keep it open, however long it is silent. NAT gateways, firewalls, VPNs, Docker or Kubernetes conntrack, and cloud load balancers can still expire idle flows outside the proxy, often without telling either end. Long-polling clients, such as AI agents waiting on a model response, are the usual victims.

To keep that state alive, OS-level TCP keepalive is enabled on each hop that rusty-conduit-ssh owns, in both directions. The first probe goes out after `60s` idle, then every `10s`, and the connection is closed after `5` unanswered probes, about 110 seconds after the peer vanishes. Tune it with `--tcp-keepalive`, `--tcp-keepalive-interval`, and `--tcp-keepalive-retries`, or turn it off with `--tcp-keepalive 0`.

| Hop | Kept alive by |
| :--- | :--- |
| Forward client ↔ forward listener | TCP keepalive |
| Your machine ↔ SSH target (the `ssh` session itself) | `ServerAliveInterval`, as above. This carries both forward and reverse traffic |
| SSH target ↔ forward destination | sshd. rusty-conduit-ssh does not control this socket |
| Reverse client ↔ sshd on the SSH target | sshd. Set `ClientAliveInterval` or `TCPKeepAlive` in `sshd_config` |
| Reverse listener ↔ reverse destination (direct egress from your machine) | TCP keepalive |

- Probes are empty TCP segments handled by the kernel. They are invisible to HTTP, TLS, SOCKS, and any tunneled protocol, and cost about 60 bytes per idle interval.
- Probes keep a single hop alive. They are not forwarded end to end, and they cannot save a connection whose path is broken.
- For SSH through the proxy, also set `ServerAliveInterval` (for example `30`) in `~/.ssh/config` for that inner session. It works end to end inside the encrypted session.
- On platforms without per-socket interval and retry control, only the idle time is applied.

**Backoff.** After a drop, the delay starts at `--reconnect-initial-delay` and doubles up to `--reconnect-max-delay` (by default 1s, 2s, 4s, and so on up to 30s). It resets once a tunnel has become ready. Each wait is randomized by ±20% so that many instances do not retry in lockstep.

**What clients see:**

| Situation | Behavior |
| :--- | :--- |
| First connection at startup | Retries until `--ssh-startup-timeout`, then exits with code `1`. Listeners are not open yet |
| Tunnel drops while running | Established connections end. Listeners stay open |
| New request while the tunnel is down | Fails immediately: HTTP clients get `502 Bad Gateway`, SOCKS clients get a failure reply |
| Upstream connect times out | HTTP clients get `504 Gateway Timeout` |
| Tunnel returns | New connections work with no client changes |

**`--no-reconnect`.** The process exits when the tunnel drops. It exits with code `1` if the tunnel never became ready, and `0` if it drops after startup, following an orderly drain.

**Shutdown.** `Ctrl+C` or `SIGTERM` stops new connections and drains active ones for up to 5 seconds. `ssh` then receives `SIGTERM` and is killed if it has not exited within 3 seconds. If the reverse proxy is enabled, it drains for up to 5 more seconds after `ssh` stops.

---

## 5. DNS behavior

- HTTP, HTTPS, SOCKS4a, and SOCKS5-with-domain requests pass the **hostname** through the tunnel, and it is resolved on the SSH target.
- Plain SOCKS4 carries only an IP address, so the client has already resolved the name. Use SOCKS4a or SOCKS5 with remote DNS instead:
  - `curl --socks5-hostname` or `socks5h://`
  - `curl --socks4a` or `socks4a://`
  - Firefox's *Proxy DNS when using SOCKS v5* setting
- The SSH target's own hostname is resolved locally by `ssh`, unless a jump host or `ProxyCommand` changes how it connects.

---

## 6. Optional HTTPS MITM

MITM is **off** until you supply a CA, and a CA is never generated for you. Only inspect traffic you are authorized to inspect, and keep the CA private key protected, because anyone holding it can impersonate sites to clients that trust it.

### Create a CA

The [MITM CA Guide](MITM-CA-GUIDE.md) walks through creating a PEM or PKCS#12 CA with `openssl`, encrypting its key, and trusting it on Linux, macOS, Windows, Firefox, and CLI tools. The short version, for a quick test:

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
- Upstream certificates are verified against the platform trust store; an invalid origin certificate fails the request (`status=502`). The startup `config:` line shows the mode as `mitm_upstream_tls=strict|insecure_hosts(N)|insecure_all`. The same mode applies to the forward and the reverse proxy:
  - `--mitm-insecure-host <RULE>` accepts invalid or self-signed certificates only for matching targets (exact domain, `*.domain`, IP, or CIDR); every other target is still verified.
  - `--mitm-insecure` accepts any upstream certificate for every target (blind trust). Use it only on isolated test networks: anyone on the path to the origin can impersonate it.
  - While MITM is enabled, either option logs a `WARN:` line at startup (at `INFO`), and `validate` prints it too: blind trust says certificates are not verified for any destination; the host list names the count and the rules.
- `--mitm-bypass-host <RULE>` excludes matching `CONNECT` targets (exact domain, `*.domain`, IP, or CIDR) from interception: they get an opaque tunnel, no leaf certificate is minted, and clients need not trust the CA for them. Bypass applies to the forward and the reverse proxy. The startup `config:` line shows the rule count as `mitm_bypass_hosts=N`.
- Leaf certificates are cached in memory only, bounded by `--mitm-cert-ttl` and `--mitm-cert-cache-max-entries`.
- SOCKS traffic is not intercepted. To stop web traffic bypassing inspection over SOCKS, add `--socks-block-web`. Blocked sessions are closed and logged with `status=blocked_web_in_mitm`, while non-web protocols such as SSH or Postgres pass through.

---

## 7. Reverse proxy (`ssh -R`)

The reverse proxy is **off** until you set a reverse port. It lets clients on the SSH target egress through the machine running `rusty-conduit-ssh`, over the same supervised SSH connection as the forward proxy.

```text
client on SSH target -> sshd:REMOTE_PORT -> ssh -R -> local reverse listener -> internet
```

### Choosing ports

| `reverse_http_port` | `reverse_socks_port` | Result |
| :--- | :--- | :--- |
| `0` | `0` | Disabled, no `-R` argument |
| `8888` | `8888` | One multiplexed listener and one `-R` |
| `8888` | `1081` | Two listeners and two `-R` arguments |
| `8888` | `0` | HTTP/HTTPS only |
| `0` | `1081` | SOCKS4/4a/5 only |

```sh
# Forward and reverse proxies together
rusty-conduit-ssh my-bastion --reverse-http-port 8888 --reverse-socks-port 1081

# Reverse only. ssh -D still runs, because it is the tunnel readiness check
rusty-conduit-ssh my-bastion --http-port 0 --socks-port 0 \
  --reverse-http-port 8888 --reverse-socks-port 8888
```

On the SSH target:

```sh
curl -x http://127.0.0.1:8888 https://example.com/
curl --socks5-hostname 127.0.0.1:8888 https://example.com/
```

### How it behaves

- **Egress and DNS are local.** Reverse connections dial directly from your machine and use its resolver, so hostnames are resolved there rather than on the SSH target.
- **Local ports stay stable.** The ephemeral loopback listeners are bound once at startup and reused by every reconnect.
- **Remote bind failures are retried.** With `ExitOnForwardFailure=yes`, `ssh` exits if the remote port is taken, and the supervisor retries with backoff. After an abrupt disconnect, sshd may hold the old port until it notices the dead session, so setting `ClientAliveInterval` on the server shortens that window.
- **Each direction has its own connection cap**, so one side cannot exhaust the other. The forward proxy uses `--max-connections` and the reverse proxy uses `--reverse-max-connections`, which defaults to the same value. Within one direction, HTTP and SOCKS share the cap. Set a lower reverse cap to limit how much remote clients can open through your machine.
- **MITM applies to both directions** when a CA is configured. The reverse proxy has its own certificate cache and dials directly.
- **Logs are shared.** Reverse connections go to the same access and SOCKS logs as forward connections.

### Security

The reverse proxy has **no authentication**, and it connects from your machine. Anyone who can reach its remote port can reach what your machine can reach, including `127.0.0.1` services and your LAN.

- Keep `--reverse-bind` on loopback, and use the reverse proxy only on SSH targets whose local users you trust.
- **The SSH server decides the final bind address, not `--reverse-bind`.** Check `GatewayPorts` in the target's `sshd_config`. It may be set inside a `Match` block, so run `sudo sshd -T -C user=<you>,host=<client-host>,addr=<client-ip> | grep -i gatewayports` to see the value that applies to you:

  | `GatewayPorts` | `--reverse-bind 127.0.0.1` | Non-loopback `--reverse-bind` |
  | :--- | :--- | :--- |
  | `no` (default) | Loopback | Loopback. The requested address is ignored without an error |
  | `clientspecified` (**recommended**) | Loopback | The requested address |
  | `yes` | **All interfaces** | All interfaces |

  With `yes`, sshd binds every remote forward to the wildcard address **even when you request `127.0.0.1`**, so the unauthenticated reverse proxy is open to the network. The client cannot detect this: the SSH reply carries only the port. Use `GatewayPorts clientspecified` on targets where you run the reverse proxy. It honours the address you request, keeps `127.0.0.1` private, and still allows a deliberate non-loopback bind. Confirm with `ss -tlnp` on the target.
- A non-loopback `--reverse-bind` logs a security notice.
- Add a `--reverse-block` blocklist such as `127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` as a second line of defence, so an exposed port still cannot reach your loopback services or LAN.

---

## 8. Logging

### Stream separation and levels

Diagnostic logs, and `ssh`'s own messages, write to **`stderr`**. Access and SOCKS logs write to their configured files, and at `DEBUG` / `VERBOSE` are **also** copied to **`stdout`** so you can pipe them independently.

| Level | `stderr` (Diagnostics) | Access & SOCKS Logs |
| :--- | :--- | :--- |
| `QUIET` | None | Files only (if configured) |
| `FATAL` | Unrecoverable startup errors | Files only |
| `ERROR` | `FATAL` + runtime / connection errors, tunnel drops | Files only |
| `INFO` *(default)* | `ERROR` + startup banner, config summary, notices, tunnel ready, shutdown | Files only |
| `DEBUG` | `INFO` + per-connection lifecycle, rejected handshakes, cap drops | **Files AND `stdout`** |
| `VERBOSE` | `DEBUG` + cert reaper & cache eviction stats | **Files AND `stdout`** |

Log files are written through a buffer that is flushed whenever no more records are queued, so records reach the file within moments even on a quiet proxy, while bursts are still written in large blocks. Records on `stdout` are written immediately.

### Log formats (`text` vs. `json`)

Every record carries `direction=forward` (local clients → SSH target via `-D`) or `direction=reverse` (clients on the SSH target → your machine via `-R`), right after `kind`.

**`text` (default, logfmt):**

```text
ts=2026-11-26T20:55:27.608Z kind=http direction=forward client=172.18.0.1:59956 proto=https mitm=false method=CONNECT target=example.com:443 status=200 bytes_in=585 bytes_out=4878 duration_ms=410
ts=2026-11-26T20:55:27.972Z kind=socks direction=forward client=172.18.0.1:62730 proto=socks5 cmd=CONNECT target=example.com:80 status=ok bytes_in=74 bytes_out=933 duration_ms=234
```

**`json` (`--log-format json`, NDJSON):**

```json
{"ts":"2026-11-26T20:55:32.568Z","kind":"http","direction":"forward","client":"172.18.0.1:59966","proto":"https","mitm":false,"method":"CONNECT","target":"example.com:443","status":200,"bytes_in":585,"bytes_out":4877,"duration_ms":328}
```

Example live filtering with `jq`, showing only reverse-proxy traffic:

```sh
rusty-conduit-ssh my-bastion --reverse-http-port 8888 --log-level DEBUG --log-format json 2>/dev/null \
  | jq -r 'select(.direction=="reverse") | "\(.ts) \(.client) \(.target) \(.status)"'
```

---

## 9. Custom proxy error pages

When `rusty-conduit-ssh` itself answers an HTTP request with an error, such as a malformed request (`400`), a destination denied by `--allow` / `--block` / `--reverse-allow` / `--reverse-block` (`403`), an upstream it cannot reach or verify (`502`), or a timeout (`504`), it sends an HTML page. By default this is a small, unbranded built-in page. Replace it with your own template:

```sh
rusty-conduit-ssh my-bastion --error-page /etc/rusty-conduit-ssh/error.html
# or: RUSTY_CONDUIT_SSH_ERROR_PAGE=/etc/rusty-conduit-ssh/error.html
# or, in the TOML file (top level): error_page = "/etc/rusty-conduit-ssh/error.html"
```

The template is a UTF-8 file read once at startup. These placeholders are replaced in every page, and every value is HTML-escaped:

| Placeholder | Value |
| :--- | :--- |
| `{{status}}` | Numeric status code, for example `502` |
| `{{reason}}` | Standard reason phrase, for example `Bad Gateway` |
| `{{message}}` | The proxy's explanation of the error |
| `{{target}}` | The requested URL or `host:port` (never includes userinfo); empty when unknown |

```html
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{{status}} {{reason}}</title></head>
<body><h1>{{status}} {{reason}}</h1><p>{{message}}</p><p><code>{{target}}</code></p></body></html>
```

- The template applies to every proxy-generated HTTP error on both the forward proxy and the reverse proxy (`ssh -R`): plain forwarding, `CONNECT`, and decrypted MITM requests. Pages are sent as `text/html; charset=utf-8` with `Cache-Control: no-store`.
- **Responses from an upstream origin are never altered**, error statuses included: a `404` or `500` from the origin reaches the client exactly as sent.
- SOCKS has no HTTP error responses, so the template does not apply to it.
- The startup `config:` line shows `error_page=<path>` or `error_page=builtin`. An unreadable file is a `FATAL` startup error, reported before `ssh` is launched; `validate` reports it too, unless `--settings-only`.

---

## 10. Security checklist

- Keep `--bind` on loopback unless a firewall restricts access. There is **no proxy authentication**, and a non-loopback bind logs a security notice at startup.
- Keep `--reverse-bind` on loopback. The reverse proxy gives its clients access to whatever your machine can reach, including its loopback services.
- On SSH targets where you run the reverse proxy, set `GatewayPorts clientspecified` in `sshd_config`. With `GatewayPorts yes`, sshd binds remote forwards to all interfaces even when you request `127.0.0.1`.
- Keep `--ssh-socks-bind` on loopback. The `ssh -D` listener is also unauthenticated and reaches everything the SSH target can reach.
- Prefer `RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE` or `--mitm-ca-passphrase-file` over `--mitm-ca-passphrase`, which is visible in process listings and shell history.
- Keep `--max-connections` and `--reverse-max-connections` bounded on shared hosts.
