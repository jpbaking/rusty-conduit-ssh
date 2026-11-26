# Basic User Guide

This guide gets you up and running with `rusty-conduit-ssh`: one command that turns an SSH login into a local HTTP/HTTPS and SOCKS proxy, with every upstream connection and DNS lookup going through the SSH target.

- Looking for every flag and TOML key, reconnect tuning, the reverse proxy in depth, MITM, or logging details? See the **[Advanced User Guide](USER-GUIDE-ADVANCED.md)**.
- Curious about RAM, CPU, or `ulimit -n` sizing? See **[Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md)**.
- Running in Docker or Compose? See the **[Docker Guide](DOCKER-GUIDE.md)**.

---

## 1. Install

`rusty-conduit-ssh` runs your system OpenSSH client, so `ssh` must be on your `PATH`. Linux and macOS ship it; on Windows 10 and later, it is the built-in *OpenSSH Client* optional feature.

### Option A: Download a prebuilt binary (recommended)

Grab the archive for your OS and CPU architecture from the [GitHub Releases](https://github.com/jpbaking/rusty-conduit-ssh/releases) page:

- **Linux:** `rusty-conduit-ssh-<version>-linux-amd64.tar.gz` or `linux-arm64.tar.gz`
- **macOS:** `rusty-conduit-ssh-<version>-macos-arm64.tar.gz` (Apple Silicon) or `macos-amd64.tar.gz` (Intel)
- **Windows:** `rusty-conduit-ssh-<version>-windows-amd64.zip` or `windows-arm64.zip`

Extract it and place `rusty-conduit-ssh` (or `rusty-conduit-ssh.exe`) somewhere on your `PATH`.

### Option B: Run with Docker

Multi-arch images (`linux/amd64` and `linux/arm64`, based on Ubuntu 26.04 LTS, with `openssh-client` included) are published to GitHub Container Registry on each release. They run as a non-root user (UID `10001`). The container needs a key, `known_hosts`, and an SSH `config` in a directory mounted at `/ssh`:

```sh
# Publish to host loopback only (recommended: there is no proxy authentication)
docker run --rm \
  -p 127.0.0.1:3128:3128 \
  -p 127.0.0.1:1080:1080 \
  -v "$PWD/ssh:/ssh:ro" \
  ghcr.io/jpbaking/rusty-conduit-ssh:2 \
  my-bastion -F /ssh/config
```

On Linux hosts, also pass `--user "$(id -u):$(id -g)"` so the container can read your files. The **[Docker Guide](DOCKER-GUIDE.md#2-give-the-container-its-ssh-files)** shows how to prepare that directory, plus Compose examples.

### Option C: Build from source

Requires a stable Rust toolchain (<https://rustup.rs>):

```sh
git clone https://github.com/jpbaking/rusty-conduit-ssh.git
cd rusty-conduit-ssh
cargo install --path .
```

---

## 2. Start the Proxy

Pass any destination `ssh` accepts: a `~/.ssh/config` alias, a host, or `user@host`:

```sh
rusty-conduit-ssh my-bastion
```

`rusty-conduit-ssh` starts `ssh` with a dynamic (`-D`) forward, waits until the tunnel answers, and then opens its listeners on loopback (`127.0.0.1`):

- **HTTP/HTTPS proxy:** `127.0.0.1:3128`
- **SOCKS4 / SOCKS4a / SOCKS5 proxy:** `127.0.0.1:1080`
- **DNS:** hostnames are resolved on the SSH target, never locally
- **Reconnect:** if the tunnel drops, `ssh` is restarted with backoff, and the listeners stay open
- **MITM mode:** `OFF` (HTTPS `CONNECT` and SOCKS act as pure encrypted tunnels)
- **Log level:** `INFO`

Authentication must finish within `--ssh-startup-timeout` (default `30s`). Press **`Ctrl+C`** (or send `SIGTERM` on Linux/macOS) to shut down cleanly: active connections drain for up to 5 seconds, then `ssh` is stopped.

---

## 3. Connect Your Clients

### Test with `curl`

```sh
# Plain HTTP via HTTP proxy
curl -x http://127.0.0.1:3128 http://example.com/

# HTTPS via HTTP CONNECT tunnel (opaque, end-to-end encrypted)
curl -x http://127.0.0.1:3128 https://example.com/

# HTTPS via SOCKS5 (the SSH target resolves DNS)
curl --socks5-hostname 127.0.0.1:1080 https://example.com/

# HTTP via SOCKS4a (the SSH target resolves DNS)
curl --socks4a 127.0.0.1:1080 http://example.com/
```

> Use `--socks5-hostname` or `socks5h://`, not `--socks5`. With plain `--socks5`, `curl` resolves the name locally before the proxy ever sees it.

### Standard CLI environment variables

Most CLI tools (`curl`, `git`, `python`, `npm`, `cargo`, etc.) respect:

```sh
# Linux / macOS
export HTTP_PROXY="http://127.0.0.1:3128"
export HTTPS_PROXY="http://127.0.0.1:3128"
# Or route everything through SOCKS5 with remote DNS:
export ALL_PROXY="socks5h://127.0.0.1:1080"
```

```powershell
# Windows PowerShell
$env:HTTP_PROXY  = "http://127.0.0.1:3128"
$env:HTTPS_PROXY = "http://127.0.0.1:3128"
```

### Browsers (Firefox, Chrome, Edge, Safari)

- **HTTP / HTTPS Proxy:** host `127.0.0.1`, port `3128`
- **SOCKS5 Host:** host `127.0.0.1`, port `1080` (enable *"Proxy DNS when using SOCKS v5"* so names resolve on the SSH target)

---

## 4. SSH Login Basics

Keep host details in `~/.ssh/config` and pass the alias:

```sshconfig
Host my-bastion
    HostName bastion.example.com
    User deploy
    IdentityFile ~/.ssh/id_ed25519
    ProxyJump jump.example.com
```

- **`ssh-agent`, FIDO2 keys, and `ProxyJump`** work as they do with plain `ssh`.
- **Passwords and 2FA prompts** work in a terminal, because `ssh` inherits it. If you need longer than 30 seconds to answer, raise `--ssh-startup-timeout`, for example `--ssh-startup-timeout 2m`.
- **Common `ssh` options have their own flags:**

  ```sh
  rusty-conduit-ssh user@host -p 2222 -i ~/.ssh/id_ed25519 -J jump.example.com
  ```

- **Anything else goes to `ssh` verbatim after `--`:**

  ```sh
  rusty-conduit-ssh my-bastion -- -v -C -o BatchMode=yes
  ```

- **Unattended runs** (systemd, containers) have nobody to answer a prompt. Use key-based authentication and add `-- -o BatchMode=yes` so `ssh` fails fast instead of waiting.

---

## 5. Common Everyday Options

### Change ports or disable one listener

```sh
# Custom ports
rusty-conduit-ssh my-bastion --http-port 8080 --socks-port 1081

# HTTP/HTTPS only (disable SOCKS with 0)
rusty-conduit-ssh my-bastion --socks-port 0

# SOCKS4/4a/5 only (disable HTTP with 0)
rusty-conduit-ssh my-bastion --http-port 0
```

### Serve HTTP/HTTPS and SOCKS on one port

Set both ports to the same non-zero number. `rusty-conduit-ssh` peeks at the first byte of each connection to tell HTTP, SOCKS4/4a, and SOCKS5 apart:

```sh
rusty-conduit-ssh my-bastion --http-port 8888 --socks-port 8888
```

### Save traffic logs to files

```sh
rusty-conduit-ssh my-bastion \
  --http-access-log access.log \
  --socks-log socks.log
```

### Watch live traffic in your terminal

Set `--log-level DEBUG` to stream HTTP access and SOCKS connection records to `stdout`, while diagnostics (including `ssh`'s own messages) stay on `stderr`:

```sh
rusty-conduit-ssh my-bastion --log-level DEBUG
```

### Block destinations (or allowlist specific hosts)

Use `--block` or `--allow` (repeatable or comma-separated; together, `--allow` entries are exceptions to `--block`) with IPs, CIDRs, exact FQDNs, or `*.domain` wildcards:

```sh
# Block one domain and its subdomains
rusty-conduit-ssh my-bastion --block "*.ads.example"

# Allow only specific domains
rusty-conduit-ssh my-bastion --allow example.com,*.example.org
```

DNS stays on the SSH target, so FQDN rules match the names clients ask for, and IP or CIDR rules match only requests made to literal IP addresses.

### Listen on your LAN

```sh
rusty-conduit-ssh my-bastion --bind 0.0.0.0
```

> **Note:** There is **no proxy authentication**. Binding to a non-loopback address prints a security notice at startup. Restrict access with your firewall and keep `--max-connections` bounded (see [Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md)).

### Check a configuration before starting

```sh
rusty-conduit-ssh validate my-bastion --config proxy.toml
```

This checks the settings without starting `ssh` or binding any listener.

---

## 6. Share Your Connection with the SSH Target

The optional **reverse proxy** runs over the same SSH connection in the other direction: it opens a proxy port **on the SSH target**, and clients there egress through **your** machine.

```sh
# One port on the SSH target for HTTP, HTTPS, and SOCKS
rusty-conduit-ssh my-bastion --reverse-http-port 8888 --reverse-socks-port 8888
```

On the SSH target:

```sh
curl -x http://127.0.0.1:8888 https://example.com/
curl --socks5-hostname 127.0.0.1:8888 https://example.com/
```

> **Security:** anyone who can reach that port can reach whatever your machine can reach, including its loopback services and your LAN. Keep the default `--reverse-bind 127.0.0.1`, set `GatewayPorts clientspecified` on the SSH server, and consider a `--reverse-block` list. Read [Reverse proxy](USER-GUIDE-ADVANCED.md#7-reverse-proxy-ssh--r) before enabling it on a shared host.

---

## 7. Where to Go Next

- **[Advanced User Guide](USER-GUIDE-ADVANCED.md):** Every CLI flag, environment variable, and TOML key, SSH launch details, reconnect and keepalive tuning, DNS behavior, HTTPS MITM, the reverse proxy, logging, and a security checklist.
- **[MITM CA Guide](MITM-CA-GUIDE.md):** Step-by-step instructions to generate and trust your own private CA.
- **[Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md):** Memory/CPU budgets, `ulimit -n` and `somaxconn` limits, and connection/cache caps.
- **[Docker Guide](DOCKER-GUIDE.md):** Running in containers, with `docker run` and Compose examples.
