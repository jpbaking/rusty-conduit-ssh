# rusty-conduit-ssh

**A single-binary HTTP/HTTPS and SOCKS4/4a/5 forward proxy that sends all upstream traffic and DNS through an auto-reconnecting `ssh -NT4D` tunnel, with optional pure-Rust HTTPS MITM inspection.**

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

---

## Why rusty-conduit-ssh?

- **Your real `ssh`, unchanged:** It runs the system OpenSSH client, so `~/.ssh/config`, `ssh-agent`, `ProxyJump`, FIDO2 keys, and interactive password or 2FA prompts all keep working.
- **Auto-reconnect:** A supervisor restarts `ssh` with exponential backoff whenever the tunnel drops, and keepalives detect dead links.
- **Every protocol on your side:** Plain HTTP forwarding, HTTPS `CONNECT`, SOCKS4, SOCKS4a, and SOCKS5, on separate ports (`3128` / `1080`) or **auto-multiplexed on one port**.
- **No local DNS lookups for proxied hosts:** Hostnames are handed to the tunnel as names and resolved on the SSH target.
- **Opt-in HTTPS MITM:** Off by default and never auto-generates a CA. Bring a PEM or PKCS#12 CA to inspect HTTP/1.1 and HTTP/2 traffic. TLS is pure Rust (`rustls` + `ring`), with no OpenSSL.
- **Built for operators:** `CLI > env > TOML` configuration, six log levels, `text` (logfmt) or `json` (NDJSON) access logs, graceful shutdown, and connection and certificate-cache caps.

---

## Quick Start

### 1. Install

You need a stable Rust toolchain to build and an OpenSSH `ssh` client at runtime.

```sh
cargo install --path .
```

### 2. Run

```sh
# Any destination ssh accepts: a ~/.ssh/config alias, host, or user@host
rusty-conduit-ssh my-bastion
```

The defaults are `127.0.0.1:3128` (HTTP/HTTPS) and `127.0.0.1:1080` (SOCKS4/4a/5), with MITM off. Listeners open once the tunnel is ready. Authentication must finish within `--ssh-startup-timeout` (default `30s`).

### 3. Test

```sh
curl -x http://127.0.0.1:3128 http://example.com/              # Plain HTTP
curl -x http://127.0.0.1:3128 https://example.com/             # Opaque HTTPS CONNECT
curl --socks5-hostname 127.0.0.1:1080 https://example.com/     # SOCKS5 (remote DNS)
curl --socks4a 127.0.0.1:1080 http://example.com/              # SOCKS4a (remote DNS)
```

> Use `--socks5-hostname` or `socks5h://`, not `--socks5`. With plain `--socks5`, `curl` resolves the name locally before the proxy ever sees it.

### Common variations

```sh
# One port for HTTP, HTTPS, and SOCKS
rusty-conduit-ssh my-bastion --http-port 8888 --socks-port 8888

# Common ssh options have their own flags
rusty-conduit-ssh user@host -p 2222 -i ~/.ssh/id_ed25519 -J jump.example.com

# Anything else goes to ssh verbatim after --
rusty-conduit-ssh my-bastion -- -v -C -o BatchMode=yes
```

---

## Architecture

```text
 clients                     rusty-conduit-ssh                     SSH target
┌────────┐   HTTP/HTTPS   ┌─────────────────────┐
│ curl   │ ─────────────► │ listeners + mux     │
│ browser│   SOCKS4/4a/5  │ HTTP / SOCKS / MITM │
│ tools  │ ─────────────► │         │           │
└────────┘                │         ▼           │   SSH    ┌─────────┐
                          │  SOCKS5 dialer ───► ssh -D ──► │  sshd   │ ─► internet
                          │  (hostnames as-is)  │          │ (DNS)   │
                          │  ssh supervisor     │          └─────────┘
                          └─────────────────────┘
```

- The **supervisor** runs `ssh -N -T -4 -D <local-port>`, confirms the SOCKS listener answers, and restarts `ssh` when it exits.
- The **listeners** accept client connections. When both ports match, the first byte of each connection selects the protocol.
- The **dialer** opens every upstream connection through the `ssh -D` listener and passes hostnames unresolved.
- **Nothing is cached** except MITM leaf certificates, which are bounded by a TTL and an entry cap.

---

## Security notes

- v1 has **no proxy authentication**. Keep the default loopback bind, or restrict access with a firewall if you use `--bind` with another address.
- Your machine still resolves the **SSH target's own hostname**, because `ssh` must reach it before the tunnel exists.
- MITM decrypts traffic. Only use it on systems and traffic you are authorized to inspect, and protect the CA private key.

---

## Documentation

See the **[User Guide](docs/USER-GUIDE.md)** for the full CLI, environment, and TOML reference, SSH authentication tips, reconnect tuning, and HTTPS MITM setup.

---

## License

BSD-3-Clause. See [LICENSE](LICENSE).
