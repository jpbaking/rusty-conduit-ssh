# Performance, Footprint & Sizing Guide

This guide documents `rusty-conduit-ssh`'s memory, CPU, file-descriptor, and listen-backlog characteristics, including the `ssh` process it supervises, along with sizing rules of thumb and how its resource caps behave under load.

- Back to [README](../README.md) · [Basic User Guide](USER-GUIDE-BASIC.md) · [Advanced User Guide](USER-GUIDE-ADVANCED.md) · [Docker Guide](DOCKER-GUIDE.md)

---

## 1. Zero-Caching Architecture

`rusty-conduit-ssh` is a streaming pass-through proxy. Keeping memory predictable starts with what it **never** retains:

| Component | Cached / Buffered? |
| :--- | :--- |
| HTTP responses (plain or decrypted MITM) | **Never.** Every request reaches the origin, regardless of `Cache-Control` / `Expires`. |
| DNS lookups | **Never, and never local on the forward path.** Hostnames go through the tunnel unresolved and are resolved on the SSH target. The reverse proxy resolves through your machine's resolver on every dial. |
| Upstream connections | **Never pooled across clients.** Each client connection gets its own channel in the SSH session (forward) or its own direct connection (reverse). |
| Request / response bodies | **Never buffered in full.** Streamed frame by frame. |
| MITM leaf certificates | **Yes — the only cache.** Bounded by `--mitm-cert-ttl` (default `1h`) and `--mitm-cert-cache-max-entries` (default `10240`). The forward and reverse proxies each keep their own cache. |

---

## 2. Memory & CPU Footprint

Two processes run: `rusty-conduit-ssh` itself and the OpenSSH `ssh` client it supervises. The **measured** figures come from the release container image (Linux arm64) with 1,000 idle `CONNECT` tunnels through an SSH server, after 1 KiB of traffic each (process RSS; kernel socket buffers excluded), with `MALLOC_ARENA_MAX=2` set ([see below](#memory-on-many-core-linux-malloc_arena_max)). **Estimated** figures were not benchmarked directly; validate them under your own traffic profile.

| Workload / Component | RAM | CPU | Basis |
| :--- | :--- | :--- | :--- |
| Idle `rusty-conduit-ssh` | ~7 MB RSS | ~0% (event-driven) | Measured (`7.0`–`7.2 MB` on 2 and 18 CPUs) |
| Idle `ssh` client | ~8–10 MB RSS | ~0%, plus keepalive probes every `--ssh-server-alive-interval` | Measured |
| Forward tunnel (`CONNECT` or SOCKS), in `rusty-conduit-ssh` | ~25 KB / connection | Low (streaming byte copy) | Measured for `CONNECT` |
| Forward tunnel, in `ssh` | ~33 KB / channel | All forward traffic is encrypted by this one process | Measured |
| Reverse tunnel | About the same as a forward tunnel in `rusty-conduit-ssh`, plus one channel in `ssh` | Low | Estimated |
| HTTPS MITM tunnel | ~50–150 KB / tunnel | Moderate–High (**2× TLS** via `ring` assembly AES-GCM/ChaCha20 + HTTP/1.1 or HTTP/2 framing) | Estimated |
| Cached MITM leaf certificate | ~3–5 KB / host (~30–50 MB at default `10240` cap, per direction) | ~0.2–0.5 ms per cache miss (ECDSA P-256 via `rcgen`, offloaded to blocking pool with single-flight dedup) | Estimated |

- **One SSH connection carries every forward tunnel.** Forward throughput is bounded by that single TCP connection and by the `ssh` process, which encrypts all of it on one CPU core. Many clients share it fairly, but one lossy link slows all of them.
- The Tokio async runtime spawns one worker thread per CPU core.
- Throughput is typically network-bound for opaque tunnels and plain HTTP, and CPU-bound (double TLS) in MITM mode.

### Memory on many-core Linux (`MALLOC_ARENA_MAX`)

On Linux, the prebuilt binaries and the container image use glibc's `malloc`, which gives each worker thread its own memory arena. On a host with many CPUs, that multiplies idle memory, and it can multiply per-connection memory too. Measured with the container image (Linux arm64):

| Setting | Idle `rusty-conduit-ssh` RSS |
| :--- | :--- |
| glibc defaults, 2 CPUs | ~9 MB |
| glibc defaults, 18 CPUs | ~42 MB |
| `MALLOC_ARENA_MAX=2`, 2 or 18 CPUs | ~7 MB |

The container image sets `MALLOC_ARENA_MAX=2`. For the prebuilt Linux binaries, set it in the environment (for example `Environment=MALLOC_ARENA_MAX=2` in a `systemd` unit) to get the low figures on any CPU count. With the same engine, `rusty-conduit` and `rusty-conduit-switch` measured 110–230 KB per open tunnel without the setting and 26–27 KB with it; in a bulk-transfer test (64 parallel tunnels, 2.2–2.7 GB/s), throughput was the same either way, within run-to-run noise. Fewer worker threads also lower the idle figure: the runtime starts one per CPU it may use, so a Docker `--cpus` limit or `TOKIO_WORKER_THREADS=<n>` reduces them. The `ssh` client's own memory does not depend on this setting.

---

## 3. File Descriptors (`ulimit -n`)

Every concurrent proxied connection uses **2 file descriptors** in `rusty-conduit-ssh`: the client socket, and either the connection to the local `ssh -D` port (forward) or the direct connection to the destination (reverse). `ssh` holds about one more per open channel.

Size your process file-descriptor limit using:

```text
ulimit -n  >=  (2 × connections) + 64
```

where `connections` is the sum of the active forward (`--max-connections`) and reverse (`--reverse-max-connections`) caps (`8256` for the default forward-only cap of `4096`; unchecked if an active cap is `0`). On Unix, `rusty-conduit-ssh` automatically raises its soft open-file limit (`RLIMIT_NOFILE`) toward the hard limit at startup whenever the current soft limit is below that threshold. The raise happens before `ssh` starts, so `ssh` inherits the same limit. If the limit still cannot hold the configured cap, it logs:

```text
NOTICE: open-file limit is <limit> but <flag> <N> needs at least <needed>; only about <M> concurrent connections will fit. Raise `ulimit -n` (LimitNOFILE= under systemd) or lower <flag>
```

Many Linux shells default to `1024` (~480 concurrent connections), so if the hard limit is also too low, either raise `ulimit -n` or lower the caps:

```sh
# Option A: raise FD limit to match default cap
ulimit -n 8256 && rusty-conduit-ssh my-bastion

# Option B: stay comfortably inside a 1024 FD limit
rusty-conduit-ssh my-bastion --max-connections 480
```

Under `systemd`, set `LimitNOFILE=8256` (or higher) in your service unit.

---

## 4. Listen Backlog (`somaxconn`)

Each listener (forward and reverse proxy, HTTP and SOCKS) asks the kernel for a listen backlog of `4096`: the queue of connections that have finished the TCP handshake but that `rusty-conduit-ssh` has not accepted yet. The kernel caps the request at its own limit:

| OS | Limit | Default |
| :--- | :--- | :--- |
| Linux | `net.core.somaxconn` | `4096` (kernel 5.4 and later; `128` before) |
| macOS | `kern.ipc.somaxconn` | `128` |
| Windows | set by the OS | — |

The queue only matters during connection bursts, such as many clients reconnecting at once after a network drop. When it is full, the kernel drops the new connection attempts and clients retry about a second later, which shows up as slow connects rather than errors. If you expect bursts larger than the limit, check it and raise it to `4096`:

```sh
# Linux (persist the setting in /etc/sysctl.d/)
sysctl net.core.somaxconn
sudo sysctl -w net.core.somaxconn=4096

# macOS (resets at reboot)
sysctl kern.ipc.somaxconn
sudo sysctl -w kern.ipc.somaxconn=4096
```

A value above `4096` has no effect, because `rusty-conduit-ssh` requests `4096`. The backlog is fixed when a listener opens, so restart `rusty-conduit-ssh` after changing the limit. On Linux, a container has its own `net.core.somaxconn` (normally `4096`) unless it uses the host network; set it with `docker run --sysctl net.core.somaxconn=4096`. On the SSH target, the reverse proxy's public port is opened by `sshd`, so that host's own limit applies there.

---

## 5. Concurrency & Sizing Rules of Thumb

Assuming a typical active browser holds roughly **10 concurrent TCP connections** (varies widely with HTTP/2 multiplexing and workload), and counting both processes (~58 KB per open forward tunnel, with `MALLOC_ARENA_MAX=2`):

| Deployment Profile | `--max-connections` | Recommended `ulimit -n` | Approx. RAM (Opaque, both processes) | Approx. Active Users |
| :--- | :--- | :--- | :--- | :--- |
| Personal / single device | `256` | `1024` | ~30 MB | 1–25 |
| Home / small team | `1024` | `2112` | ~75 MB | 25–100 |
| Default | `4096` | `8256` | ~250 MB | 100–400 |

- Add the reverse proxy's connections to the count when it is enabled; it has its own cap, `--reverse-max-connections`.
- At the larger sizes, the single SSH connection and the one CPU core `ssh` uses are usually the limit before memory is. Measure throughput over your actual link.
- MITM adds TLS work on your machine and the cached certificates (per direction); budget the MITM figures from [section 2](#2-memory--cpu-footprint).
- On many-core Linux with glibc defaults, budget more for `rusty-conduit-ssh`, or set `MALLOC_ARENA_MAX=2`.

---

## 6. How the Resource Caps Behave

### `--max-connections` (default `4096`, `0` = unlimited) and `--reverse-max-connections`
- Each direction has its own cap, so one side cannot exhaust the other. `--reverse-max-connections` defaults to the same value as `--max-connections`. Within one direction, HTTP and SOCKS share the cap.
- When a cap is reached, new incoming connections are **accepted and closed immediately** (no reply, no queue, no slowloris buildup) and logged at `DEBUG`.
- Existing connections are unaffected, and a slot is freed immediately when any connection or tunnel ends.

### `--mitm-cert-cache-max-entries` (default `10240`, `0` = unlimited)
- Strictly bounds the number of in-memory MITM leaf certificates, separately for the forward and reverse proxies.
- When a new hostname is signed at the cap:
  1. Already-expired entries are reaped first so live certificates are not evicted unnecessarily.
  2. If the cache is still at the cap, the **oldest** entries (closest to expiry) are evicted and logged at `VERBOSE`.
- Cache hits are lock-free and unaffected; an evicted host is simply re-signed on its next connection.

> **Security note:** Setting either cap to `0` disables the upper bound. Avoid `0` on untrusted networks where a client could exhaust file descriptors or flood random SNI hostnames.
