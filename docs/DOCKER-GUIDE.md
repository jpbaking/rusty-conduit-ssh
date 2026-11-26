# Docker Guide

This guide covers running `rusty-conduit-ssh` in a container with `docker run` and Docker Compose: the published images, giving the container its SSH files, configuration, the reverse proxy, logs, HTTPS MITM, resource limits, health checks, and hardening.

- Back to [README](../README.md) · [Basic User Guide](USER-GUIDE-BASIC.md) · [Advanced User Guide](USER-GUIDE-ADVANCED.md) · [Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md)

The examples were tested with Docker Engine 29.9 and Docker Compose 5.7 on Docker Desktop (Linux arm64), against an OpenSSH 10.2 server in a container. The file-ownership notes for Linux hosts were checked with files owned by another UID.

---

## 1. Images

| | |
| :--- | :--- |
| **Image** | `ghcr.io/jpbaking/rusty-conduit-ssh` |
| **Tags** | `X.Y.Z`, `X.Y`, `X`, and `latest` (the newest stable release). A pre-release gets only its full version tag. |
| **Platforms** | `linux/amd64`, `linux/arm64` |
| **Base** | Ubuntu 26.04 LTS with `ca-certificates` and `openssh-client` |
| **User** | `rusty-conduit-ssh`, UID and GID `10001`, set as a numeric `USER 10001:10001` so orchestrators can verify it is not root (Kubernetes `runAsNonRoot`). Nothing in the image runs as root. |
| **Entrypoint** | `/usr/local/bin/rusty-conduit-ssh`. Anything after the image name is passed to it as arguments, starting with the SSH target. |
| **Ports** | `3128` (HTTP/HTTPS) and `1080` (SOCKS4/4a/5) |
| **Environment** | `RUSTY_CONDUIT_SSH_BIND=0.0.0.0`, so the listeners accept connections forwarded by Docker, and `MALLOC_ARENA_MAX=2`, which keeps memory low on hosts with many CPUs |

Pin a major tag such as `:1` so you get fixes and features within that major version, but not breaking changes. To build the image yourself from a clone of the repository:

```sh
docker build -t rusty-conduit-ssh .
```

---

## 2. Give the container its SSH files

A container has nobody to answer a password or 2FA prompt, and no access to your agent by default. Give it a directory with a dedicated key, the server's host key, and an SSH `config`, mounted read-only at `/ssh`:

```sh
mkdir -p ssh && chmod 700 ssh
ssh-keygen -t ed25519 -N '' -C rusty-conduit-ssh -f ssh/id_ed25519   # or copy an existing key
ssh-keyscan -t ed25519 bastion.example.com > ssh/known_hosts          # then compare the fingerprint
cat > ssh/config <<'EOF'
Host my-bastion
    HostName bastion.example.com
    User deploy
    IdentityFile /ssh/id_ed25519
    UserKnownHostsFile /ssh/known_hosts
    BatchMode yes
    UpdateHostKeys no
EOF
chmod 600 ssh/*
```

Add `ssh/id_ed25519.pub` to `~/.ssh/authorized_keys` for that user on the SSH server, and check the scanned key with `ssh-keygen -lf ssh/known_hosts` against the server's real fingerprint before you rely on it. Then start the proxy with `-F /ssh/config` ([section 3](#3-run-with-docker-run)).

- **Absolute paths** in the `config` work whichever UID the container runs as; `~` only resolves for the image's own user.
- **`BatchMode yes`** makes `ssh` fail fast instead of waiting for a prompt, and **`UpdateHostKeys no`** stops it trying to add more host keys to the read-only `known_hosts`.
- **`StrictHostKeyChecking=accept-new`** connects without a `known_hosts` entry, but a read-only mount cannot save the key, so every restart trusts whatever key the server presents. Prefer the scanned and checked `known_hosts`.

### File ownership

`ssh` refuses a key or `config` it cannot read, and the image does not fix ownership or modes at startup: that would need root, and the image never runs as root. Bind mounts keep the host's owner, so match the container's UID to the files:

| Host | Do this |
| :--- | :--- |
| **Linux (recommended)** | Run the container as your own UID: `--user "$(id -u):$(id -g)"` (Compose: `user: "1000:1000"`, with your numbers). The files stay yours, at mode `600`, and no `sudo` is needed. The process is still not root. |
| **Linux, image user** | Keep UID `10001` and hand it the files: `sudo chown -R 10001:10001 ssh`. |
| **Docker Desktop** (macOS, Windows) | Nothing: Docker Desktop maps file ownership to the container user. |

When ownership is wrong, `ssh` fails with `Can't open user config file /ssh/config: Permission denied` or `Load key "/ssh/id_ed25519": Permission denied`.

### `ssh-agent` instead of a key file

- **Docker Desktop:** the host agent is at `/run/host-services/ssh-auth.sock`, owned by root with mode `660`. Add `--group-add 0` so the container user can use it:

  ```sh
  -v /run/host-services/ssh-auth.sock:/run/host-services/ssh-auth.sock \
  -e SSH_AUTH_SOCK=/run/host-services/ssh-auth.sock --group-add 0
  ```

- **Linux:** an agent socket belongs to your user with mode `600`. Run as your own UID (above) and mount it the same way: `-v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent`.

Leave `IdentityFile` out of the `config` when you use the agent.

---

## 3. Run with `docker run`

```sh
docker run -d --name rusty-conduit-ssh --restart unless-stopped \
  -p 127.0.0.1:3128:3128 \
  -p 127.0.0.1:1080:1080 \
  -v "$PWD/ssh:/ssh:ro" \
  ghcr.io/jpbaking/rusty-conduit-ssh:1 \
  my-bastion -F /ssh/config
```

- **The listeners open once the tunnel is ready.** Watch for `SSH tunnel ready` in `docker logs rusty-conduit-ssh`. If the server restarts or the link drops, the tunnel reconnects with backoff while the listeners stay open.
- **Publish on `127.0.0.1`.** Inside the container the proxy listens on `0.0.0.0`, so the `SECURITY NOTICE` at startup is expected. What decides who can reach it is the host side of `-p`: `-p 3128:3128` without an address exposes the proxy to your network, and v1 has **no proxy authentication**.
- **Flags and environment variables** work as usual: put flags after the image name, or pass `-e RUSTY_CONDUIT_SSH_*` variables. Other `ssh` options can go in `/ssh/config` or after `--`.
- **On a Linux host**, add `--user "$(id -u):$(id -g)"` so the container can read your files ([section 2](#file-ownership)).
- **Memory:** the image sets `MALLOC_ARENA_MAX=2`, which keeps memory low on hosts with many CPUs. Leave it in place unless you measure otherwise; see [Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md#memory-on-many-core-linux-malloc_arena_max).
- **The SSH server must be reachable from the container.** A server on the Docker host is `host.docker.internal` (on Linux, add `--add-host host.docker.internal:host-gateway`); `127.0.0.1` is the container itself.
- **Stop:** `docker stop rusty-conduit-ssh` sends `SIGTERM`. Connections drain for up to 5 seconds, then `ssh` is stopped; the whole shutdown fits well inside Docker's default 10-second grace period.

---

## 4. Configuration file

Mount a directory read-only and point `--config` at the file inside it. The SSH target can live in the file (`ssh.target`), so the command line stays short:

```sh
docker run -d --name rusty-conduit-ssh \
  -p 127.0.0.1:3128:3128 -p 127.0.0.1:1080:1080 \
  -v "$PWD/ssh:/ssh:ro" \
  -v "$PWD/conf:/etc/rusty-conduit-ssh:ro" \
  ghcr.io/jpbaking/rusty-conduit-ssh:1 --config /etc/rusty-conduit-ssh/config.toml
```

Check it before starting; `validate` does not start `ssh`:

```sh
docker run --rm -v "$PWD/conf:/etc/rusty-conduit-ssh:ro" \
  ghcr.io/jpbaking/rusty-conduit-ssh:1 validate --config /etc/rusty-conduit-ssh/config.toml
# config OK: /etc/rusty-conduit-ssh/config.toml target=my-bastion
```

`validate` checks the settings, not the files they name: an unreadable key or CA still passes, and fails only when the proxy starts. See the [Advanced User Guide](USER-GUIDE-ADVANCED.md) for every key; `ssh.config` is the file form of `-F`.

---

## 5. The reverse proxy in a container

The reverse proxy (`--reverse-http-port`, `--reverse-socks-port`) works the same in a container: the port opens on the SSH target, and its traffic egresses **from the container**. So:

- Reverse destinations resolve through the container's DNS and reach what the container's network can reach.
- `127.0.0.1` in `--reverse-block` or `--reverse-allow` means the container's loopback, not the Docker host's. Keep blocking `127.0.0.0/8` and your LAN ranges if the container can reach them.
- Nothing extra is published: the reverse proxy's ports are on the SSH target, not on the Docker host.

---

## 6. Logs

Diagnostics, and `ssh`'s own messages, go to `stderr`, which `docker logs` shows. For HTTP access and SOCKS connection records, choose one of these:

**On `stdout`.** At `--log-level DEBUG`, records are also written to `stdout`, so Docker's log driver collects them. Diagnostics stay on `stderr`, so you can split the two:

```sh
docker logs rusty-conduit-ssh 2>/dev/null   # access and SOCKS records only
```

**In files.** Mount a volume at the image's log directory and point the log flags at it:

```sh
docker run -d --name rusty-conduit-ssh \
  -p 127.0.0.1:3128:3128 -p 127.0.0.1:1080:1080 \
  -v "$PWD/ssh:/ssh:ro" \
  -v rusty-conduit-ssh-logs:/var/log/rusty-conduit-ssh \
  ghcr.io/jpbaking/rusty-conduit-ssh:1 my-bastion \
  --http-access-log /var/log/rusty-conduit-ssh/access.log \
  --socks-log /var/log/rusty-conduit-ssh/socks.log \
  -F /ssh/config

docker exec rusty-conduit-ssh tail -f /var/log/rusty-conduit-ssh/access.log
```

- The image's `/var/log/rusty-conduit-ssh` belongs to the container user (UID `10001`), so a new named volume mounted there is writable as is. To keep the files in a host directory instead (needed when you run with `--user` as your own UID), mount it there (`-v "$PWD/logs:/var/log/rusty-conduit-ssh"`) and make sure the container's UID can write it ([section 2](#file-ownership)).
- Records reach the files as soon as the proxy has no more queued, so `tail -f` follows them live; `docker stop` flushes the rest at shutdown.

---

## 7. HTTPS MITM

MITM needs a CA you create yourself; see the [MITM CA Guide](MITM-CA-GUIDE.md). Mount the CA files read-only, make sure the container's UID can read the key (on Linux, run as your own UID or `sudo chown 10001 ca/ca.key`, keeping mode `600`; see [section 2](#file-ownership)), and pass the paths inside the container:

```sh
docker run -d --name rusty-conduit-ssh \
  -p 127.0.0.1:3128:3128 -p 127.0.0.1:1080:1080 \
  -v "$PWD/ssh:/ssh:ro" \
  -v "$PWD/ca:/etc/rusty-conduit-ssh/ca:ro" \
  ghcr.io/jpbaking/rusty-conduit-ssh:1 my-bastion \
  --mitm-ca-cert /etc/rusty-conduit-ssh/ca/ca.pem \
  --mitm-ca-key /etc/rusty-conduit-ssh/ca/ca.key \
  -F /ssh/config
```

- An unreadable key stops the proxy at startup with `FATAL MITM setup failed: failed to read MITM CA file ...: Permission denied`. The CA is checked before SSH authentication.
- For an encrypted key or PKCS#12 bundle, pass the passphrase as a file (`--mitm-ca-passphrase-file`) mounted the same way, or as a Compose secret. `docker inspect` shows command-line arguments and environment variables to anyone with access to the Docker daemon.

---

## 8. Resource limits, health checks, and hardening

| Limit | Inside the container | What to do |
| :--- | :--- | :--- |
| Open files (`ulimit -n`) | Usually high: `1048576` on Docker Desktop. The proxy raises its soft limit toward the hard limit at startup, before `ssh` starts, so `ssh` inherits it. | If startup logs `NOTICE: open-file limit is ...`, add `--ulimit nofile=65536`, or lower the caps. It needs `2 × connections + 64`. |
| Listen backlog (`somaxconn`) | The container has its own network namespace; the default is `4096` on Linux 5.4 and later. | On older kernels, add `--sysctl net.core.somaxconn=4096`. With `--network host`, the host's value applies and `--sysctl` is not allowed. |
| Memory | The image sets `MALLOC_ARENA_MAX=2`, so memory stays low on any CPU count; `ssh` adds ~8–10 MB plus ~33 KB per open channel. | Add `--memory` as a ceiling if you want one. |
| CPUs | One worker thread per CPU the container may use; `ssh` uses one core for all encryption. | `--cpus=2` also reduces idle memory. |

**Health check.** The image has no `curl` or `nc`, but it has `bash`, which can open a TCP connection to the listener:

```sh
--health-cmd 'bash -c "exec 3<>/dev/tcp/127.0.0.1/3128"' \
--health-interval 30s --health-timeout 3s --health-retries 3 --health-start-period 30s
```

The listeners open only after the first tunnel is ready, so the check turns healthy once the SSH login has worked. Later drops do not close the listeners, so the check stays healthy while the tunnel reconnects; watch the logs for `SSH tunnel down` to alert on that. The start period covers `--ssh-startup-timeout` (default `30s`).

**Hardening.** The proxy writes nothing except the log files you configure, and needs no Linux capabilities. `--read-only --cap-drop ALL --security-opt no-new-privileges:true` were tested with every example in this guide. Keep the published ports on `127.0.0.1`, or behind a firewall, until proxy authentication exists.

---

## 9. Docker Compose

Save an example as `compose.yaml` next to the `ssh/` directory from [section 2](#2-give-the-container-its-ssh-files), then:

```sh
docker compose up -d
docker compose logs -f
docker compose down
```

### 9.1 Forward proxy over SSH

```yaml
services:
  rusty-conduit-ssh:
    image: ghcr.io/jpbaking/rusty-conduit-ssh:1
    restart: unless-stopped
    user: "1000:1000"   # Linux: your $(id -u):$(id -g); remove on Docker Desktop
    command: ["my-bastion", "-F", "/ssh/config"]
    ports:
      - "127.0.0.1:3128:3128"
      - "127.0.0.1:1080:1080"
    volumes:
      - ./ssh:/ssh:ro
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/3128"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 30s
```

Check the target and flags with the same mounts before starting:

```sh
docker compose run --rm --no-deps rusty-conduit-ssh validate my-bastion
```

### 9.2 Settings in a config file

Keep the target, the SSH config path, and the reverse proxy in `conf/config.toml`:

```toml
http_port = 3128
socks_port = 1080

[ssh]
target = "my-bastion"
config = "/ssh/config"

[reverse]
http_port = 8888
socks_port = 8888
block = ["127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

```yaml
services:
  rusty-conduit-ssh:
    image: ghcr.io/jpbaking/rusty-conduit-ssh:1
    restart: unless-stopped
    command: ["--config", "/etc/rusty-conduit-ssh/config.toml"]
    ports:
      - "127.0.0.1:3128:3128"
      - "127.0.0.1:1080:1080"
    volumes:
      - ./ssh:/ssh:ro
      - ./conf:/etc/rusty-conduit-ssh:ro
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
```

### 9.3 A proxy for other containers

Services on the same Compose network reach the proxy by its service name, so their traffic leaves through the SSH target. This proxy publishes no ports, so nothing outside the network can use it:

```yaml
services:
  proxy:
    image: ghcr.io/jpbaking/rusty-conduit-ssh:1
    restart: unless-stopped
    command: ["my-bastion", "-F", "/ssh/config"]
    volumes:
      - ./ssh:/ssh:ro

  app:
    image: curlimages/curl:latest
    command: ["-sS", "-o", "/dev/null", "-w", "%{http_code}\n", "https://example.com/"]
    environment:
      HTTP_PROXY: http://proxy:3128
      HTTPS_PROXY: http://proxy:3128
      NO_PROXY: localhost,127.0.0.1
    depends_on:
      - proxy
```

The `app` request fails if it starts before the tunnel is ready; in real services, rely on their retries or add a health check to `proxy` and `condition: service_healthy` to `depends_on`. Tools differ in which proxy variables they read: `curl`, for example, ignores `HTTP_PROXY` and reads only the lowercase `http_proxy` for `http://` URLs. For SOCKS, use `ALL_PROXY: socks5h://proxy:1080`, so names resolve on the SSH target.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `Can't open user config file /ssh/config: Permission denied` | The container's UID cannot read the files (a Linux host keeps their owner) | Run as your own UID with `--user "$(id -u):$(id -g)"`, or `sudo chown -R 10001:10001 ssh` ([section 2](#file-ownership)) |
| `ssh: Could not resolve hostname my-bastion: Name or service not known` | `ssh` did not read the config that defines the alias, for example because `-F /ssh/config` is missing | Pass `-F /ssh/config` (or set `ssh.config`) |
| `Load key ".../id_ed25519": Permission denied` followed by `Permission denied (publickey)` | The key file is not readable by the container's UID | Same fix as above; keep the key at mode `600` |
| `Host key verification failed.` | No matching entry in `known_hosts` | Add the server's key with `ssh-keyscan`, then check its fingerprint |
| `hostfile_replace_entries failed ...: Read-only file system` | `ssh` tried to record extra host keys in the read-only mount | Harmless; add `UpdateHostKeys no` to the `config` |
| `Error connecting to agent: Permission denied` | The Docker Desktop agent socket is root-owned, mode `660` | Add `--group-add 0` ([section 2](#2-give-the-container-its-ssh-files)) |
| `SSH tunnel down: ... reconnecting` after startup | The SSH server or the link went away | Nothing; the tunnel reconnects with backoff and the listeners stay open |
| `FATAL MITM setup failed: failed to read MITM CA file ...: Permission denied` | The CA key is not readable by the container's UID | Run as your own UID, or `sudo chown 10001` the key on the host |
| Clients on other machines cannot connect | The ports are published on `127.0.0.1` | Publish on a LAN address or `0.0.0.0` only behind a firewall: v1 has no proxy authentication |
| Memory is much higher than the sizing guide says | `MALLOC_ARENA_MAX` was overridden or unset, so glibc allocates a memory arena per worker thread | Keep the image default, `MALLOC_ARENA_MAX=2` ([section 8](#8-resource-limits-health-checks-and-hardening)) |
