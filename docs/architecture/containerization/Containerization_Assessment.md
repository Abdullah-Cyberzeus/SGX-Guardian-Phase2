# SG-X Guardian — Containerization Assessment

**Status**: Draft for discussion
**Scope**: `sgx_guardian_client` daemon (and `sgx-pa-cli`), Phase 1 codebase
**Author**: Engineering
**Date**: 2026-06-29

---

## 1. Executive Summary

The SG-X Guardian is a Rust daemon whose **core purpose is host-level L3/L4
network enforcement** via `nftables`, combined with mDNS-based peer discovery,
mutual attestation, and mTLS gRPC. Those three facts dominate the
containerization story:

- **Building** the project in a container is straightforward and recommended
  (a standard multi-stage Rust image).
- **Running** the enforcement daemon in a container is possible but
  *philosophically and technically constrained*: a container's network
  namespace is isolated by design, while the product exists to manipulate
  the **host's** firewall and discover peers over **multicast on the LAN**.
  Real enforcement requires `--network host` + `CAP_NET_ADMIN` (or privileged),
  which discards most of the isolation containers provide.

There are three realistic targets, in increasing difficulty:

| Target | Difficulty | Value | Recommendation |
|--------|-----------|-------|----------------|
| **Build / CI / test in containers** | Low | High | Do this now — no code changes |
| **3-node dev/demo cohort via Compose** | Medium | High | Do this with small config + bind changes |
| **Production enforcement node in a container** | High | Mixed | Only with `hostNetwork` + `NET_ADMIN`; keep `.deb`/`.rpm` + systemd as the primary path |

The recommended end state: **containers for build, test, and the cloud-side
mock/services; native packages (`.deb`/`.rpm` + systemd) for the actual
enforcement agents.** Containerizing the agent for production is feasible only
after the code changes in §8 and with the privilege trade-offs in §7 accepted.

---

## 2. What the Application Is

Single statically-linkable Rust binary, `sgx_guardian_client`, launched as
`sgx_guardian_client <node_id>` (e.g. `nodeA`). A second workspace member,
`sgx-pa-cli`, is an offline admin tool for key generation and policy signing.

The daemon runs these concurrent services (see `README.md` and `src/main.rs`):

| Service | Module | Container-relevant behavior |
|---------|--------|------------------------------|
| P2P discovery | `p2p_discovery.rs` | mDNS responder + UDP listener on **5353–5360**; multicast |
| Key manager | `key_manager.rs` | Persists ECDSA P-256 identity key to disk |
| Attestation | `attestation_service.rs` | TCP listener on **node port + 100** (50151/2/3) |
| Policy manager | `policy_manager.rs` | Verifies signed policy, atomic load/rollback |
| Enforcement | `enforcement/` | Shells out to **`nft -f`** — modifies kernel netfilter |
| Telemetry | `metrics_server.rs` | Optional warp HTTP `/metrics` endpoint |
| Audit logger | `audit/` | Tamper-evident hash-chained log to disk |
| gRPC server | `server.rs` | mTLS `PingService` on **50051/2/3** |
| Cloud uplink | `cloud/client.rs` | Outbound-only HTTPS heartbeat (mock) |

---

## 3. Build Requirements

The build side is clean and containerizes without code changes.

**Build-time dependencies:**

- Rust stable toolchain (edition 2021).
- **`protoc`** (the `protobuf-compiler` package) — required by `tonic-build`
  in `build.rs`, which compiles `proto/*.proto` at build time. The CI workflow
  already installs this (`.github/workflows/ci.yml`).
- A C compiler (`cc`) for `ring`'s build.
- TLS uses **`rustls`** everywhere (`reqwest` is configured with
  `rustls-tls`, `default-features = false`). **No OpenSSL / system TLS libs
  are needed** — this materially simplifies the runtime image.

**Output:** `target/release/sgx_guardian_client` (the package binary is renamed
to `/usr/bin/sgx-guardian`).

**Architecture:** packaging today targets **amd64 / x86_64 only**
(`packaging/deb/DEBIAN/control` → `Architecture: amd64`; the RPM spec →
`ExclusiveArch: x86_64`). Multi-arch images would require cross-compilation or
native arm64 runners.

### 3.1 musl / static option

A fully static `x86_64-unknown-linux-musl` build would let the runtime image be
`scratch` or `distroless` — **except** the daemon shells out to the external
`nft` binary at runtime (§5), so a bare `scratch` image cannot enforce policy.
The practical floor is a slim glibc/musl image that *also ships `nftables`*.

---

## 4. Runtime Requirements

**Runtime dependencies (must exist in the image):**

- The **`nft`** binary (`nftables` package) — invoked via
  `std::process::Command` in `enforcement/executor.rs`. Missing `nft` ⇒
  enforcement fails closed.
- `ca-certificates` — for the outbound cloud uplink TLS trust store.
- glibc (`libc6 >= 2.31` per the `.deb` control) unless built against musl.

**Environment variables** (read at runtime):

| Variable | Effect |
|----------|--------|
| `SGX_RUN_MOCK_CLOUD` | `true`/`1` starts the in-process mock cloud server on `127.0.0.1:9443` (dev only) |
| `SGX_CLOUD_UPLINK_ENABLED` | `true` enables the outbound heartbeat |
| `SGX_CLOUD_ENDPOINT` | Heartbeat target URL |
| `RUST_LOG` | `tracing` env-filter level |

**CLI argument:** `<node_id>` is mandatory and selects which config the node
adopts (`nodeA`/`nodeB`/`nodeC` are the only accepted values in
`src/main.rs:313`).

---

## 5. The Three Hard Problems

These are what make containerizing the **agent** non-trivial. Each is a
consequence of the product doing real host security work.

### 5.1 nftables enforcement (the central tension)

`enforcement/executor.rs` writes a ruleset to a temp file and runs `nft -f`.
The ruleset creates `table inet sgx_guardian` with an **`input` hook at
priority 0 and `policy drop`** (default-deny), then adds allow rules.

Implications for containers:

- **Capability**: `nft` requires `CAP_NET_ADMIN`. A default container does not
  have it.
- **Namespace scope**: nftables rules apply to the **network namespace** the
  process runs in. In a bridge-networked container, the rules firewall *the
  container itself*, **not the host or the LAN** — which defeats the product's
  purpose. To enforce host traffic the container must share the host network
  namespace (`--network host` / K8s `hostNetwork: true`).
- **Self-lockout risk**: a default-drop `input` chain inside a container can cut
  off the container's own gRPC/mDNS/metrics traffic. The current ruleset hard-codes
  allowances for loopback, established/related, SSH (22), mDNS (5353), and
  gRPC (50051–50053), but anything else (including the metrics port and the
  attestation port 5015x) would be dropped.

> **Bottom line:** meaningful enforcement ⇒ host network namespace +
> `CAP_NET_ADMIN`. At that point the container is a packaging/distribution
> convenience, not an isolation boundary.

### 5.2 mDNS peer discovery

`p2p_discovery.rs` uses `libmdns` to advertise `_sgx-guardian._tcp` and binds a
UDP listener on 5353–5360. mDNS relies on **multicast (224.0.0.251:5353)**.

- Docker **bridge** networks do not forward multicast cleanly between
  containers, and never to the physical LAN.
- `--network host` makes mDNS work as designed.
- In Kubernetes, cross-node multicast generally does not work at all — discovery
  would need to be replaced (static peer list, headless Service, or a
  registry).

The code already contains a **simulation/static-peer fallback** (it reads
`config/nodeA.yaml`…`nodeC.yaml` relative to CWD and attests those peers
directly), which is the pragmatic path for a Compose-based cohort.

### 5.3 Persistent identity + hard-coded paths

Identity keys must survive restarts (they *are* the node's cryptographic
identity). The daemon reads/writes a fixed set of **absolute paths**:

| Path | Purpose | Mount type |
|------|---------|-----------|
| `/var/lib/sgx-guardian/sgx-agent/device_<id>.key` | ECDSA identity key (persistent) | **named volume / PVC** |
| `/var/lib/sgx-guardian/sgx-agent/device_<id>_cert.der` | Self-gen TLS cert | persistent (regenerable) |
| `/etc/sgx-guardian/nodeA.yaml`, `nodeB.yaml`, `nodeC.yaml` | Node configs — **all three loaded by every node** (`.expect` ⇒ panic if missing) | config mount (read-only) |
| `/etc/sgx-guardian/schemas/uep_policy_v1.yaml` | Policy schema — `.expect` ⇒ panic if missing | config mount (read-only) |
| `/etc/sgx-guardian/policies/policy.sig` | Signed policy (optional) | config mount |
| `/etc/sgx-guardian/policies/backup_policy.yaml` | Last-known-good policy | config mount |
| `/var/log/sgx-guardian/audit-<id>.log` | Tamper-evident audit log | persistent volume |

Plus several **CWD-relative paths** that will misbehave if the working
directory isn't the repo root:

- `key_manager.rs` does `fs::create_dir_all("sgx-agent")` and writes
  `sgx-agent/device_public.der` relative to CWD.
- `p2p_discovery.rs` reads `config/nodeA.yaml` … relative to CWD.
- `main.rs` falls back to a relative `logs/` directory.

These paths are not configurable today — see §8 for the recommended fix.

---

## 6. Networking Model

| Port | Proto | Bind | Purpose | Container note |
|------|-------|------|---------|----------------|
| 50051 / 50052 / 50053 | TCP | node `ip` | mTLS gRPC ping | Must bind `0.0.0.0` to be reachable cross-container |
| 50151 / 50152 / 50153 | TCP | node `ip` | Attestation listener (`port+100`) | Same — currently inherits the config `ip` |
| 5353–5360 | UDP | `0.0.0.0` | mDNS responder/listener | Needs host net or multicast-capable network |
| 8443 | — | advertised | mDNS service advert (informational) | — |
| configurable | TCP | `metrics.bind` | Prometheus `/metrics` (optional) | Expose if scraping |
| 9443 | TCP | `127.0.0.1` | Mock cloud (dev only) | Loopback-only |

**Critical config issue for containers:** the shipped configs set
`ip: "127.0.0.1"` (`config/nodeA.yaml`). Services bind to that address, so peers
in *other* containers cannot connect. For any multi-container topology the
configs must use `0.0.0.0` for binds and resolvable hostnames/service names for
peer targets.

---

## 7. Privilege & Security Trade-offs

The Phase 1 systemd unit (`packaging/deb/systemd/sgx-guardian.service`) is
**heavily hardened** and notably:

- `CapabilityBoundingSet=` and `AmbientCapabilities=` are **empty** (no caps),
- `IPAddressDeny=any`, `IPAddressAllow=localhost`,
- `ProtectSystem=strict`, `ProtectKernelModules=true`, etc.

That profile **contradicts** what the running daemon actually needs
(`CAP_NET_ADMIN` for `nft`, outbound LAN/cloud networking). This is worth
reconciling regardless of containerization, but it matters here because the
container security posture has to make the same decision explicitly:

- **Build image**: no special privileges.
- **Agent image (real enforcement)**: `--network host`, `--cap-add NET_ADMIN`
  (or `privileged` if `nft` needs more), writable `/var/lib` + `/var/log`
  volumes, read-only config mount. Run as non-root *user* where possible, but
  `NET_ADMIN` is the floor.
- The isolation you give up (shared host netns) is the explicit cost of doing
  host firewall enforcement from a container.

---

## 8. Recommended Code Changes (to make the agent container-friendly)

None are required to **build** in a container. The following make the **agent**
deployable cleanly and remove panics/relative-path foot-guns:

1. **Make paths configurable.** Introduce `SGX_CONFIG_DIR`, `SGX_DATA_DIR`,
   `SGX_LOG_DIR` (defaulting to the current `/etc`, `/var/lib`, `/var/log`
   locations). Removes every hard-coded absolute path in `main.rs`.
2. **Fix CWD-relative writes.** `key_manager.rs` (`sgx-agent/`,
   `device_public.der`), `p2p_discovery.rs` (`config/*.yaml`), and the `logs/`
   fallback should derive from the dirs above, not CWD.
3. **Decouple the node topology.** Today every node loads **all three** configs
   and matches its own ID by string (`nodeA`/`nodeB`/`nodeC` only). Replace with
   "load my own config + a peers list," which also removes the `.expect`
   panics when a sibling config is absent.
4. **Bind to `0.0.0.0`, target by hostname.** Stop binding services to the
   config `ip` (which is `127.0.0.1`); bind listeners to `0.0.0.0` and resolve
   peers by DNS/service name.
5. **Make enforcement optional / dry-run.** Add a mode (env or flag) to skip the
   `nft` apply or log the ruleset without applying it, so the daemon can run in
   CI, bridge-networked dev, or non-enforcing roles without `NET_ADMIN`.
6. **Replace `.expect` with graceful degradation** on missing policy/schema/
   config files so a misconfigured mount doesn't crash-loop the container.

Items 1–2 and 5 are the highest leverage for containerization.

---

## 9. Reference Artifacts

### 9.1 Multi-stage Dockerfile (build + slim runtime)

```dockerfile
# ---- Builder ----
FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --bin sgx_guardian_client

# ---- Runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/sgx_guardian_client /usr/bin/sgx-guardian
# Config and state are provided via mounts (see compose / k8s)
ENTRYPOINT ["/usr/bin/sgx-guardian"]
CMD ["nodeA"]
```

> Note: without the §8 code changes the container expects configs at
> `/etc/sgx-guardian/...` and writes state to `/var/lib/sgx-guardian` and
> `/var/log/sgx-guardian` — mount those paths accordingly.

### 9.2 docker-compose (3-node dev cohort)

```yaml
# Enforcement is disabled / dry-run in dev unless NET_ADMIN + host net are added.
# Requires the §8 changes (configurable paths, 0.0.0.0 binds, dry-run enforce)
# to run cleanly on a bridge network. Otherwise use network_mode: host per node.
services:
  nodeA:
    build: .
    command: ["nodeA"]
    cap_add: ["NET_ADMIN"]          # only if exercising real enforcement
    environment:
      RUST_LOG: info
    volumes:
      - ./config:/etc/sgx-guardian:ro
      - nodeA-data:/var/lib/sgx-guardian
      - nodeA-logs:/var/log/sgx-guardian
  nodeB:
    build: .
    command: ["nodeB"]
    volumes:
      - ./config:/etc/sgx-guardian:ro
      - nodeB-data:/var/lib/sgx-guardian
      - nodeB-logs:/var/log/sgx-guardian
  nodeC:
    build: .
    command: ["nodeC"]
    volumes:
      - ./config:/etc/sgx-guardian:ro
      - nodeC-data:/var/lib/sgx-guardian
      - nodeC-logs:/var/log/sgx-guardian
volumes:
  nodeA-data: {}
  nodeA-logs: {}
  nodeB-data: {}
  nodeB-logs: {}
  nodeC-data: {}
  nodeC-logs: {}
```

For working **mDNS** between the three, either put them on `network_mode: host`
(loses Compose DNS, requires distinct ports per node on one host) or rely on the
static-peer simulation fallback already in `p2p_discovery.rs`.

### 9.3 Kubernetes (production enforcement)

If host enforcement is truly required, the agent maps to a **DaemonSet** (one
per node) with:

- `hostNetwork: true` (for real host firewalling + any chance at LAN discovery),
- `securityContext.capabilities.add: ["NET_ADMIN"]`,
- a **PersistentVolumeClaim or hostPath** for the identity key per node,
- a **ConfigMap** for configs/policy and a **Secret** for any signing material,
- mDNS **replaced** by a static peer list / headless Service (multicast won't
  cross nodes).

This is the heaviest option and only justified if the operational story
specifically calls for K8s-managed agents.

---

## 10. Recommendation & Phasing

1. **Now (no code changes):** add the build-stage Dockerfile and use it in CI
   for reproducible builds and artifact extraction. Containerize the **cloud
   mock / future cloud services** freely — they have none of the constraints
   above.
2. **Next (small changes — §8 items 1, 2, 5):** ship a Compose-based 3-node
   dev/demo cohort. This is high-value for onboarding and demos and removes the
   "works on my LAN" fragility.
3. **Later (full §8 + privilege acceptance):** offer a container image for
   agents in container-first environments, deployed with `hostNetwork` +
   `NET_ADMIN`. Keep **`.deb`/`.rpm` + systemd as the supported production path**
   for bare-metal/VM edge nodes, since that aligns with the product's host-level
   enforcement model and the existing hardening work.

**Decision needed from stakeholders:** is the goal (a) reproducible builds &
easier dev/test, (b) container-packaged distribution, or (c) replacing the
native-package deployment model entirely? The answer determines whether we stop
at phase 1–2 or invest in the phase-3 code changes and the privilege/isolation
trade-offs they force.

---

## 11. Open Questions

- Target orchestrator(s)? (Compose only, Kubernetes, Nomad?)
- Is real `nftables` enforcement required *inside* containers, or only on
  native nodes — with containers used for build/test/cloud roles?
- Multi-arch (arm64) needed for edge hardware, or amd64-only as today?
- How should per-node identity keys be provisioned and backed up in a
  container/orchestrated world (volume vs. external secret store)?
- Should discovery remain mDNS, or move to a static/registry model that works
  across container networks and K8s?
```
