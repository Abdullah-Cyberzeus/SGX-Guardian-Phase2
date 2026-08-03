# Containerization — Complete Development Plan
**Scope: DevOps / Containerization | Deliverable: Container Image Workflow | Test tag: CTR-series (CTR-001 – CTR-010)**
**Repo:** `AsadAli-CyberZeus/SGX` (main) | **Grounded on:** fresh indexed pull, 2026-07-06 | **Supersedes:** `Containerization_Assessment.md` (2026-06-29, written against Phase 1 codebase)

> Current repo layout note:
> The laptop-only cohort assets now live under `optional/container-cohort/`.
> Removing that single folder disables the Docker cohort without touching board/native runtime files.

## Operator Quick Reference
From the repo root:

```bash
./optional/container-cohort/up.sh
./optional/container-cohort/start.sh
./optional/container-cohort/stop.sh
./optional/container-cohort/down.sh
./optional/container-cohort/ps.sh
./optional/container-cohort/logs.sh nodeA
./optional/container-cohort/logs.sh nodeB
./optional/container-cohort/logs.sh nodeC
```

Host REST ports:

- `nodeA` -> `http://localhost:18443`
- `nodeB` -> `http://localhost:28443`
- `nodeC` -> `http://localhost:38443`

Node-wise command examples:

```bash
docker exec -it sgx-nodeA sh
docker exec -it sgx-nodeB sh
docker exec -it sgx-nodeC sh
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeA sgx-pa-cli crl root
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeB sgx-pa-cli crl root
docker exec -e SGX_FORCE_SOFTWARE_KEYS=1 sgx-nodeC sgx-pa-cli crl root
```

Detailed runbook:

- [optional/container-cohort/docs/CONTAINERS.md](/home/asad/SGX/optional/container-cohort/docs/CONTAINERS.md:1)

---

## 0. Grounding Statement (READ FIRST)

Fresh pull of `main` completed before writing this plan. The June assessment was written against the **Phase 1** codebase; the repo has moved substantially, and that movement changes the plan in our favor:

| Fact confirmed on current `main` | Consequence |
|---|---|
| `src/runtime_gates.rs` exists with env gates: `SGX_DISABLE_NEBULA`, `SGX_DISABLE_POLICY_ENFORCEMENT`, `SGX_FORCE_SOFTWARE_KEYS`/`SGX_DISABLE_SE050_DKP`, `SGX_DISABLE_SECURE_BOOT_CHECK`, `SGX_DISABLE_PCR`, `SGX_DISABLE_READ_OCOTP`, `SGX_DISABLE_BROADCAST`, `SGX_DISABLE_DKP_ROTATION`, `SGX_DISABLE_COT_*`, `SGX_DISABLE_GRPC_SERVER`, `SGX_DISABLE_CERT_BOOTSTRAP`, + more | Assessment §8 item 5 ("dry-run enforcement") and the SE050/board-hardware decoupling **already exist**. Containers select behavior via env only. |
| `main.rs` creates ALL required dirs at startup (`/etc/sgx-guardian/{config,schemas,policies,threat}`, `/var/lib/sgx-guardian/{keys,pcr,boot,sgx-agent,identity,identity/peers,nebula/*,threat}`, `/var/log/sgx-guardian`) | No seed files needed in images — empty named volumes work. Assessment's `.expect`-panic warnings are stale: config/schema loads now fall back gracefully. |
| `SGX_LIGHTHOUSE_IP` env lets members find the CA without UDP broadcast; `SGX_NEBULA_DIR` overrides the nebula dir | Compose bridge networking works: static container IPs + one env var replaces LAN broadcast discovery. |
| `KeyManager` SE050 backend is a **`ssscli` shell-out** behind `#[cfg(feature = "secure-element")]` (`default = ["secure-element"]`), with automatic **software-key fallback** when hardware init fails | No native NXP libs at build OR run time. One build works on boards (hardware) and in containers (software fallback / forced via `SGX_FORCE_SOFTWARE_KEYS=1`). |
| `scripts/build.sh` already encodes the exact aarch64 cross recipe: apt prereqs (`protobuf-compiler cmake pkg-config gcc/g++-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu nmap libcap2-bin`), rustup + target, `CC_aarch64_unknown_linux_gnu=… CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=… cargo build --release --workspace --locked --target aarch64-unknown-linux-gnu --features secure-element` | The board-builder image is a **containerized pin of this exact recipe** — no new build logic invented. |
| Board = Yocto mickledore, **glibc 2.37**; `debian:bookworm` cross toolchain = glibc **2.36** | Bookworm-based builder guarantees `GLIBC_*` symbol versions ≤ 2.36 ≤ board 2.37 → **container-built binaries always run on the boards**. (Ubuntu 24.04 hosts cross at 2.39 → can produce board-incompatible binaries — this is exactly the reproducibility problem the builder image kills.) |
| Nebula subsystem: daemon spawns external `nebula -config …` binary, uses `pkill`; binary missing ⇒ `exit(1)` (when gate enabled) | Runtime image must ship `nebula` + `nebula-cert` + `procps`; container needs `/dev/net/tun` + `CAP_NET_ADMIN` for the mesh. All standard for VPN-class containers. |
| Enforcement = `nft -f` shell-out with `table inet sgx_guardian`, `policy drop` on input | In a **bridge-networked container, nft rules scope to the container's own netns** → safe to exercise enforcement in the dev cohort without touching the dev machine's firewall. |
| `.github/workflows/ci.yml` exists (x86 build/test/clippy/audit/deny/semgrep/tarpaulin + GPG signing); **no container usage, no aarch64 job** | New `containers.yml` workflow is additive; existing CI stays untouched. |
| `rustls 0.23` pinned to the **`ring`** provider (`default-features = false`), reqwest = `rustls-tls` | No OpenSSL anywhere; slim runtime image needs only `nftables ca-certificates procps iproute2 curl` + nebula. |
| Cervais deliverable tracker contains a client-requested line: *"Package Storage & Versioning — … how they are versioned and signed, **container registry**"* | GHCR image publishing in CI directly satisfies a billed client line item. |
| Decision log D009/D010: native packages + direct binary remain the sanctioned production path; boards are run via `./sgx_guardian_client nodeX` (no systemd/apt) | **Production on boards stays native.** Containers = build reproducibility + CI + dev cohort. On-board containers are documented as an optional, gated future (Section 3, Q1). |

**Net result: this task is 100 % additive infrastructure — 7 new files, 0 `src/` edits, 0 FIND→REPLACE blocks, 0 new Rust dependencies.**

---

## 1. Task Definition (three roles, from the assessment, mapped to current main)

| Role | What it is | Privileges | Status after this plan |
|---|---|---|---|
| **R1 — CI / build & test image** | Reproducible x86_64 build + full test/lint suite in a pinned container | none | Implemented (`Dockerfile.agent` builder stage + `containers.yml`) |
| **R1b — Board-builder image** | Pinned aarch64 cross-compile container producing the **exact board binaries** (`sgx_guardian_client`, `sgx-pa-cli`) with glibc-safe symbols | none | Implemented (`Dockerfile.board-builder`) |
| **R2 — 3-node dev/demo cohort** | `docker compose up` ⇒ nodeA (CA/Lighthouse) + nodeB + nodeC on one machine: cert bootstrap, Nebula overlay, DID docs, CRL **gossip**, REST APIs — no boards needed | `NET_ADMIN` + `/dev/net/tun` per container (scoped to container netns) | Implemented (`optional/container-cohort/docker-compose.dev.yml`) |
| **R3 — Production enforcement container on boards** | Agent container on the Variscite boards | host netns, `NET_ADMIN`, `/dev/net/tun`, `/dev/i2c-*`, ssscli+Plug&Trust in-image, nvmem/boot sysfs mounts, Docker in the Yocto BSP | **Deliberately deferred** — gated on Q1 (Section 3); native binary remains the production path per D009 and current board workflow |

---

## 2. Direct Answer: Do we need hardware details? How does this deploy to the device?

**Short answer: Roles R1/R1b/R2 need no new hardware information — everything required is already known from the project context, so the plan is created (this file). Only R3 (running containers ON the boards) has genuine unknowns, and R3 is deferred by design.**

**What lands on the boards does NOT change.** The board deployment path stays exactly your current workflow — the only difference is *where the binary comes from*:

```
BEFORE:  dev machine (whatever toolchain) ──scripts/build.sh──▶ scp ──▶ ./sgx_guardian_client nodeX
AFTER:   docker run board-builder (pinned bookworm toolchain) ──▶ artifacts/ ──▶ scp ──▶ ./sgx_guardian_client nodeX
```

No Docker on the boards. No systemd. No change to `pkill -f sgx_guardian_client`, log tailing, or any board command.

### 2.1 Facts I already have (stated for your confirmation — no reply needed unless wrong)

| # | Assumption used by this plan | Source |
|---|---|---|
| A1 | Boards: Variscite VAR-SOM-MX8M-PLUS (i.MX8MP, aarch64), Yocto NXP i.MX 6.1-mickledore, **glibc 2.37**, eMMC storage | Project context / datasheets |
| A2 | Board deployment = direct binary via scp + `./sgx_guardian_client nodeX`; no apt/systemd; opkg exists but unused for guardian | Board workflow + `scripts/install.sh` |
| A3 | SE050 access = `ssscli` external tool (I2C); Rust build has **no** native SE050 linkage | `src/secure_element/ssscli.rs`, `key_manager.rs` |
| A4 | Dev/test host = your Windows machine ⇒ cohort runs under **Docker Desktop (WSL2 backend)**; `NET_ADMIN` + `/dev/net/tun` work there | CRL log ("Windows PowerShell ke SSH client") + Docker Desktop capability |
| A5 | Repo CI = GitHub Actions in the Cervais org ⇒ **GHCR** (`ghcr.io/<org>/…`) is the natural registry for the client's "container registry" line item | `.github/workflows/ci.yml`, deliverable tracker |

### 2.2 Genuine open questions (none block R1/R1b/R2 — answers only refine R3 + one CI toggle)

| Q | Question | How to answer it yourself (2 min) | What it gates |
|---|---|---|---|
| **Q1** | Does the Yocto board image contain a container runtime (docker/containerd/podman)? *(Expected: NO — and that's fine)* | On any board: `which docker containerd podman; docker info 2>&1 \| head -5; zcat /proc/config.gz 2>/dev/null \| grep -E "CONFIG_(NAMESPACES\|CGROUPS\|OVERLAY_FS)="` | **R3 only.** If ever wanted, it's a BSP request to Ranjeet & Lucas (meta-virtualization). This plan does not need it. |
| **Q2** | Are we allowed to push packages to GHCR in the Cervais org (or is a different private registry mandated)? | Ask James/org admin; or check `Settings → Packages` on the org | Only the final **push** step in `containers.yml` (guarded by a repo variable `ENABLE_GHCR_PUSH` — everything else runs regardless). |
| **Q3** | Which Nebula version do the boards run? | On any board: `nebula -version` | Only the `NEBULA_VERSION` ARG pin in the agent image (default `1.9.5`; overlay interop is tolerant, but matching versions is good hygiene). |
| **Q4** | Dev cohort host has ≥ 8 GB RAM free + Docker Desktop installed? | `docker version` on your machine | Only R2 comfort; 3 nodes are lightweight (~100–200 MB RSS each). |

If Q1 comes back "yes, Docker exists on the board" and Cervais explicitly wants on-board containers, tell me — I'll produce the R3 addendum (host-netns compose file + device passthrough matrix). Until then R3 stays a documented option, matching decision D009 and the assessment's own recommendation.

---

## 3. Scope

### In scope
1. **`.dockerignore`** — keep contexts small and secrets out.
2. **`optional/container-cohort/docker/Dockerfile.agent`** — multi-stage: pinned builder (build + test-capable) → slim runtime with `nebula`/`nebula-cert`, `nftables`, `procps`; ships BOTH `sgx_guardian_client` and `sgx-pa-cli`.
3. **`docker/Dockerfile.board-builder`** — pinned bookworm aarch64 cross image; containerizes the `scripts/build.sh` recipe; emits board artifacts to a mounted `artifacts/` dir.
4. **`optional/container-cohort/docker/entrypoint.sh`** — tiny exec wrapper (`NODE_ID` env or argv passthrough).
5. **`optional/container-cohort/docker-compose.dev.yml`** — 3-node cohort on an isolated bridge (`172.31.250.0/24`, static IPs), per-node volumes, health-gated startup, REST published on `18443/28443/38443`.
6. **`.github/workflows/containers.yml`** — additive CI: build agent image, run workspace tests in the builder stage, produce aarch64 board artifacts via the board-builder, upload artifacts, optionally push images to GHCR.
7. **`optional/container-cohort/docs/CONTAINERS.md`** — usage + troubleshooting + Windows notes.
8. CTR-series verification matrix (Section 10).

### Out of scope (explicitly)
- Any `src/` change (none required — see §0).
- Kubernetes manifests (assessment marks K8s as heaviest option; no stakeholder ask).
- On-board (R3) production containers — gated on Q1, deferred.
- Replacing the native board deployment path (kept per D009).
- Touching the existing `ci.yml` (new workflow is separate to avoid destabilizing the billed pipeline).

---

## 4. Architecture

### 4.1 Image topology

```
 optional/container-cohort/docker/Dockerfile.agent                     docker/Dockerfile.board-builder
┌─────────────────────────────┐             ┌───────────────────────────────────┐
│ stage: builder              │             │ debian:bookworm                   │
│  rust:1.90-bookworm         │             │  + gcc/g++-aarch64-linux-gnu      │
│  + protobuf-compiler cmake  │             │  + libc6-dev-arm64-cross (2.36)   │
│  cargo build --workspace    │             │  + protobuf-compiler cmake        │
│  --locked --release (x86)   │             │  + rustup (pinned) + aarch64 tgt  │
│  [cargo test runs here]     │             │  CMD: locked cross build          │
└──────────┬──────────────────┘             │       --features secure-element   │
           ▼                                │  OUT: /artifacts/sgx-guardian*    │
┌─────────────────────────────┐             └───────────────┬───────────────────┘
│ stage: runtime              │                             │ scp (unchanged
│  debian:bookworm-slim       │                             ▼  board workflow)
│  + nftables ca-certificates │              boards: ./sgx_guardian_client nodeX
│    procps iproute2 curl     │
│  + nebula, nebula-cert      │
│  + sgx_guardian_client      │
│  + sgx-pa-cli               │
└─────────────────────────────┘
```

### 4.2 Dev cohort (R2) — what actually happens on `compose up`

```
bridge sgxnet 172.31.250.0/24      every container: NET_ADMIN + /dev/net/tun
┌─ nodeA 172.31.250.10 ───────┐    nodeA: generates Nebula CA, assigns own
│ CA + Lighthouse             │           overlay IP (192.168.100.x), starts
│ registry sync :50062        │◄──┐       registry server + cert bootstrap
│ cert bootstrap :50061       │   │
│ REST :8443 → host :18443    │   │  members: SGX_LIGHTHOUSE_IP=172.31.250.10
└─────────────────────────────┘   │  (replaces LAN UDP broadcast), request
┌─ nodeB 172.31.250.11 ───────┐   │  overlay IP + Nebula cert from nodeA,
│ REST :8443 → host :28443    │───┤  start nebula → nebula0 inside container
└─────────────────────────────┘   │
┌─ nodeC 172.31.250.12 ───────┐   │  Overlay 192.168.100.0/24 forms INSIDE
│ REST :8443 → host :38443    │───┘  the containers over sgxnet UDP 4242.
└─────────────────────────────┘      DID docs sync, CRL gossip (:50063) runs.
```

Cohort env profile (set in compose, not baked into the image):

| Env | Value | Why |
|---|---|---|
| `SGX_FORCE_SOFTWARE_KEYS=1` | forced | No SE050/ssscli in containers — software ring keys (existing gate) |
| `SGX_DISABLE_SECURE_BOOT_CHECK=1`, `SGX_DISABLE_READ_OCOTP=1`, `SGX_SIM_MODE=true` | forced | Off-board runs use simulation mode and skip board-specific secure boot / OCOTP paths |
| `SGX_DISABLE_DKP_ROTATION=1` | forced | Skips the second ssscli probe |
| `SGX_DISABLE_COT_BLUETOOTH/CELLULAR/SATELLITE=1` | forced | No such interfaces in containers |
| `SGX_LIGHTHOUSE_IP=172.31.250.10` (members) | forced | Direct lighthouse addressing keeps member bootstrap deterministic on the bridge network |
| `SGX_DISABLE_POLICY_ENFORCEMENT=1` | **default, removable** | Default-safe. Remove it to exercise real `nft` enforcement **scoped to the container's own netns** (CTR-010) — a safe sandbox the boards can't offer |
| `RUST_LOG=info` | default | tracing filter |

Everything else (attestation, gRPC mTLS, registry sync, DID docs, VC status lists, CRL + gossip, REST API) runs **real**, unmodified.

### 4.3 Design decisions

| Decision | Choice | Why |
|---|---|---|
| Base images | `rust:1.90-bookworm` / `debian:bookworm(-slim)` | Bookworm = glibc 2.36 ≤ board 2.37 (R1b correctness); slim runtime + vendored nebula |
| Keep binary name `sgx_guardian_client` in image | yes | All house tooling (`pkill -f sgx_guardian_client`, docs, muscle memory) keeps working inside containers |
| `--locked` everywhere | yes | `Cargo.lock` is the reproducibility contract; mirrors `scripts/build.sh` |
| Features | default (`secure-element` on) for BOTH x86 and aarch64 builds | Matches board build exactly; software fallback + `SGX_FORCE_SOFTWARE_KEYS` handle hardware absence |
| Nebula in runtime image | vendored `docker/vendor/nebula` + `docker/vendor/nebula-cert` | Daemon hard-exits without the binary; local vendoring removes GitHub as a build-time dependency |
| Per-node `/etc/sgx-guardian` volumes (NOT a shared ro bind) | named volume per node | Current code **writes** configs (dynamic IP updates) — the assessment's shared read-only config mount is stale advice |
| Existing `ci.yml` untouched | separate `containers.yml` | The signed-package pipeline is a billed deliverable; zero risk appetite |
| GHCR push behind `vars.ENABLE_GHCR_PUSH` | repo variable gate | Respects Q2 without blocking everything else |

---

## 5. Sprint Deliverable Row (copy-paste)

| Scope | Deliverable | Description | Test tag |
|---|---|---|---|
| DevOps / Containerization | Container Image Workflow | Implement the three-role container workflow for the Guardian: (1) a pinned multi-stage CI image that builds and tests the full workspace reproducibly on x86_64; (2) a bookworm-based aarch64 board-builder image that containerizes the existing `scripts/build.sh` cross recipe and guarantees glibc-2.36-safe board binaries for the i.MX8MP fleet; and (3) a `docker compose` three-node dev/demo cohort (nodeA CA/Lighthouse + two members on an isolated bridge with `NET_ADMIN` + TUN) that exercises the real cert-bootstrap, Nebula overlay, DID document sync, CRL gossip, and REST surfaces end-to-end on a single machine using existing runtime gates (software keys, enforcement dry-run) — with an additive GitHub Actions workflow that builds/tests the images, emits board artifacts, and optionally publishes to GHCR, satisfying the client's container-registry line item with zero `src/` changes and the native binary retained as the production board path. | CTR-series (CTR-001–CTR-010) |

---

## 6. File Structure

```
.dockerignore                       NEW
docker/
├── Dockerfile.agent                NEW  (builder + runtime stages, x86_64)
├── Dockerfile.board-builder        NEW  (aarch64 cross toolchain, pinned)
└── entrypoint.sh                   NEW
optional/container-cohort/docker-compose.dev.yml              NEW  (3-node cohort)
.github/workflows/containers.yml    NEW  (additive CI)
optional/container-cohort/docs/CONTAINERS.md                  NEW
src/**                              UNCHANGED (zero edits)
Cargo.toml / Cargo.lock             UNCHANGED
.github/workflows/ci.yml            UNCHANGED
```

---

## 7. Pre-Flight Verification (run before creating files)

```bash
git pull origin main && git log -1 --oneline

# Gates this plan depends on (all must hit):
grep -n "SGX_FORCE_SOFTWARE_KEYS\|SGX_DISABLE_POLICY_ENFORCEMENT\|SGX_DISABLE_PCR\|SGX_DISABLE_SECURE_BOOT_CHECK" src/runtime_gates.rs
grep -n "SGX_LIGHTHOUSE_IP" src/main.rs
grep -n "SGX_NEBULA_DIR" src/main.rs
grep -n 'default = \["secure-element"\]' Cargo.toml
grep -n "aarch64-unknown-linux-gnu" scripts/build.sh

# Nothing container-related exists yet (all must MISS):
ls Dockerfile* docker/ docker-compose*.yml .dockerignore 2>/dev/null && echo "❌ artifacts already exist — reconcile first" || echo "✅ clean slate"
```

---

## 8. Implementation — New Files (create exactly as written)

### 8.1 `.dockerignore`

```
target/
artifacts/
.git/
.github/
*.md
docs/
deliverables/
decision-log/
logs/
*.log
*.key
*.der
*.crt
*.pem
signed_artifacts/
.vscode/
.idea/
```

> `Cargo.lock` is intentionally NOT ignored — `--locked` builds require it in context. `*.md` exclusion keeps docs out of the build context; add exceptions later only if a build consumes them.

### 8.2 `optional/container-cohort/docker/Dockerfile.agent`

```dockerfile
# syntax=docker/dockerfile:1.7
# =============================================================================
# SG-X Guardian — agent image (x86_64)
#   builder : pinned Rust toolchain; also the CI test environment
#   runtime : slim Debian + nftables + nebula; runs the real daemon
#
# Build:  docker build -f optional/container-cohort/docker/Dockerfile.agent -t sgx-guardian:dev .
# Tests:  docker build -f optional/container-cohort/docker/Dockerfile.agent --target builder -t sgx-builder . \
#         && docker run --rm sgx-builder cargo test --workspace --locked
# =============================================================================

ARG RUST_IMAGE=rust:1.90-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

# ---- Stage 1: builder -------------------------------------------------------
FROM ${RUST_IMAGE} AS builder

# protoc: required by tonic-prost-build in build.rs
# cmake + pkg-config: mirror scripts/build.sh prerequisites exactly
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Same contract as CI and scripts/build.sh: locked, whole workspace,
# default features (secure-element ships; software fallback handles no-SE050).
RUN cargo build --release --workspace --locked

# ---- Stage 2: runtime -------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime

# nftables      : enforcement executor shells out to `nft -f`
# procps        : daemon uses pkill/pgrep for nebula lifecycle
# iproute2      : `ip`/`ss` for interface verification + debugging
# ca-certificates: outbound TLS trust (cloud uplink, fetches)
# curl          : healthchecks + in-container smoke tests
RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables ca-certificates procps iproute2 curl \
    && rm -rf /var/lib/apt/lists/*

# Nebula mesh binaries are vendored in-repo so image builds do not depend on GitHub.
COPY docker/vendor/nebula /usr/local/bin/nebula
COPY docker/vendor/nebula-cert /usr/local/bin/nebula-cert
RUN chmod 0755 /usr/local/bin/nebula /usr/local/bin/nebula-cert \
    && nebula -version

# Keep canonical binary names — pkill -f sgx_guardian_client etc. must keep working.
COPY --from=builder /src/target/release/sgx_guardian_client /usr/local/bin/sgx_guardian_client
COPY --from=builder /src/target/release/sgx-pa-cli          /usr/local/bin/sgx-pa-cli
COPY optional/container-cohort/docker/entrypoint.sh /usr/local/bin/sgx-entrypoint
RUN chmod 0755 /usr/local/bin/sgx-entrypoint

# State/config/log roots — the daemon creates subdirs itself at startup.
VOLUME ["/etc/sgx-guardian", "/var/lib/sgx-guardian", "/var/log/sgx-guardian"]

# gRPC 50051-53 | cert bootstrap 50061 | registry 50062 | CRL gossip 50063
# REST 8443 | discovery UDP 9000 | nebula UDP 4242 | attestation 50151-53
EXPOSE 50051-50053 50061-50063 8443 50151-50153 9000/udp 4242/udp

WORKDIR /var/lib/sgx-guardian
ENTRYPOINT ["/usr/local/bin/sgx-entrypoint"]
CMD ["nodeA"]
```

> **Vendoring note:** before the first build on a new machine, copy the approved local `nebula` and `nebula-cert` binaries into `docker/vendor/`. The build verifies the vendored `nebula` binary by running `nebula -version`.

### 8.3 `optional/container-cohort/docker/entrypoint.sh`

```bash
#!/bin/sh
# SG-X Guardian container entrypoint.
# Node selection precedence: $NODE_ID env > first argv > baked CMD default.
set -eu

NODE="${NODE_ID:-${1:-nodeA}}"

echo "── SG-X Guardian container ──────────────────────────────"
echo "   node_id            : ${NODE}"
echo "   nebula gate        : SGX_DISABLE_NEBULA=${SGX_DISABLE_NEBULA:-<unset>}"
echo "   enforcement gate   : SGX_DISABLE_POLICY_ENFORCEMENT=${SGX_DISABLE_POLICY_ENFORCEMENT:-<unset>}"
echo "   software keys      : SGX_FORCE_SOFTWARE_KEYS=${SGX_FORCE_SOFTWARE_KEYS:-<unset>}"
echo "   lighthouse ip      : SGX_LIGHTHOUSE_IP=${SGX_LIGHTHOUSE_IP:-<unset>}"
echo "─────────────────────────────────────────────────────────"

exec /usr/local/bin/sgx_guardian_client "${NODE}"
```

### 8.4 `docker/Dockerfile.board-builder`

```dockerfile
# syntax=docker/dockerfile:1.7
# =============================================================================
# SG-X Guardian — aarch64 board-builder (containerized scripts/build.sh recipe)
#
# WHY BOOKWORM: the boards run Yocto mickledore (glibc 2.37). Bookworm's
# aarch64 cross libc is 2.36, so every symbol this image links is guaranteed
# available on the boards. Newer hosts (e.g. Ubuntu 24.04, glibc 2.39 cross)
# can silently produce binaries the boards cannot run — this image makes that
# class of failure impossible.
#
# Build image:  docker build -f docker/Dockerfile.board-builder -t sgx-board-builder .
# Produce bins: docker run --rm -v "$PWD":/src -v "$PWD/artifacts":/artifacts sgx-board-builder
# Output:       artifacts/sgx-guardian  artifacts/sgx-pa-cli   (aarch64, board-ready)
# =============================================================================

FROM debian:bookworm

# Exact prerequisite set from scripts/build.sh (base + cross packages).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential pkg-config cmake \
        protobuf-compiler \
        gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
        libc6-dev-arm64-cross binutils-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

# Pinned Rust toolchain (bump deliberately, in lockstep with CI).
ARG RUST_TOOLCHAIN=1.90.0
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain ${RUST_TOOLCHAIN} \
    && rustup target add aarch64-unknown-linux-gnu \
    && rustc -Vv && cargo -V && protoc --version \
    && aarch64-linux-gnu-gcc --version | head -n1

# Same env contract as scripts/build.sh.
ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

WORKDIR /src
VOLUME ["/src", "/artifacts"]

# Locked release build of the whole workspace, secure-element ON — the exact
# board contract from scripts/build.sh — then export with board artifact names.
CMD set -eux; \
    cargo build --release --workspace --locked \
        --target aarch64-unknown-linux-gnu --features secure-element; \
    install -m 0755 target/aarch64-unknown-linux-gnu/release/sgx_guardian_client /artifacts/sgx-guardian; \
    install -m 0755 target/aarch64-unknown-linux-gnu/release/sgx-pa-cli          /artifacts/sgx-pa-cli; \
    aarch64-linux-gnu-strip --strip-debug /artifacts/sgx-guardian /artifacts/sgx-pa-cli || true; \
    file /artifacts/sgx-guardian; \
    echo "Max GLIBC symbol version required:"; \
    aarch64-linux-gnu-objdump -T /artifacts/sgx-guardian | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -3

# NOTE (Windows/Docker Desktop): if the bind-mounted target/ dir is slow,
# run with a named volume for target instead:
#   docker run --rm -v "$PWD":/src -v sgx-target:/src/target -v "$PWD/artifacts":/artifacts sgx-board-builder
```

### 8.5 `optional/container-cohort/docker-compose.dev.yml`

```yaml
# =============================================================================
# SG-X Guardian — 3-node dev/demo cohort (R2)
#   docker compose -f optional/container-cohort/docker-compose.dev.yml up --build -d
#
# What you get on one machine, no boards:
#   nodeA = CA + Lighthouse (registry :50062, cert bootstrap :50061)
#   nodeB / nodeC = members (bootstrap certs from nodeA, join Nebula overlay)
#   Real: attestation, mTLS gRPC, DID docs, VC status, CRL + gossip, REST.
#   Gated off: SE050/ssscli, HAB/OCOTP/PCR board measurements, LAN broadcast,
#              nftables apply (remove SGX_DISABLE_POLICY_ENFORCEMENT to test it
#              safely inside the container's own netns).
#
# REST from the host:  nodeA http://localhost:18443
#                      nodeB http://localhost:28443
#                      nodeC http://localhost:38443
# =============================================================================
name: sgx-guardian-dev

x-guardian-common: &guardian-common
  build:
    context: .
    dockerfile: optional/container-cohort/docker/Dockerfile.agent
  image: sgx-guardian:dev
  cap_add:
    - NET_ADMIN            # nebula TUN + (optional) in-container nftables
  devices:
    - /dev/net/tun:/dev/net/tun
  environment: &guardian-env
    RUST_LOG: info
    SGX_FORCE_SOFTWARE_KEYS: "1"
    SGX_DISABLE_SECURE_BOOT_CHECK: "1"
    SGX_DISABLE_READ_OCOTP: "1"
    SGX_DISABLE_DKP_ROTATION: "1"
    SGX_DISABLE_COT_BLUETOOTH: "1"
    SGX_DISABLE_COT_CELLULAR: "1"
    SGX_DISABLE_COT_SATELLITE: "1"
    SGX_SIM_MODE: "true"
    SGX_DISABLE_POLICY_ENFORCEMENT: "1"   # remove to exercise nft in-container (CTR-010)
  restart: unless-stopped

services:
  nodeA:
    <<: *guardian-common
    container_name: sgx-nodeA
    hostname: sgx-nodeA
    environment:
      <<: *guardian-env
      NODE_ID: nodeA
    networks:
      sgxnet:
        ipv4_address: 172.31.250.10
    ports:
      - "18443:8443"
    volumes:
      - nodeA-etc:/etc/sgx-guardian
      - nodeA-lib:/var/lib/sgx-guardian
      - nodeA-log:/var/log/sgx-guardian
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://127.0.0.1:8443/api/v1/crl/root"]
      interval: 10s
      timeout: 5s
      retries: 12
      start_period: 40s

  nodeB:
    <<: *guardian-common
    container_name: sgx-nodeB
    hostname: sgx-nodeB
    environment:
      <<: *guardian-env
      NODE_ID: nodeB
      SGX_LIGHTHOUSE_IP: 172.31.250.10
    networks:
      sgxnet:
        ipv4_address: 172.31.250.11
    ports:
      - "28443:8443"
    volumes:
      - nodeB-etc:/etc/sgx-guardian
      - nodeB-lib:/var/lib/sgx-guardian
      - nodeB-log:/var/log/sgx-guardian
    depends_on:
      nodeA:
        condition: service_healthy

  nodeC:
    <<: *guardian-common
    container_name: sgx-nodeC
    hostname: sgx-nodeC
    environment:
      <<: *guardian-env
      NODE_ID: nodeC
      SGX_LIGHTHOUSE_IP: 172.31.250.10
    networks:
      sgxnet:
        ipv4_address: 172.31.250.12
    ports:
      - "38443:8443"
    volumes:
      - nodeC-etc:/etc/sgx-guardian
      - nodeC-lib:/var/lib/sgx-guardian
      - nodeC-log:/var/log/sgx-guardian
    depends_on:
      nodeA:
        condition: service_healthy

networks:
  sgxnet:
    driver: bridge
    ipam:
      config:
        - subnet: 172.31.250.0/24

volumes:
  nodeA-etc: {}
  nodeA-lib: {}
  nodeA-log: {}
  nodeB-etc: {}
  nodeB-lib: {}
  nodeB-log: {}
  nodeC-etc: {}
  nodeC-lib: {}
  nodeC-log: {}
```

### 8.6 `.github/workflows/containers.yml`

```yaml
name: Containers

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  agent-image:
    name: Agent image — build & test (x86_64)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build builder stage (cached)
        uses: docker/build-push-action@v6
        with:
          context: .
          file: optional/container-cohort/docker/Dockerfile.agent
          target: builder
          tags: sgx-builder:ci
          load: true
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Run workspace tests inside the builder
        run: docker run --rm sgx-builder:ci cargo test --workspace --locked

      - name: Build runtime image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: optional/container-cohort/docker/Dockerfile.agent
          tags: sgx-guardian:ci
          load: true
          cache-from: type=gha

      - name: Runtime image smoke (binaries + nebula present)
        run: |
          docker run --rm --entrypoint /bin/sh sgx-guardian:ci -c \
            "sgx_guardian_client 2>&1 | head -2; sgx-pa-cli --help >/dev/null; nebula -version; nft --version"

      - name: Push to GHCR (main only, opt-in via repo variable)
        if: github.ref == 'refs/heads/main' && vars.ENABLE_GHCR_PUSH == 'true'
        env:
          GHCR_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          echo "$GHCR_TOKEN" | docker login ghcr.io -u "${{ github.actor }}" --password-stdin
          IMAGE=ghcr.io/${{ github.repository_owner }}/sgx-guardian
          docker tag sgx-guardian:ci $IMAGE:${{ github.sha }}
          docker tag sgx-guardian:ci $IMAGE:latest
          docker push $IMAGE:${{ github.sha }}
          docker push $IMAGE:latest

  board-artifacts:
    name: Board artifacts — aarch64 (glibc-safe)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build board-builder image
        run: docker build -f docker/Dockerfile.board-builder -t sgx-board-builder:ci .

      - name: Cross-compile board binaries
        run: |
          mkdir -p artifacts
          docker run --rm -v "$PWD":/src -v "$PWD/artifacts":/artifacts sgx-board-builder:ci

      - name: Assert aarch64 + glibc ceiling
        run: |
          file artifacts/sgx-guardian | tee /dev/stderr | grep -q "ARM aarch64"
          MAX=$(docker run --rm -v "$PWD/artifacts":/a sgx-board-builder:ci sh -c \
            "aarch64-linux-gnu-objdump -T /a/sgx-guardian | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1")
          echo "Max required: $MAX (board provides 2.37)"
          [ "$(printf '%s\n2.37\n' "${MAX#GLIBC_}" | sort -V | tail -1)" = "2.37" ]

      - name: Upload board artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sgx-guardian-board-aarch64-${{ github.run_number }}
          path: |
            artifacts/sgx-guardian
            artifacts/sgx-pa-cli
```

### 8.7 `optional/container-cohort/docs/CONTAINERS.md` (skeleton — expand during rollout)

```markdown
# SG-X Guardian — Containers

## Roles
1. **CI/build image** (`optional/container-cohort/docker/Dockerfile.agent`, builder stage) — reproducible x86_64 build + `cargo test`.
2. **Board-builder** (`docker/Dockerfile.board-builder`) — aarch64 binaries for the i.MX8MP boards,
   glibc-2.36-pinned (boards run 2.37). Output: `artifacts/sgx-guardian`, `artifacts/sgx-pa-cli`.
3. **Dev cohort** (`optional/container-cohort/docker-compose.dev.yml`) — 3 real nodes on one machine.

## Quickstart — board binaries (replaces ad-hoc host cross builds)
    docker build -f docker/Dockerfile.board-builder -t sgx-board-builder .
    docker run --rm -v "$PWD":/src -v "$PWD/artifacts":/artifacts sgx-board-builder
    scp artifacts/sgx-guardian root@192.168.50.101:/path/on/board/sgx_guardian_client
    # then, on the board, the usual: pkill -f sgx_guardian_client; ./sgx_guardian_client nodeA

## Quickstart — dev cohort
    docker compose -f optional/container-cohort/docker-compose.dev.yml up --build -d
    docker compose -f optional/container-cohort/docker-compose.dev.yml logs -f nodeA   # CA + registry startup
    curl -s http://localhost:18443/api/v1/crl/root           # nodeA REST
    docker exec sgx-nodeB sgx-pa-cli crl root                # member CLI

## Production note
Boards run the **native binary** (decision D009). Containers here are for build
reproducibility, CI, and dev/demo. On-board containers are a gated future option
(requires Docker in the Yocto BSP — see plan Section 2.2 Q1).

## Windows (Docker Desktop / WSL2)
Works as-is (NET_ADMIN + /dev/net/tun available to Linux containers). If bind-mount
builds are slow, use a named volume for `target/` (note in Dockerfile.board-builder).

## Troubleshooting
- nodeA unhealthy → `docker logs sgx-nodeA` (look for STEP_xx markers from runtime gates).
- Member can't bootstrap → confirm `SGX_LIGHTHOUSE_IP=172.31.250.10` and nodeA healthy.
- `nebula0` missing in a container → verify `cap_add: NET_ADMIN` + `/dev/net/tun` device.
- Enforcement experiments → remove `SGX_DISABLE_POLICY_ENFORCEMENT` on ONE node first;
  rules scope to that container's netns only.
```

---

## 9. Constraint Compliance (project hard rules)

| Rule | Compliance |
|---|---|
| No touching `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()` / daemon lifecycle | **Zero `src/` edits anywhere.** Nebula/pkill/procps requirements are satisfied in the image, not the code. |
| No `std::thread::sleep` / sync `Command` reintroduction | No Rust code written. |
| Board workflow (no systemctl/journalctl/apt for guardian) | Board path unchanged: scp + `./sgx_guardian_client nodeX` + `pkill`/`tail`. Containers never land on boards in this task. |
| ECDSA-P256 + SHA-256 only | Untouched; `SGX_FORCE_SOFTWARE_KEYS` uses the existing ring P-256 path. |
| Board freeze vectors (OCOTP mmap, blocking-in-async) | Cohort sets `SGX_DISABLE_READ_OCOTP=1`; nothing board-freeze-adjacent is exercised in containers. |
| Yocto/aarch64 | Board-builder pins bookworm cross glibc 2.36 ≤ board 2.37, with a CI assertion (CTR/CI step) that fails the build if the ceiling is ever exceeded. |

---

## 10. Verification Matrix — CTR-series

Run after creating the files. (Same board rules as always: propagation tests via REST/CLI, no systemctl.)

| Tag | Check | Commands | Expected |
|---|---|---|---|
| **CTR-001** | Agent image builds | `docker build -f optional/container-cohort/docker/Dockerfile.agent -t sgx-guardian:dev .` | Build succeeds; final image < ~250 MB |
| **CTR-002** | Workspace tests green in container | `docker build -f optional/container-cohort/docker/Dockerfile.agent --target builder -t sgx-builder . && docker run --rm sgx-builder cargo test --workspace --locked` | All tests pass (same set as host `cargo test`) |
| **CTR-003** | Board artifacts correct arch + glibc ceiling | `docker build -f docker/Dockerfile.board-builder -t sgx-board-builder . && docker run --rm -v "$PWD":/src -v "$PWD/artifacts":/artifacts sgx-board-builder && file artifacts/sgx-guardian` | `ARM aarch64`; printed max `GLIBC_*` ≤ 2.36 |
| **CTR-004** | Container-built binary is a drop-in on a real board | `scp artifacts/sgx-guardian root@192.168.50.101:/…/sgx_guardian_client` → on board: `pkill -f sgx_guardian_client; ./sgx_guardian_client nodeA` → `curl -s http://localhost:8443/api/v1/crl/root` | Daemon starts through all STEP markers; SE050 hardware path active (`DKP initialized via SE050 hardware`); REST answers |
| **CTR-005** | Cohort comes up, members bootstrap | `docker compose -f optional/container-cohort/docker-compose.dev.yml up --build -d && docker compose -f optional/container-cohort/docker-compose.dev.yml ps` | nodeA healthy; B/C started after health gate; B/C logs show cert bootstrap from 172.31.250.10 |
| **CTR-006** | Overlay forms inside containers | `for n in A B C; do docker exec sgx-node$n ip addr show nebula0; done` then `docker exec sgx-nodeB ping -c2 192.168.100.1` | `nebula0` with 192.168.100.x on all three; overlay ping OK |
| **CTR-007** | REST reachable from host | `for p in 18443 28443 38443; do curl -s http://localhost:$p/api/v1/crl/root; echo; done` | Three JSON responses |
| **CTR-008** | CRL propagation across the cohort (gossip demo without boards) | `docker exec sgx-nodeA sgx-pa-cli crl revoke --did did:guardian:ctr-test-001 --reason compromised --severity critical` → wait ≤2 gossip intervals (or trigger endpoint) → `docker exec sgx-nodeB sgx-pa-cli crl check --did did:guardian:ctr-test-001; docker exec sgx-nodeC sgx-pa-cli crl root` | `revoked: true` on B; Merkle roots identical A/B/C |
| **CTR-009** | Identity persists across restarts | `docker exec sgx-nodeA sh -c "grep -o '\"did\":\"[^\"]*\"' /var/lib/sgx-guardian/identity/did.json"` → `docker compose -f optional/container-cohort/docker-compose.dev.yml restart nodeA` → repeat | Same DID before/after (named volume) |
| **CTR-010** | (Opt-in) enforcement fires safely in-container | Remove `SGX_DISABLE_POLICY_ENFORCEMENT` for nodeA only → `docker compose up -d nodeA` → `docker exec sgx-nodeA nft list table inet sgx_guardian` | `table inet sgx_guardian` with `policy drop` + allow rules exists **inside the container netns only**; host firewall untouched (`sudo nft list tables` on host shows no sgx table) |

---

## 11. Deployment Guide — Device (boards)

**Track A — what we actually do (unchanged workflow, better provenance):**
1. `docker run --rm -v "$PWD":/src -v "$PWD/artifacts":/artifacts sgx-board-builder` (or download the `sgx-guardian-board-aarch64-*` artifact from the Actions run).
2. `scp artifacts/sgx-guardian root@192.168.50.101:/<deploy_dir>/sgx_guardian_client` (repeat for `.115`, `.248`; `sgx-pa-cli` likewise).
3. On each board: `pkill -f sgx_guardian_client || true` → `./sgx_guardian_client nodeX`.
4. CTR-004 confirms hardware paths (SE050, PCR, OCOTP-via-nvmem) behave identically to host-built binaries.

Nothing else changes: no Docker, no new packages, no new services on the boards.

**Track B — containers ON the boards (deferred, gated on Q1):** would require, at minimum: container runtime in the Yocto BSP (Ranjeet & Lucas, meta-virtualization), `--network host` + `NET_ADMIN` (host firewalling + Nebula), `/dev/net/tun`, `/dev/i2c-*` passthrough **plus ssscli + NXP Plug & Trust inside the image**, read-only mounts of `/sys/bus/nvmem`, `/proc/device-tree`, `/boot` (PCR/HAB sources), and `nmap` in-image (Sprint 6). At that point the container is packaging, not isolation — exactly the assessment's conclusion. Native stays the production path unless Cervais explicitly requests otherwise.

---

## 12. Regression Checks

```bash
# 1. Host build/test contract unchanged (no src edits — should be trivially green)
cargo build --release --workspace --locked && cargo test --workspace --locked

# 2. Existing CI untouched
git diff --stat .github/workflows/ci.yml    # must be empty

# 3. No src changes at all
git diff --stat src/ sgx-pa-cli/ Cargo.toml Cargo.lock    # must be empty

# 4. Board parity: container-built vs host-built binary
sha256sum artifacts/sgx-guardian target/aarch64-unknown-linux-gnu/release/sgx_guardian_client
# (Hashes may differ due to path remapping — the CTR-004 board smoke is the real parity test.)

# 5. Board suite still green after deploying the container-built binary
./scripts/crl_board_check.sh
```

---

## 13. Step-by-Step Checklist

- [ ] `git pull origin main` → run Section 7 pre-flight (gates present, clean slate)
- [ ] Branch: `git checkout -b containerization`
- [ ] Create the 7 files (Section 8) exactly as written
- [ ] Refresh `NEBULA_SHA256` pin (Section 8.2 note); confirm Q3 (`nebula -version` on a board) and align `NEBULA_VERSION` if it differs
- [ ] CTR-001 → CTR-003 locally
- [ ] CTR-004 on nodeA board (container-built binary drop-in)
- [ ] CTR-005 → CTR-009 cohort on your machine (Docker Desktop)
- [ ] Optional: CTR-010 enforcement-in-container experiment
- [ ] Push branch → confirm both `containers.yml` jobs green; download board artifact from Actions as a second CTR-003 sample
- [ ] Q2 answer → set repo variable `ENABLE_GHCR_PUSH=true` (or leave off) 
- [ ] PR with this plan + filled CTR results; note the client "container registry" line item linkage
- [ ] Update `optional/container-cohort/docs/CONTAINERS.md` troubleshooting with anything learned

---

## 14. Rollback

Everything is additive: delete the 7 files (or revert the branch) and the repo is byte-identical to before. No data migration, no board impact, no CI impact (existing `ci.yml` never changed). The cohort's named volumes can be dropped with `docker compose -f optional/container-cohort/docker-compose.dev.yml down -v`.

---

## 15. Known Limitations → Follow-up Register

| # | Limitation | Severity | Follow-up |
|---|---|---|---|
| L1 | Cohort containers run as root (nebula TUN + optional nft need it); no userns remap | Low (dev-only scope) | Non-root + fine-grained caps if R3 ever ships |
| L2 | `NEBULA_VERSION` pin may drift from the board's nebula | Low | Q3 answer → align ARG; add a CI echo comparing versions |
| L3 | Compose cohort ≠ board hardware truth (SE050/PCR/HAB/OCOTP gated off) | By design | CTR-004 keeps the hardware path honest on every release |
| L4 | GHCR push inert until `ENABLE_GHCR_PUSH` set (Q2) | None | Flip the repo variable when confirmed |
| L5 | On-board containers (R3) undocumented beyond requirements list | Deferred | Separate addendum on explicit Cervais request + Q1 = yes |
| L6 | `optional/container-cohort/docker/Dockerfile.agent` builds x86_64 only (no multi-arch manifest) | Low | Add `--platform linux/arm64` matrix later if an arm64 *container* consumer appears (boards don't need it — they run native) |
