# Technical Assessment Framework: Containerizing the SG-X Guardian & Host/Kernel Decoupling

**Document type**: Applied assessment + reusable framework (populated against this repository)
**Subject**: `sgx_guardian_client` daemon + `sgx-pa-cli` (Phase 1 codebase)
**Audience**: Backend/systems engineers, DevOps, security architects
**Companion doc**: `./Containerization_Assessment.md` (concise, practical summary). This document is the deep, methodical version with the coupling audit **populated from actual code**.

---

## 0. Why a "Firmware-style" Framework Applies Here

SG-X Guardian is **not** firmware — it is a Rust user-space daemon. But it has the same structural problem that makes firmware hard to containerize: its core capabilities are **bound to low-level platform primitives**, not to portable application logic. For firmware that primitive is silicon; for SG-X it is the **Linux kernel and host network stack**. The decoupling methodology is therefore identical — isolate the platform-bound code behind a seam, then stub/mock/emulate it.

| Firmware concept | SG-X Guardian analog | Where in this repo |
|------------------|----------------------|--------------------|
| Register-level MMIO (`volatile` pointers) | Kernel netfilter mutation via `nft` subprocess | `src/enforcement/executor.rs:38` |
| Peripheral bus (I2C/SPI/UART) | LAN multicast / mDNS, TCP peer links | `src/p2p_discovery.rs`, `src/attestation_service.rs` |
| Architecture-specific assembly | OS-specific syscalls (`#[cfg(windows)]` console handler) | `src/main.rs:46-66` |
| Vendor HAL / BSP | External tools & libs: `nft` CLI, `libmdns`, systemd | `executor.rs`, `p2p_discovery.rs`, `packaging/` |
| Privileged hardware access | `CAP_NET_ADMIN` for netfilter | required by `nft` apply |
| ISRs / hardware timers | tokio async tasks, signal handlers, periodic loops | `src/main.rs`, `src/attestation_service.rs` |
| Target vs Host dual build | Enforcing backend vs. dry-run/no-op backend | partially present (mock cloud, sim discovery) |
| QEMU/Renode emulation | Linux network namespaces / Docker network as a synthetic LAN | (proposed) |
| USB/JTAG passthrough | Host netns + capability passthrough (`--network host`, `--cap-add`) | (deployment) |

> Convention: tables marked **[FILL]** remain templates; all other tables are **populated from this repo**. Severity: **H** (blocks containerized execution / core-purpose blocker), **M** (abstractable with effort), **L** (cosmetic/portable).

---

## 1. Executive Summary & Objectives

The SG-X Guardian's defining capability — **deterministic L3/L4 enforcement via kernel `nftables`** — is also its hardest containerization constraint, because a container's network namespace is isolated by design while the product exists to manipulate the *host's* firewall and discover peers over *LAN multicast*. Everything else (build, identity, attestation logic, policy verification, telemetry, audit, cloud uplink) containerizes cleanly.

### 1.1 Core Goals

| Goal | Definition | SG-X-specific driver |
|------|-----------|----------------------|
| **Deterministic / reproducible builds** | Same source + image digest ⇒ identical binary | Release packages (`.deb`/`.rpm`) are assembled and GPG-signed by `.github/workflows/release-packages.yml`; the manifest records the binary/package hashes and bounded toolchain provenance. |
| **CI/CD scalability** | Ephemeral agents, no host toolchain drift | Replace per-developer Rust/`protoc` setups; fan out `cargo test` + clippy/audit/deny/semgrep + tarpaulin. |
| **Reduce host/LAN-in-the-loop testing** | Run the 3-node cohort without a physical LAN of privileged hosts | The current demo (`scripts/run_three_nodes.sh`) needs a multicast LAN and real `nft`; move it into reproducible containers. |
| **Decouple from kernel/host primitives** | Daemon runnable in non-privileged / non-enforcing roles | Today `nft`, multicast, and absolute paths are hard requirements; decoupling enables CI and degraded-mode deployment. |
| **Toolchain provenance** | Pinned Rust + `protoc` captured as an image | `build.rs` runs `tonic-build`, requiring `protoc` at build time. |

### 1.2 Explicit Non-Goals (Scope Boundaries)

Containerization **does not** replace:

- **Validation of real host enforcement.** `nft` rules applied in a container's netns do not prove host-wide L3/L4 control. Final enforcement validation requires a real host (or `--network host`).
- **Real multicast/LAN discovery behavior.** Bridge-network mDNS is a simulation, not the deployment medium.
- **The native-package deployment model.** `.deb`/`.rpm` + systemd remains the supported production path for enforcement nodes (see §6.3).

### 1.3 Success Metrics

- Build reproducibility: stable hash of `target/release/sgx_guardian_client` across clean container runs.
- Left-shift ratio: % of `cargo test` + the 3-node cohort runnable with **no privilege** and **no physical LAN**.
- Toolchain restore time: clean checkout → green build in container.
- Enforcement decoupling: daemon boots and passes non-enforcement tests with `nft` absent.
- **Minimal-host footprint**: runtime image runs all roles on the reference host (Ubuntu 26.04 LTS, x86_64, 8 GB RAM) with no build tooling installed (§6.4).

---

## 2. Repository & Toolchain Anatomy (Populated)

Unlike proprietary firmware toolchains, SG-X's toolchain is **fully open and permissively licensed** — there is no FlexLM/dongle/EULA gate. This removes the single biggest firmware blocker.

### 2.1 Toolchain Inventory

| Attribute | Value (from repo) | Notes |
|-----------|-------------------|-------|
| Language / edition | Rust, **edition 2021** (`Cargo.toml`, `sgx-pa-cli/Cargo.toml`) | Workspace with 2 members: root daemon + `sgx-pa-cli`. |
| Compiler | `rustc` stable (CI: `actions-rs/toolchain@v1`, `stable`) | Pin an exact version in the image; CI uses floating `stable`. |
| Build-time codegen | **`protoc`** via `tonic-build` in `build.rs` | Compiles `proto/{peer,policy,ping}.proto`. CI installs `protobuf-compiler`. |
| Native build deps | C compiler (`cc`) for `ring` 0.17 | No OpenSSL — `reqwest` uses `rustls-tls`, `default-features=false` (`Cargo.toml:35`). |
| TLS stack | `rustls` / `tokio-rustls` / `rcgen` (self-signed certs) | Pure-Rust TLS ⇒ slim runtime image, no system TLS libs. |
| Target arch | **amd64 / x86_64 only** in packaging (`packaging/deb/DEBIAN/control`, RPM `ExclusiveArch: x86_64`) | arm64 edge targets would need cross-compile. |

### 2.2 Build System Inventory

| Item | Location | Containerization impact |
|------|----------|-------------------------|
| Cargo workspace | `Cargo.toml` (`members = ["sgx-pa-cli"]`) | Single `cargo build --release` builds the daemon; CLI built separately. |
| Build script | `build.rs` | Must run inside the image; needs `protoc` on `PATH`. |
| Quality gates | `.github/workflows/ci.yml` | clippy `-D warnings`, `cargo fmt --check`, `cargo test`, **tarpaulin** (coverage), **semgrep**, **cargo-audit**, **cargo-deny** (`deny.toml`), CodeQL (`codeql.yml`). All must be reproducible in-container. |
| Packaging | `packaging/deb`, `packaging/rpm`, `build/deb/...` | Pre-built-binary packaging (RPM `%build` is a no-op); GPG signing in CI. |

### 2.3 Host OS Dependency Inventory (Runtime)

- **`nft`** binary (`nftables` package) — invoked via `std::process::Command` (`executor.rs:38`). Absent ⇒ enforcement fails closed.
- `ca-certificates` — for outbound cloud uplink TLS trust.
- glibc (`libc6 >= 2.31` per `.deb`) unless built against musl.
- For the demo script only: `bash`, `jq` (`scripts/run_three_nodes.sh`).

### 2.4 Licensing & Redistribution

| Concern | Finding |
|---------|---------|
| Toolchain license | Rust/Cargo (open), `protoc` (BSD) — freely redistributable in images. |
| Crate licenses | Enforced by `cargo deny` (`deny.toml`). Project license: `Apache-2.0 OR MIT` (`Cargo.toml`). |
| Signing material | Release-only GPG inputs (`RELEASE_GPG_PRIVATE_KEY`, `RELEASE_GPG_PASSPHRASE`, `RELEASE_GPG_FINGERPRINT`) are scoped to the protected `release-signing` environment in `.github/workflows/release-packages.yml`; they are never available to pull-request CI or baked into an image layer. |

> Net: §2.4 — the firmware framework's heaviest gate (proprietary, license-locked toolchains) **does not apply**. This is the single biggest reason SG-X is *easier* to containerize than firmware.

---

## 3. Platform / Kernel Dependency Mapping (The Coupling Audit — Populated)

The deliverable: a Coupling Matrix of every host/kernel/OS touchpoint, with isolation strategy. Categories are the firmware four, re-pointed at the kernel/OS.

### 3.1 Category 1 — Kernel/Syscall-Level Access (the "MMIO" analog)

| Touchpoint | Location | Severity | Why it blocks plain container execution |
|-----------|----------|----------|------------------------------------------|
| `nft -f <ruleset>` subprocess | `src/enforcement/executor.rs:38` | **H** | Mutates kernel `inet` table `sgx_guardian` with `input` hook priority 0, **`policy drop`** (`executor.rs:76-112`). Requires `CAP_NET_ADMIN`; in a bridge netns it firewalls only the container, and default-drop can self-lock the container. |
| Raw multicast UDP bind | `src/p2p_discovery.rs:49-50` (`0.0.0.0:5353-5360`) | **H** | mDNS depends on multicast (224.0.0.251:5353) that does not traverse Docker bridges or reach the LAN. |
| mDNS responder | `src/p2p_discovery.rs:30-36` (`libmdns::Responder`) | **H** | Same multicast constraint; advertises `_sgx-guardian._tcp`. |
| TCP listeners (gRPC, attestation) | `src/server.rs` (50051-3), `src/attestation_service.rs:494` (port+100) | **M** | Bind to config `ip` (`127.0.0.1` in shipped configs) ⇒ unreachable across containers until bound to `0.0.0.0`. |

### 3.2 Category 2 — OS/Architecture-Specific Code (the "assembly" analog)

| Touchpoint | Location | Severity | Isolation |
|-----------|----------|----------|-----------|
| Windows console ctrl handler | `src/main.rs:46-66` (`SetConsoleCtrlHandler`, `#[cfg(windows)]`) | **L** | Already `cfg`-gated; irrelevant in a Linux container. Dependency `windows-sys` (`Cargo.toml:19`) is dead weight on Linux. |
| Windows-specific exit path | `src/main.rs:570-574` (`cfg!(windows)`) | **L** | No-op on Linux target. |
| amd64-only packaging | `packaging/*` | **M** | Cross-arch (arm64) requires explicit cross-compile; see §7 R-Arch. |

### 3.3 Category 3 — External "HAL/BSP" (tools, libraries, init system)

| Touchpoint | Location | Severity | Notes |
|-----------|----------|----------|-------|
| `nft` CLI dependency | `executor.rs` | **H** | The de-facto "vendor driver" — an external binary the image must ship and the kernel must honor. |
| `libmdns` | `Cargo.toml:23`, `p2p_discovery.rs` | **H** | Multicast discovery library; the "peripheral bus driver." |
| systemd unit | `packaging/deb/systemd/sgx-guardian.service` | **M** | Assumes systemd as service manager; **contradicts runtime needs** — `CapabilityBoundingSet=` empty, `IPAddressDeny=any` would block `nft` and all networking (see §7 R-Priv). Not used inside a normal container (no PID 1 systemd). |
| `/tmp` temp ruleset file | `executor.rs:33-36` | **L** | `PrivateTmp=true` in systemd; in containers use a writable tmp. |

### 3.4 Category 4 — Async Tasks, Signals & Timers (the "ISR/timer" analog)

| Touchpoint | Location | Severity | Notes |
|-----------|----------|----------|-------|
| tokio runtime (`features=["full"]`) | `Cargo.toml:12`, `#[tokio::main]` | **L** | Portable; runs fine in-container. |
| `signal::ctrl_c()` graceful shutdown | `src/main.rs:550` | **L** | Maps to SIGINT/SIGTERM; ensure container stop signal handled. |
| Multicast listener loop | `p2p_discovery.rs:65-83` | **H** | Tied to multicast (Category 1). |
| Periodic re-attestation (60s), heartbeat, uptime (30s) | `attestation_service.rs`, `main.rs:539-548`, `cloud/client.rs` | **L** | Time-based async loops; portable. |
| Fixed 20s startup sleep before enforcement | `src/main.rs:475` | **L** | Works but slows container test cycles; candidate to parameterize. |

### 3.5 Filesystem & Namespace Coupling (cross-cutting)

| Path / behavior | Location | Severity | Mount/fix |
|-----------------|----------|----------|-----------|
| `/var/lib/sgx-guardian/sgx-agent/device_<id>.key` (identity, persistent) | `main.rs:75`, `p2p_discovery.rs:38` | **H** | Named volume / PVC. |
| `/var/lib/.../device_<id>_cert.der` (TLS cert) | `main.rs:426-430` | M | Persistent (regenerable). |
| `/etc/sgx-guardian/{nodeA,nodeB,nodeC}.yaml` — **all three loaded by every node**, `.expect` ⇒ panic | `main.rs:120-124` | **H** | Read-only config mount; decouple topology (§4). |
| `/etc/sgx-guardian/schemas/uep_policy_v1.yaml` — `.expect` ⇒ panic | `main.rs:88-92,140` | **H** | Config mount; replace panics. |
| `/etc/sgx-guardian/policies/{policy.sig,backup_policy.yaml}` | `main.rs:358,411` | M | Config mount. |
| `/var/log/sgx-guardian/audit-<id>.log` (tamper-evident chain) | `main.rs:200-203` | M | Persistent volume. |
| **CWD-relative**: `sgx-agent/`, `device_public.der` | `key_manager.rs:26,64` | **H** | Breaks if CWD ≠ repo root; derive from config dir. |
| **CWD-relative**: `config/{nodeA,B,C}.yaml` (sim discovery) | `p2p_discovery.rs:89-93` | M | Same. |
| **CWD-relative**: `logs/` fallback | `main.rs:177,183` | L | Same. |
| `127.0.0.1` binds in shipped configs | `config/nodeA.yaml` | **H** | Peers in other containers can't connect; bind `0.0.0.0`, target by service name. |

---

## 4. Decoupling & Isolation Strategy

Goal: the daemon's logic depends on **abstract platform interfaces**, not directly on `nft`, multicast, or absolute paths — with two backends (enforcing vs. simulated), mirroring firmware's Target-vs-Host build.

### 4.1 The Platform Seam (what to abstract)

Introduce narrow, owned interfaces (Rust **traits**) for the platform-bound capabilities; today these are called inline:

- `Enforcer` — `apply(rules)`; backends: `NftEnforcer` (real `nft`) vs. `DryRunEnforcer` (logs the ruleset, no kernel mutation).
- `Discovery` — `run()`; backends: `MdnsDiscovery` (multicast) vs. `StaticDiscovery` (config peer list — *already partially present* in `p2p_discovery.rs:87-145`).
- `Paths` — config/data/log directories from env (`SGX_CONFIG_DIR`, `SGX_DATA_DIR`, `SGX_LOG_DIR`) with current absolute paths as defaults.

### 4.2 Dual-Target = Enforcing vs. Simulation Backend

The repo **already has the seeds** of a dual-target model:

- A **mock cloud server** gated by `SGX_RUN_MOCK_CLOUD` (`main.rs:220-235`, `cloud/mock_server.rs`).
- A **static-peer "simulation mode"** discovery fallback (`p2p_discovery.rs:87`).
- Env-driven cloud config (`config_loader.rs:86-95`).

Formalize this into a single switch (env or cargo feature) selecting **enforce** vs. **simulate** for the kernel/network seams, so the same binary runs in CI/bridge networks without `CAP_NET_ADMIN`.

### 4.3 Conditional Compilation Without Spaghetti (Rust idioms)

- **Prefer runtime trait objects / dependency injection** over `#[cfg(...)]` scattered through logic. Select the backend once at startup from config/env.
- Use **cargo features** (`--features enforce`) only for compiling out heavy/privileged code paths, confined to module boundaries — not sprinkled in business logic.
- Keep the existing `#[cfg(windows)]` blocks **only** in `main.rs` startup glue (where they already are).
- Add a **no-vendor-call lint**: domain modules (`policy`, `audit`, `attestation` logic) must not call `Command::new`, `libmdns`, or absolute paths directly — only through the seam. Enforce via a grep gate in CI (Appendix A).

### 4.4 Pragmatic Refactor Sequence

1. Introduce `Paths` (env-configurable) — removes every hard-coded absolute + CWD-relative path (highest leverage, lowest risk).
2. Wrap `nft` behind `Enforcer`; add `DryRunEnforcer`; default to dry-run when `nft` is absent or `SGX_ENFORCE=0`.
3. Wrap discovery behind `Discovery`; make static mode first-class (not a "simulation" side-effect).
4. Replace `.expect` on config/schema/policy reads with graceful degradation (no crash-loop on a bad mount).
5. Bind listeners to `0.0.0.0`; resolve peers by hostname/service name.

---

## 5. Emulation, Simulation & Stubbing Framework

Three tiers, mapped to SG-X's kernel/network coupling.

| Tier | Replaces | Mechanism | Use |
|------|----------|-----------|-----|
| **Stub** | `nft`, kernel mutation | `DryRunEnforcer` (log ruleset, no-op) | Build/boot validation, CI without privilege; coupling detector |
| **Mock** | Cloud, peers | `cloud/mock_server.rs` (exists), static peer list, mock attestation responders | Functional/integration tests of uplink + trust logic |
| **Emulate** | Host network + netfilter | **Linux network namespaces / Docker network** as a synthetic LAN; run real `nft` inside an isolated netns | Full 3-node cohort + real enforcement, safely isolated |

### 5.1 Stubbing (build/CI without privilege)

- `DryRunEnforcer` satisfies the `Enforcer` seam and logs the generated ruleset (reuse `build_nft_ruleset` from `executor.rs:76`). The daemon boots, forms trust, verifies policy, and exercises everything *except* the kernel write.
- Coupling detector: if a module can't run without real `nft`/multicast, it has leaked through the seam — treat as an audit finding.

### 5.2 Mocking (functional tests)

- **Already present**: `cloud/mock_server.rs` + `SGX_RUN_MOCK_CLOUD` lets the uplink path be tested end-to-end with no external service.
- Static `Discovery` + in-process attestation responders let the trust handshake be tested deterministically (no multicast).
- Rust unit/integration tests already cover policy, audit, TLS, config (`tests/*.rs`); run them in the container's host build with no privilege.

### 5.3 "Emulation" — Network Namespaces as the Synthetic LAN

The SG-X analog of QEMU/Renode is the **Linux networking stack itself, namespaced**:

| Need | Mechanism | Container plumbing |
|------|-----------|--------------------|
| Isolated firewall sandbox | Run `nft` inside a dedicated **network namespace** (per-container netns, or `ip netns`) | Real enforcement executes without touching the host; default-drop is contained. |
| Synthetic multi-node LAN | Docker user-defined **bridge network** with one container per node | Containers reach each other by service name (replaces `127.0.0.1` binds). |
| Multicast/mDNS fidelity | Bridge multicast is unreliable ⇒ use **static `Discovery`**; or `--network host` for a real multicast test | Map "the bus" to the Docker network; accept the fidelity gap (§7). |
| Cross-node trust + enforcement together | `docker compose` 3-node cohort, each with its own data/log volume; `--cap-add NET_ADMIN` per node when exercising real `nft` | Reproduces `scripts/run_three_nodes.sh` without a physical LAN. |
| Deterministic time | Parameterize the 20s startup sleep (`main.rs:475`) and 30/60s loops via env for fast CI | Avoids minute-scale test runs. |

Design rule (mirrors firmware "expose every bus as a socket/file"): **expose every node interface on the Docker network and back persistent state with named volumes** — keep it headless and scriptable, no host LAN required.

---

## 6. Container Design & Architecture

### 6.1 Multi-Stage Build (build env vs. runtime/sim env)

```dockerfile
# ---- Stage 1: builder (heavy: Rust + protoc) ----
FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --bin sgx_guardian_client

# ---- Stage 2: test (host build, no privilege; runs cargo test) ----
FROM builder AS test
RUN cargo test --release --workspace

# ---- Stage 3: runtime (slim; ships nft for enforcement nodes) ----
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/sgx_guardian_client /usr/bin/sgx-guardian
# Config + state provided via mounts (see §3.5 / compose)
ENTRYPOINT ["/usr/bin/sgx-guardian"]
CMD ["nodeA"]
```

Reproducibility: pin bases by digest, set `SOURCE_DATE_EPOCH`, strip paths (`-C ... --remap-path-prefix`), hash the binary, emit an SBOM. (See `./Containerization_Assessment.md §9` for the compose 3-node cohort.)

### 6.2 The "Passthrough" Analog — Privilege & Namespace Passing

Firmware needs `--device` for JTAG/serial; SG-X needs **kernel-capability and namespace passing** to do real enforcement:

| Need | Mechanism | Notes |
|------|-----------|-------|
| Apply `nft` rules in-container | `--cap-add NET_ADMIN` (sometimes `NET_RAW`) | Floor for any real enforcement; default containers lack it. |
| Enforce **host** traffic (not just container) | `--network host` (K8s `hostNetwork: true`) | Shares the host netns — gives real control but discards isolation. |
| Real multicast discovery | `--network host` | Bridge multicast won't reach the LAN. |
| Broad kernel access (last resort) | `--privileged` | Avoid unless `nft` needs more than `NET_ADMIN`; document why. |
| Safe enforcement testing | per-container netns + `NET_ADMIN`, **no** `--network host` | Rules affect only the container — the recommended CI posture. |

### 6.3 Deployment Topology Decision

- **Build / CI / unit + mock tests** → unprivileged container (Stage 1–2). No `nft`, no multicast.
- **3-node integration cohort** → compose, per-container netns, `NET_ADMIN`, static discovery. Real `nft`, isolated.
- **Production enforcement node** → either `--network host` + `NET_ADMIN` container (DaemonSet in K8s) **or** keep the **`.deb`/`.rpm` + systemd** native install (recommended primary path, aligned with the product's host-enforcement model).

### 6.4 Target Host Environment & Minimum Requirements

**Design target:** the runtime image must run on a *minimal* host — reference spec **Ubuntu 26.04 LTS, x86_64, 8 GB RAM**. The multi-stage build (§6.1) is what makes this achievable: the Rust toolchain and `protoc` live only in the *builder* stage, so the **deployment host needs no Rust, no `protoc`, no build tooling** — only a container runtime, the shared kernel's netfilter, and (for enforcement) `CAP_NET_ADMIN`. Build heavy, run light.

| Resource | Minimum (runtime) | Reference / recommended | Notes |
|----------|-------------------|-------------------------|-------|
| **Host OS** | Linux, kernel ≥ 5.10 with `nf_tables` | **Ubuntu 26.04 LTS** (kernel 6.x) | Container shares the **host** kernel; that kernel must provide `nf_tables`/`nft_chain_filter` (built-in on Ubuntu/Debian/RHEL 9+). Also OK: Debian 12+, RHEL/Rocky 9+. |
| **Architecture** | x86_64 / amd64 | x86_64 | Matches packaging (`ExclusiveArch: x86_64`). arm64 edge hosts need a cross-built image — see §7 R-Arch. |
| **CPU** | 1 vCPU | 2 vCPU | Runtime is light (async tokio daemon, mostly idle between heartbeats/attestation). |
| **RAM (runtime)** | ~256 MB for a single node | well within **8 GB** | Per-node resident set is tens of MB; the full 3-node compose cohort fits comfortably in < 1 GB, leaving 8 GB host headroom for the runtime + OS + observability. |
| **RAM (build, if on-host)** | ~4 GB | 8 GB+ | A release `cargo build` (tonic/tokio) peaks ~2–4 GB. **Recommendation: build in CI, ship the image** — then the 8 GB host never pays the build cost. If building on the 8 GB host, cap `CARGO_BUILD_JOBS`/`-j` to avoid OOM. |
| **Disk** | ~1 GB | few GB | Runtime image ≈ 80–150 MB (`debian:slim` + `nftables` + binary). Plus volumes for the identity key (tiny) and the **append-only audit log** (grows over time — plan rotation/retention). |
| **Container runtime** | Docker Engine ≥ 24 **or** Podman ≥ 4 | Docker/Podman from Ubuntu 26.04 repos | cgroups v2 (default since Ubuntu 22.04). |
| **Kernel features** | network namespaces (always present); `nf_tables` modules | + ability to grant `CAP_NET_ADMIN` | Required only for **enforcement** roles; build/unit/mock roles need none. |

**Privilege footprint by role** (set the host expectation accordingly):

| Role on the host | Privilege needed | Fits the 8 GB / Ubuntu 26.04 target? |
|------------------|------------------|--------------------------------------|
| Build / unit + mock tests | none (unprivileged) | Yes — trivially |
| Synthetic-LAN 3-node cohort (dev) | `--cap-add NET_ADMIN` per node, isolated netns | Yes — full cohort < 1 GB RAM |
| Production enforcement node | `--network host` + `NET_ADMIN` | Yes — single lightweight container; host kernel does the work |

> Bottom line: an Ubuntu 26.04 LTS / 8 GB / x86_64 host is **more than sufficient** for any runtime role, including the full dev cohort. The only resource-heavy activity is *compilation*, which the multi-stage design keeps off the deployment host. Confirm the host **kernel** ships `nf_tables` (Ubuntu 26.04 does) — that, not RAM, is the real enforcement prerequisite.

---

## 7. Risk Assessment & Limitations Matrix (Populated)

L/I = Likelihood/Impact (H/M/L). Firmware-only risks (cycle timing, FPU, silicon errata) are **N/A** and omitted.

| # | Risk domain | Specific failure mode (this repo) | L | I | Mitigation |
|---|-------------|-----------------------------------|---|---|------------|
| R-NS | **Namespace scope** | `nft` rules apply to the container netns, not the host/LAN ⇒ "enforcement works" in CI but proves nothing about host control (`executor.rs`) | H | H | Only validate real enforcement with `--network host` or on a native node; mark CI enforcement tests "container-scope only." |
| R-MC | **Multicast fidelity** | mDNS/multicast doesn't traverse Docker bridges; `p2p_discovery` finds no peers (`p2p_discovery.rs:49`) | H | M | Use static `Discovery` for bridge cohorts; reserve multicast tests for `--network host`. |
| R-Priv | **Privilege vs. isolation** | Real enforcement needs `NET_ADMIN`/`--network host`, negating container isolation; systemd unit's `CapabilityBoundingSet=`/`IPAddressDeny=any` contradicts this (`packaging/.../sgx-guardian.service`) | H | H | Decide posture explicitly per §6.3; reconcile the systemd hardening profile with actual `nft`/network needs. |
| R-Lock | **Self-lockout** | Default-drop `input` chain can cut the container's own gRPC/metrics/attestation traffic (`executor.rs:76-100` only allow-lists 22/5353/50051-3) | M | H | Ensure allow-list covers metrics + attestation (5015x) ports; test in isolated netns first. |
| R-Path | **Filesystem coupling** | Hard-coded absolute + CWD-relative paths panic or misbehave if not mounted exactly (`main.rs`, `key_manager.rs:26`) | H | M | Implement `Paths` env config (§4.4-1); replace `.expect` with graceful handling. |
| R-Bind | **Loopback binds** | Services bind `127.0.0.1` ⇒ cross-container unreachable (`config/nodeA.yaml`) | H | M | Bind `0.0.0.0`; resolve peers by service name. |
| R-Topo | **Hard-coded 3-node topology** | Every node loads all of nodeA/B/C and matches its ID by string; only `nodeA/B/C` accepted (`main.rs:313-322`) | M | M | Decouple to "own config + peer list" (§4.4-3). |
| R-Arch | **Single architecture** | amd64/x86_64 only (`packaging/*`) | M | M | Add arm64 cross-build if edge hardware requires it. |
| R-Libc | **glibc vs musl** | glibc base needed unless static-musl; but `nft` still required so `scratch` is impossible | L | L | Use `debian:slim` + `nftables`; musl optional and doesn't remove the `nft` dependency. |
| R-Host | **Host kernel netfilter** | Container shares the host kernel; if that kernel lacks `nf_tables`, enforcement fails regardless of image contents (§6.4) | L | H | Require kernel ≥ 5.10 with `nf_tables` (Ubuntu 26.04 LTS satisfies this); verify with `nft list ruleset` on the host before deploying enforcement roles. |
| R-Time | **Slow test cycles** | Fixed 20s startup sleep + 30/60s loops (`main.rs:475`) inflate CI runtime | M | L | Parameterize delays via env for test profiles. |
| R-Sec | **Signing secrets** | GPG key in CI (`ci.yml`) must not leak into image layers | L | H | Inject as masked secret; never `COPY` into an image. |

> Rule of thumb: containers/sim answer **"is the trust/policy/audit logic correct?"** A real host (or `--network host`) answers **"does enforcement actually control this machine's traffic?"** Keep the matrix honest about which question each test answers.

---

## 8. Actionable Migration Roadmap

Four phases with entry/exit gates; each delivers standalone value.

### Phase 1 — Containerized Toolchain (Build + Test, unprivileged)

- Author the `builder` + `test` stages (§6.1); pin Rust + `protoc`.
- Reproduce the release binary; achieve a **stable hash** across clean runs; emit SBOM.
- Run the full quality gate in-container (clippy/fmt/test/tarpaulin/audit/deny/semgrep) — already defined in `ci.yml`.

**Exit**: green, reproducible build + `cargo test` in CI from a clean container; no developer-host builds in the release path.
**Risks addressed**: R-Sec, R-Libc, reproducibility.

### Phase 2 — Path & Enforcement Decoupling (host build runs anywhere)

- Implement `Paths` env config (§4.4-1); remove absolute/CWD-relative coupling.
- Introduce the `Enforcer` seam + `DryRunEnforcer`; default to dry-run when `nft` absent / `SGX_ENFORCE=0`.
- Replace `.expect` panics; bind `0.0.0.0`.

**Exit**: a single unprivileged container boots, forms trust (static discovery), verifies policy, logs the would-be ruleset, with **no `nft` and no multicast**.
**Risks addressed**: R-Path, R-Bind, R-Lock (test-side), R-NS (CI clarity).

### Phase 3 — Synthetic-LAN Cohort (network-namespace "emulation")

- Stand up the `docker compose` 3-node cohort on a user-defined bridge; per-container netns; named volumes for identity/audit.
- Promote static `Discovery` to first-class; decouple the hard-coded topology (§4.4-3).
- Add an opt-in enforcement profile (`--cap-add NET_ADMIN`, isolated netns) running **real `nft`** safely.

**Exit**: `run_three_nodes.sh`-equivalent demo passes in containers with no physical LAN; real-`nft` enforcement verified in isolated netns.
**Risks addressed**: R-MC, R-Topo, R-Time, R-NS (managed/visible).

### Phase 4 — Full CI/CD Pipeline

- Orchestrate: lint/SAST → cross-build → unit+mock tests → synthetic-LAN integration → **optional host-network enforcement check on a self-hosted runner** → package + GPG-sign + SBOM + release.
- Parallelize build/test; serialize and resource-lock the privileged/host-network stage (exclusive host access).

**Exit**: commit → signed, reproducible, test-gated artifacts; privileged/host enforcement runs only the subset containers can't prove (R-NS, R-Priv per §7).
**Risks addressed**: R-Priv, R-Arch (matrix), end-to-end provenance.

---

## Appendix A — Coupling-Scan Patterns (repo-specific)

- Kernel/process coupling: `Command::new`, `"nft"`, `std::process`
- Multicast/discovery: `libmdns`, `Responder`, `5353`, `UdpSocket::bind`
- OS-specific: `cfg\(windows\)`, `windows_sys`, `SetConsoleCtrlHandler`
- Path coupling (absolute): `/etc/sgx-guardian`, `/var/lib/sgx-guardian`, `/var/log/sgx-guardian`
- Path coupling (CWD-relative): `"sgx-agent`, `"config/node`, `"logs`
- Crash-on-missing: `\.expect\(`, `\.unwrap\(\)` in startup paths
- Loopback binds: `127\.0\.0\.1`, `ip:\s*"127`

## Appendix B — Coupling Matrix (Populated Extract)

| ID | File:Line | Symbol/Call | Category | Severity | Isolation approach | Status |
|----|-----------|-------------|----------|----------|--------------------|--------|
| C-001 | `enforcement/executor.rs:38` | `Command::new("nft")` | Kernel/MMIO | H | `Enforcer` trait + `DryRunEnforcer` | open |
| C-002 | `p2p_discovery.rs:30-50` | `libmdns::Responder`, UDP 5353 | Bus/HAL | H | `Discovery` trait + static mode | partial (sim exists) |
| C-003 | `attestation_service.rs:494` | `TcpListener::bind(ip:port+100)` | Net listener | M | bind `0.0.0.0` | open |
| C-004 | `main.rs:120-124` | load all 3 node configs (`.expect`) | Topology/FS | H | own-config + peer list | open |
| C-005 | `key_manager.rs:26,64` | CWD `sgx-agent/` writes | Filesystem | H | `Paths` env config | open |
| C-006 | `main.rs:46-66` | `SetConsoleCtrlHandler` (`cfg(windows)`) | OS-specific | L | already gated; drop on Linux | n/a |
| C-007 | `cloud/mock_server.rs` + `SGX_RUN_MOCK_CLOUD` | mock cloud | Sim seam | L | promote to formal mock backend | present |

## Appendix C — Capability / Privilege Requirement Registry (replaces "peripheral fidelity")

| Capability | Required for | Container mechanism | Validated where |
|-----------|--------------|---------------------|-----------------|
| `CAP_NET_ADMIN` | `nft` apply | `--cap-add NET_ADMIN` | isolated netns (CI) + host (prod) |
| Host network namespace | host-wide enforcement, real multicast | `--network host` / `hostNetwork` | self-hosted runner / native node only |
| Multicast | mDNS discovery | `--network host` or static fallback | host net; bridge = static only |
| Persistent volume | identity key, audit log | named volume / PVC | all profiles |

## Appendix D — "Where Does This Get Validated?" Decision Aid

| Question | Right layer |
|----------|-------------|
| Is policy verification / atomic load / rollback correct? | Unprivileged container `cargo test` (Phase 1) |
| Is the trust handshake / attestation / mTLS logic correct? | Mock + static-discovery container (Phase 2) |
| Does the cohort form and sync over a network? | Synthetic-LAN compose cohort (Phase 3) |
| Does `nft` produce the right ruleset? | Dry-run (any container) / real `nft` in isolated netns (Phase 3) |
| Does enforcement actually control **this host's** traffic? | **`--network host` container or native node only** |
| Does real **multicast** discovery work on the LAN? | **`--network host` / native node only** |
| Is the released binary reproducible & signed? | Containerized build + CI (Phase 1/4) |
