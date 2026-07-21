# SG-X Guardian — Binary Compatibility: Requirements Confirmation

**Status**: Engineering recommendations — for stakeholder confirmation
**Scope**: Build, packaging, and distribution of `sgx_guardian_client` (+ `sgx-pa-cli`)
**Companion docs**: `./Containerization_Assessment.md`, `./Technical_Assessment_Framework_Containerizing_SGX_Guardian.md`
**Date**: 2026-07-09 — rev B (adds §0.2 dev-team Q&A and the Yocto-branch decision D-6); supersedes 2026-07-08

---

## 0. How to Read This Document

This responds to the 10 numbered requirement questions. For **each** question it
gives:

- **Recommended answer** — the option we recommend (bolded).
- **Basis** — one of:
  - **Code-dictated** — the codebase / product nature already forces this answer;
    we're confirming, not choosing.
  - **Engineering recommendation** — a genuine choice; we recommend one option and
    say why, but it needs **your sign-off**.
- **Rationale & caveats** — evidence (with `file:line`) and anything the answer
  depends on.

The single fact that ties most answers together: **the production Guardian boards
appear to be embedded ARM64 devices** — signalled by the board running **Yocto**
(an embedded-Linux build system, not a desktop distro — *Mickledore* today, with
*Scarthgap* proposed) and the *SE050 secure element* in the questions. That one fact drives Q1, Q2, Q3, Q5, Q7, Q8, and Q9. **If the
boards are actually x86_64, several answers change** — so please confirm the board
architecture first (it's the top open decision in §11).

---

## 0.1 Answers at a Glance

| # | Question | Recommended answer | Basis |
| - | -------- | ------------------ | ----- |
| 1 | CPU architecture | **Both** — AMD64 (dev/server/container) + ARM64 (production boards) | Recommendation (confirm boards = ARM64) |
| 2 | OS support | **Ubuntu 22.04+ & Debian 12+ (.deb); Yocto Scarthgap LTS on boards (currently Mickledore/EOL — recommend upgrade); Windows = dev-only** | Code-dictated (Linux-only enforcement) |
| 3 | Release packaging | **One release package containing platform-specific binaries** | Code-dictated (a single universal binary is infeasible) |
| 4 | Reproducible + single locked dep set | **Yes** | Code-dictated (single `Cargo.lock` already committed) |
| 5 | Shared version + auto-detect installer | **Yes** — shared version; installer for Ubuntu/Debian; boards provisioned via Yocto image | Recommendation |
| 6 | Official Docker images | **Yes** — for dev/demo/CI/cloud; not the board path | Recommendation |
| 7 | Boards run native under systemd (not Docker) | **Yes** | Code-dictated (host enforcement + SE050 + embedded) |
| 8 | SE050 mandatory for production boards | **Required** (Phase 2 delivery; hardware-dependent) | Recommendation (security decision — confirm) |
| 9 | Software keys = dev/demo/Docker only; prod = SE050 | **Yes** | Recommendation (corollary of Q8) |
| 10 | Acceptance criteria | **Confirmed set — see §10 / §11 checklist** | — |

> Legend on current state: ✅ already in the repo · ⚠️ partially present / needs
> work · ❌ not present yet.

---

## 0.2 Dev-Team Questions — Direct Answers

The seven questions engineering raised against this document, answered in their own
numbering. Each points to the fuller section. Legend: ✅ code-dictated / settled ·
⚠️ engineering answer given, still needs a stakeholder sign-off.

| # | Dev-team question | Direct answer | Detail | Sign-off? |
|---|-------------------|---------------|--------|-----------|
| 1 | Is the production board CPU **ARM64/AArch64**? | **Yes — production boards are ARM64/AArch64.** AMD64 stays for dev, servers, the NUC, and containers. | §1 | ⚠️ Hardware fact — confirm (D-1) |
| 2 | Board OS — **Scarthgap** or the current **Mickledore**? | **Move to Yocto Scarthgap (5.0 LTS).** Mickledore (4.2) is **non-LTS and already end-of-life** — no upstream security backports, which is unacceptable under a security-enforcement product. | §2 | ⚠️ Confirm + verify vendor BSP (D-6) |
| 3 | Which host OSes — **Ubuntu 22.04+, Debian 12+, RHEL/Rocky**? | **Yes: Ubuntu 22.04+ and Debian 12+ are required (`.deb`).** RHEL/Rocky/Fedora 9+ (`.rpm`) already builds — official vs. dev-only is your call. Windows is dev-only. | §2 | ⚠️ RHEL scope (D-3) |
| 4 | Does **"one binary"** mean one release package with per-platform binaries (AMD64 for NUC/server, ARM64 for board)? | **Yes, exactly.** A single universal binary is infeasible across arch/libc; ship **one immutable, versioned release** that bundles the per-platform artifacts. | §3 | ✅ Code-dictated |
| 5 | Should the board run SG-X Guardian as a **native systemd service** (not Docker)? | **Yes — native, systemd-managed, on the boards.** | §7 | ✅ Code-dictated |
| 6 | Are **software keys** allowed only for Docker/demo/dev? | **Yes.** Software keys = dev/demo/CI/Docker only; production boards use **SE050-backed keys and fail closed** (no silent software fallback). | §9, §8 | ⚠️ Corollary of SE050 (D-2) |
| 7 | Docker scope — **dev/demo/CI only, or an official deliverable**? | **Both: an official, supported deliverable — but scoped to dev/demo/CI/cloud, never the production board path.** | §6 | ✅ Recommendation |

---

## 1. CPU Architecture Support — **Both (AMD64 + ARM64)**

**Basis: Engineering recommendation (confirm board arch).**

- **AMD64 / x86_64** — required. It is what the project builds today: `.deb`
  `Architecture: amd64` (`packaging/deb/DEBIAN/control:5`), `.rpm`
  `ExclusiveArch: x86_64` (`packaging/rpm/SPECS/sgx-guardian-client.spec:10`).
  Serves developers, CI, servers/VMs, and the Docker images (Q6).
- **ARM64 / AArch64** — required **for the production Guardian boards.** Yocto
  Scarthgap (Q2) and the SE050 secure element (Q8) are hallmarks of an **embedded
  ARM64** device, not an x86 server. The architecture doc *already advertises*
  "x86_64 or ARM64" (`docs/architecture/README.md:1149`) and the decision log
  lists multi-arch as a CI goal
  (`docs/decisions/phase-1-sow-decision-log.md:871`) — but
  **nothing in packaging produces ARM64 today.** That gap is exactly what this
  work item must close.

**Net:** **Both.** AMD64 for dev/server/container roles; ARM64 (cross-compiled)
for the embedded boards.

> ⚠️ Current state: AMD64-only is built; ARM64 is promised in docs but not
> produced. **If the boards are confirmed x86_64, downgrade this to AMD64-only**
> and remove the ARM64 promise from the architecture doc.

---

## 2. Operating System Support — **Ubuntu 22.04+ & Debian 12+; Yocto Scarthgap for boards; Windows dev-only**

**Basis: Code-dictated.** The production daemon's core function is **host L3/L4
enforcement via kernel `nftables`/`nft`**, which is **Linux-only**
(`Containerization_Assessment.md §5.1`). This bounds the answer:

| Option | Verdict | Notes |
|--------|---------|-------|
| **Ubuntu 20.04+** | Supported as the **glibc floor** | The `.deb` already depends on `libc6 >= 2.31` (`control:7`) — exactly Ubuntu 20.04's glibc. Works, but 20.04 EOLs Apr 2025 (standard); prefer 22.04+ as the stated minimum. |
| **Ubuntu 22.04+** | ✅ **Required (recommended minimum)** | Primary server/dev target; cgroups v2, modern kernel with `nf_tables`. |
| **Debian 12+** | ✅ **Required** | Same `.deb` artifact family; kernel ships `nf_tables`. |
| **Yocto — boards** | ✅ **Required — production boards; target Scarthgap (5.0 LTS)** | Not a package-install target: the binary is **cross-compiled to aarch64 and integrated via a bitbake recipe (`.bb`)** into the board image; SE050 support pulls in NXP's Plug & Trust middleware. Kernel config must enable `nf_tables`. **Branch:** the board runs **Mickledore (4.2) today, which is non-LTS and already end-of-life** (no upstream CVE backports) — **recommend moving to Scarthgap (5.0 LTS**, maintained to ~2028**)**. If the board/SoC vendor BSP predates Scarthgap, fall back to **Kirkstone (4.0 LTS)** — **not** Mickledore. See D-6. |
| **Windows** | ❌ **Dev-only, not production** | The Windows code (`src/main.rs:46-66`) is console-ctrl-handler glue behind `#[cfg(windows)]`; it **cannot enforce** (no `nftables`). Fine for developer builds/tests; not a deployment target. |
| **Other** | RHEL/Rocky/Fedora 9+ **available now** | An `.rpm` spec already exists (`packaging/rpm/...`), so the RHEL family is essentially free if you want it in scope. Please confirm. |

> **Confirm:** (a) minimum Ubuntu = 22.04 (with 20.04 as glibc floor, or drop it);
> (b) whether the RHEL/Rocky `.rpm` family is officially in scope or dev-only;
> (c) the target Yocto branch for boards — **Scarthgap (5.0 LTS)** recommended over
> the current **Mickledore (4.2, EOL)** (D-6).

---

## 3. Release Packaging — **One release package with platform-specific binaries**

**Basis: Code-dictated.** "A single universal binary for all platforms" is **not
technically feasible** — a Rust binary is per-architecture (an aarch64 binary
cannot run on x86_64), and libc differs across targets (glibc on Ubuntu/Debian vs.
the board's Yocto sysroot). So:

- ❌ **Single universal binary** — infeasible across arch/libc boundaries.
- ✅ **One release, platform-specific binaries** — **recommended.** One immutable,
  versioned release (e.g. `v1.1.0`) that gathers *every* artifact — amd64 `.deb`,
  amd64 `.rpm`, aarch64 board binary/recipe output, container manifest — each with
  its SHA256 + detached signature + a shared SBOM.
- ❌ **Separate releases per platform** — avoid; it fragments the version story
  and makes provenance/verification harder.

This is also what the CI already leans toward: it uploads a per-run artifact
bundle and GPG-signs the packages (`ci.yml:94-121`) — it just isn't yet gathered
under one versioned, multi-platform release.

---

## 4. Linux Build Requirements — **Yes (reproducible, single locked dep set)**

**Basis: Code-dictated / already partly true.**

- ✅ A **single workspace `Cargo.lock` is already committed** at the repo root — the
  dependency graph is locked and shared by all Linux targets (native and
  cross-compiled). Cross-compiling to aarch64 uses the *same* lockfile, so behavior
  stays consistent across architectures.
- ⚠️ To make builds actually **reproducible** (not just locked), add the hardening
  called out in `…Framework… §6.1`, which is **not yet configured**:
  - Enforce the lock in CI with `cargo build --locked` (today CI runs plain
    `cargo build --release`, `ci.yml:82`).
  - **Pin the toolchain** — add a `rust-toolchain.toml` and pin `protoc`; CI
    currently floats `toolchain: stable` (`ci.yml:22`), which allows silent
    compiler drift.
  - `SOURCE_DATE_EPOCH`, `--remap-path-prefix`, pinned base-image digests, binary
    hashing, and a published **SBOM** for bit-for-bit reproducibility of the
    release binary.

**Answer: Yes** — one locked dep set for all Linux binaries, with reproducibility
hardened to at least "pinned toolchain + `--locked`" and ideally bit-for-bit for
the signed release artifact.

---

## 5. Versioning & Installer — **Yes (shared version; auto-detect installer)**

**Basis: Engineering recommendation.**

- **Shared version number: yes, unconditionally.** All artifacts must carry **one
  version string, single-sourced from `Cargo.toml`** — no drift between the crate
  version, `.deb` `Version:` (`control:2`), `.rpm` `Version:` (`.spec:2`), and the
  image tag. (They're independently hard-coded today and must be unified.)
- **Single auto-detecting installer: yes, with one important nuance.** An
  `install.sh` that detects **OS + CPU arch**, selects the matching **signed**
  artifact, **verifies its signature/checksum before installing**, installs it,
  and enables the systemd service is a good convenience layer — **for the
  Ubuntu/Debian (and optionally RHEL) hosts.**
  - **Nuance:** the **Yocto board is not installed via a script at runtime** — the
    binary is baked into the board image at **build time** via the bitbake recipe.
    So "auto-detect installer" applies to the general-purpose Linux hosts; the
    boards are provisioned by image build. The installer should detect a board/
    Yocto target and cleanly say "provisioned via image, not this installer" rather
    than pretend to install.
  - **Security:** the installer must **not** bypass signature verification or fetch
    over an unverified channel (installers are a supply-chain surface).

**Answer: Yes** — shared version everywhere; auto-detect installer for host
Linux, image-build provisioning for boards.

---

## 6. Container Support — **Yes (official Docker images)**

**Basis: Engineering recommendation.**

- ✅ Provide **official multi-arch Docker images** (`linux/amd64` [+ `linux/arm64`
  per Q1]), built with the multi-stage Dockerfile proposed in `…Framework… §6.1`,
  pinned by digest, same version tag as the packages, shipping `nftables` +
  `ca-certificates`, with an SBOM.
- ❌ **Current state:** **no Dockerfile or compose file exists in the repo yet** —
  both companion docs only *propose* them. This is net-new work.
- **Positioning (important honesty clause):** images are for **developers, CI, the
  3-node demo cohort, and any cloud-side/non-board deployment** — **not** the
  production board path (that's native, Q7). Real host enforcement from a container
  still requires `--network host` + `CAP_NET_ADMIN`, which trades away isolation
  (`Containerization_Assessment.md §7`); that's a deployment-posture decision, not
  something the image alone provides.

**Answer: Yes**, with images scoped to dev/test/cloud roles, boards run native.

---

## 7. Production on Guardian Boards — **Yes (native app under systemd, not Docker)**

**Basis: Code-dictated.** Native + systemd is the right production model on the
boards, for four converging reasons:

1. The product does **host-level** firewalling; a native process on the board
   enforces the board's real traffic directly, with no container netns indirection
   (`Containerization_Assessment.md §5.1`, §7).
2. ✅ **systemd integration already exists** — a unit ships in both packages
   (`packaging/{deb,rpm}/systemd/sgx-guardian.service`) with maintainer scripts.
3. **SE050 access** (Q8) is cleaner for a native process talking to the board's
   secure element than through container device passthrough.
4. Yocto/embedded boards run systemd as PID 1 and integrate services via units —
   Docker-on-board adds overhead and complexity for no benefit here.

> ⚠️ **One defect to fix as part of "systemd integration works":** the shipped unit
> is **over-hardened to the point of being non-functional** — empty
> `CapabilityBoundingSet=`/`AmbientCapabilities=` and `IPAddressDeny=any` would
> **block the `CAP_NET_ADMIN` that `nft` needs and block networking**
> (`Containerization_Assessment.md §7`, `…Framework… §7 R-Priv`). Acceptance must
> mean *the daemon actually runs and enforces under the unit*, not merely that a
> unit file is present.

**Answer: Yes** — native, systemd-managed, on the boards.

---

## 8. Hardware-Backed Identity (SE050) — **Required for production boards (Phase 2)**

**Basis: Engineering recommendation — this is a security/product decision; please
confirm.**

- **Recommended: Required** for production boards. Hardware-backed identity is the
  entire point of a secure element — the private key is generated inside the chip
  and **never leaves it**, giving tamper-resistant identity and a hardware root of
  trust. The **Phase 2 SOW already frames this as a core value proposition** —
  "HSM integration / secure element chips for tamper-resistant key storage and
  hardware attestation" (`docs/sow/phase-2/README.md:12,25`).
- **Reality check on scope & timing:**
  - ❌ **Not implemented today** — identity is a **software ECDSA P-256 key on
    disk** (`/var/lib/sgx-guardian/sgx-agent/device_<id>.key`,
    `Containerization_Assessment.md §5.3`). The string "SE050" does not appear in
    the repo.
  - It is **Phase 2** and **hardware-dependent**: it can only be validated on the
    physical boards with the NXP SE05x middleware — it **cannot** be tested in CI
    or containers. It is therefore a **separate deliverable from binary
    compatibility**; the only build-compat obligation is *supporting the board's
    architecture* (Q1) and optionally a **cargo feature flag** (e.g.
    `--features se050`) so the secure-element backend compiles only for board
    builds.

**Answer: Required for production boards**, delivered in Phase 2, tracked with its
own hardware-based acceptance (key generated in-element, never exported,
attestation uses the SE050). **Confirm this is a hard requirement vs. "Optional."**

---

## 9. Software-Based Keys — **Yes (dev/demo/Docker only; production = SE050)**

**Basis: Engineering recommendation — direct corollary of Q8.**

- **Yes.** The current software key path (on-disk ECDSA P-256) is the correct fit
  for **development, demonstration, CI, and Docker** environments, where no secure
  element exists. **Production boards must use SE050-backed keys.**
- This maps cleanly onto the "dual-backend" seam the assessment already recommends
  (`…Framework… §4`): a `KeyStore`/identity trait with a **software backend**
  (dev/demo/container) and an **SE050 backend** (production boards), selected at
  startup — mirroring the existing enforce-vs-simulate pattern.
- **Guard-rail to add:** production board builds should **refuse to fall back to
  software keys** (fail closed), so a misprovisioned board can't silently run with
  a software identity. That check is part of the SE050 (Phase 2) acceptance.

**Answer: Yes.**

---

## 10. Acceptance Criteria for Binary Compatibility — **Confirmed set**

Confirming the proposed deliverables, each mapped to the question that drives it
and its current state:

| Deliverable | In scope? | Drives from | Current state |
|-------------|-----------|-------------|---------------|
| **Native binaries for all required CPU arch + OSes** | ✅ **Core** | Q1, Q2 | ⚠️ amd64 only; aarch64/Yocto to add |
| **Versioned release package with all platforms' binaries** | ✅ **Core** | Q3, Q5 | ⚠️ per-run bundle exists; not one versioned multi-platform release |
| **Native production binary with systemd integration** | ✅ **Core** | Q7 | ✅ unit ships; ⚠️ hardening profile must be fixed to function |
| **Reproducible builds using a locked dependency set** | ✅ **Core** | Q4 | ⚠️ `Cargo.lock` ✅; toolchain unpinned, no `--locked`, no SBOM |
| **Release documentation & install instructions** | ✅ **Core** | Q2, Q5 | ❌ to write (see §11) |
| **Multi-architecture Docker images** | ✅ **Core if arch>1 / containers shipped** | Q1, Q6 | ❌ no Dockerfile yet |
| **Universal installer with auto platform detection** | ✅ **Convenience wrapper** | Q5 | ❌ none (existing `install_layout.sh` is a dpkg helper, not this) |
| **SE050 hardware-backed identity on production boards** | ⏭ **Phase 2 / separate** | Q8, Q9 | ❌ not implemented; software keys today |

---

## 11. Consolidated Definition of Done (Acceptance Checklist)

"Binary Compatibility" is **delivered** when, for the confirmed support matrix:

- [ ] **Support matrix agreed** (Q1 arch × Q2 OS) and the architecture doc no
      longer promises platforms we don't build.
- [ ] For **each matrix row**: native `sgx_guardian_client` + `sgx-pa-cli` binary
      and its distribution artifact (`.deb`/`.rpm`, or Yocto recipe output for the
      board) are **produced in CI**.
- [ ] Each host artifact **installs on a clean reference OS and the daemon starts**
      (boot smoke-test), including a **functional systemd unit** that grants the
      capabilities the daemon needs (Q7 fix).
- [ ] The **aarch64 board binary** cross-compiles from the same locked source and
      integrates into a **Scarthgap image** (bitbake recipe) that boots the daemon.
- [ ] All artifacts gathered under **one immutable versioned release**, single
      version string, SHA256s + detached signatures + **SBOM** (Q3).
- [ ] Builds are **`--locked` + pinned-toolchain reproducible** (bit-for-bit for
      the signed release binary) (Q4).
- [ ] **Multi-arch Docker image manifest** published, digest-pinned, same version
      tag, boots the daemon (Q6).
- [ ] **Auto-detect installer** for host Linux that **verifies signatures** before
      install; recognizes board/Yocto targets as image-provisioned (Q5).
- [ ] **Release documentation**: supported-platform matrix; per-platform install;
      **signature/checksum verification**; first-run/node provisioning (mandatory
      `<node_id>`, config under `/etc/sgx-guardian`); upgrade/rollback/uninstall;
      kernel `nf_tables` prerequisite.
- [ ] **SE050 recorded as a separate Phase-2 deliverable** (Q8/Q9) with its own
      hardware acceptance — **not gating** the above.

Descoped items (e.g. if arch is x86_64-only, or RHEL is dev-only) are marked N/A
with the decision reference, not left open.

---

## 12. Open Decisions Needed From Stakeholders

Most answers above are code-dictated; these few are genuine business/security
calls we need confirmed:

- **D-1 — Board architecture (drives Q1, Q2, Q3, Q6):** Are production Guardian
  boards **ARM64** (our assumption from Yocto + SE050) or **x86_64**? If x86_64,
  ARM64 leaves scope and the answers simplify.
- **D-2 — SE050 mandatory? (Q8/Q9):** Confirm **Required** (vs. Optional) for
  production boards, and that production builds **fail closed** rather than fall
  back to software keys. *(Security-sensitive — needs explicit sign-off.)*
- **D-3 — OS minimums (Q2):** Ubuntu **22.04** as the stated minimum (keep 20.04
  as glibc floor, or drop it)? Is the **RHEL/Rocky `.rpm`** family official or
  dev-only?
- **D-4 — Reproducibility level (Q4):** Contract to **pinned-toolchain + `--locked`**
  as the bar, with **bit-for-bit + SBOM** for the signed release binary?
- **D-5 — Distribution channel (Q3/Q5):** Where do signed artifacts live (GitHub
  Releases, an APT/YUM repo, a container registry)? The versioned release and the
  installer both depend on this.
- **D-6 — Board Yocto branch (Q2):** Target **Scarthgap (5.0 LTS)** for the boards?
  The board runs **Mickledore (4.2) today, which is non-LTS and end-of-life** — no
  upstream security maintenance, a poor base for a security product. Confirm the
  board/SoC vendor BSP supports Scarthgap (fallback: **Kirkstone 4.0 LTS**, not
  Mickledore). *(Security-relevant — sets the board's patch cadence.)*

**Top priority: D-1.** Until the board architecture is confirmed, "binaries for all
supported platforms" has no testable definition, and the repo's own docs disagree
(packaging is x86_64-only while the architecture README promises ARM64).
