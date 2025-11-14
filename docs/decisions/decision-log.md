# 🧭 SG-X Guardian Client — Decision Log Documentation

This document tracks all **architectural, tactical, and procedural decisions**
made during the development of the **SG-X Guardian Client**.  
It provides a transparent record of choices related to system design, security,
programming standards, and deferred features — aligning with the client’s deliverable expectations.

---

## ⚙️ Architectural & Technical Decisions

## 📅 Sprint 1 – Foundation & Bootstrap (Completed)

| Area | Decision | Reason / Impact |
|------|-----------|----------------|
| **Programming Language** | **Rust** selected instead of C++ | Ensures memory safety, concurrency safety, and eliminates buffer-overflow class bugs; faster secure execution. |
| **Communication Protocol** | **gRPC + Protobuf** | Provides efficient, language-agnostic data exchange between distributed nodes; auto-generated Rust stubs simplify maintenance. |
| **Cryptography & Security** | **mTLS 1.3**, **Ed25519/X25519** for authentication & encryption | Lightweight and secure; prepares for future **PQC (Kyber/Dilithium)** integration in later sprints. |
| **Policy Schema** | **UEP Policy v1** defined in YAML | Human-readable, easy to validate and iterate during testing; compatible with future gRPC-based policy sync. |
| **Data Storage** | YAML configs for node setup (`nodeA/B/C.yaml`) | Simplifies local simulation and allows quick multi-node bootstrapping without a central DB. |
| **Logging Framework** | `tracing` + `tracing-appender` JSON logs | Structured, tamper-evident logs with timestamps and node IDs; supports future AI log analysis. |
| **Metrics Tracking** | Custom async `metrics.rs` | Records uptime, errors, and connection events; foundation for Prometheus/AI analytics integration. |
| **Security Model** | Zero-Trust Edge | Every node authenticates peers individually; enforces policy locally even offline. |
| **System Structure** | Modular architecture (`src/`, `sgx-pa-cli/`, `tests/`) | Separates core runtime, CLI admin tool, and integration tests; improves maintainability. |
| **Integration Pattern** | **CI/CD via GitHub Actions** | Automates build → test → audit → license checks; prevents insecure merges. |
| **Deployment Automation** | **GitHub Actions CI/CD with GPG-signed artifact publishing** | Full pipeline includes build caching, multi-stage tests, coverage, security scans, **GPG package signing**, and **artifact publishing** to satisfy deployment stage requirements. |
| **Policy Authority CLI (sgx-pa-cli)** | **Modular CLI tool** built for Policy Authority operations — includes subcommands for keypair generation (`keygen`) and policy signing (`sign`). | Provides secure offline policy lifecycle management; enables cryptographic integrity of configuration files before distribution. |
| **Static Analysis & Security Scanning** | Integrated **Semgrep** and **CodeQL** into CI/CD workflow. | Adds deep semantic vulnerability detection and continuous security auditing of Rust codebase; satisfies SOW SAST deliverable. |
| **API Specification v1.0** | Defined complete **gRPC Protobuf schemas** (`peer.proto`, `ping.proto`, `policy.proto`) and **sequence diagram** (`sgx_grpc_sequence_v1.png`). | Documents inter-node communication flow and ensures message-level compatibility between Guardian nodes and Policy Authority. |
| **Code Quality & Scanning** | `cargo fmt`, `clippy`, `audit`, `deny`,`CodeQL` | Maintains style, detects vulnerabilities, and enforces license compliance both locally and in CI. |
| **Feature Deferrals** | PQC crypto & AI anomaly detection | Deferred to Sprint 2–3 due to dependency on upgraded environment and hardware. |

---

### 🔹 Summary
- CI/CD pipeline fully automated with **format, lint, test, audit, and license** stages.  
- Implemented **UEP Policy Schema v1** for policy validation and enforcement.  
- Developed **multi-node LAN simulation** (Node A, B, C) with gRPC communication.  
- Integrated **structured logging and metrics** for observability and performance tracking.  
- Built **CLI tool (`sgx-pa-cli`)** to inspect logs and status directly from terminal.    
- Established **modular architecture** for core, CLI, and testing components.
- Extended **sgx-pa-cli** with functional cryptographic subcommands:
  - `keygen` — generates ECDSA-P256 keypair.
  - `sign` — signs YAML/JSON policy files producing `policy.sig`.
- Published **API Specification v1.0** including finalized Protobuf definitions and `sgx_grpc_sequence_v1.png` diagram.
- Enhanced CI/CD pipeline with **CodeQL** and **Semgrep** static analysis for continuous security scanning.

✅ Result: The foundation phase is complete — the client now has a fully operational,  
secure, and observable Rust-based edge agent, ready for **Sprint 2: Identity & Discovery.**

---

## 📅 Sprint 2 – Identity & Discovery

| Area | Decision | Reason / Impact |
|------|-----------|----------------|
| **Node Identity** | Implemented persistent ECDSA P-256 key manager (`key_manager.rs`) with secure file storage. | Ensures each node has a durable, cryptographically unique identity for attestation and future mTLS. |
| **Peer Discovery** | Added zero-configuration peer discovery using **mDNS** service `_sgx-guardian._tcp` with nonce exchange. | Enables automatic LAN-level peer visibility without manual configuration. |
| **Attestation Service** | Created `attestation_service.rs` for generating and signing attestation evidence over nonces and policy digest. | Establishes foundation for mutual verification and Circle-of-Trust formation. |
| **Integration** | Linked discovery and attestation services through async tasks in `main.rs`. | Allows nodes to auto-discover peers and initiate attestation handshakes at runtime. |
| **Background Task Management** | Added structured Tokio task spawning + Ctrl-C signal handling. | Ensures deterministic cleanup and stability across multi-node environments. |
| **CLI Visibility Layer** | Extended **sgx-pa-cli** with new sub-commands `peers` and `attestation`. | Provides administrators live insight into discovered peers and latest attestation results. |
| **Data Source for CLI** | CLI parses JSON log files (`trusted_peers.json`, `last_attestation.json`). | Decouples admin tooling from daemon runtime; future-ready for gRPC telemetry. |
| **Logging Enhancements** | Added JSON log writers in daemon for discovery and attestation outcomes. | Enables CLI and monitoring tools to consume structured data consistently. |
| **Unit & Integration Testing** | Added CLI output format unit tests (`tests/cli_output.rs`) and validated async service startup. | Guarantees CLI reliability and daemon stability under test harness. |
| **Security & Observability** | Maintained tamper-evident logging and verified key-pair reuse safety during multi-node runs. | Confirms Zero-Trust principles across nodes. |
| **Integration Testing** | Conducted full multi-node LAN simulation using `run_three_nodes.sh` with Node A, B, C. | Verified that discovery and mutual attestation handshakes succeed automatically across all peers, forming a 3-node Circle of Trust. |
| **TCP Attestation Listener** | Added async listener (`start_attestation_listener`) for inbound attestation evidence on dynamic ports (+100 offset). | Enables bidirectional peer attestation, allowing nodes to both initiate and respond within the trust mesh. |
| **Trusted Peer and Evidence Logs** | Introduced `logs/trusted_peers.json` and `logs/last_attestation.json` for persisted trust and verification data. | Provides durable state for CLI inspection and replayable trust chain verification. |
| **Re-Attestation & Stability** | Implemented periodic **re-attestation timer (60 seconds)** to auto-refresh trusted peer connections. | Maintains continuous trust validation across long-running sessions, aligning with Zero-Trust principles. |
| **Auto Re-Attest on Startup** | Added startup routine to automatically re-verify peers from previous trusted state. | Ensures seamless trust restoration after node restarts. |
| **Trusted Peer Timestamp Refresh** | Enhanced `write_trusted_peer()` to update timestamps and overwrite JSON on every successful re-attestation. | Keeps CLI “Last Seen” column up to date, proving live trust health. |
| **Failure Handling Improvements** | Added retry loop (3 attempts) + graceful `[NetworkError]` logs on connection failures. | Improves network resilience and clear diagnostics during transient disconnects. |
| **Validation & CLI Sync** | Confirmed CLI commands `peers` and `attestation` reflect current re-attestation results with updated timestamps. | Demonstrates full synchronization between daemon logs and administrator interface. |
| **Result Verification** | Observed dynamic timestamp updates and successful periodic attestation cycles across all 3 nodes. | Confirms end-to-end stability and correctness. |
| **Autonomous Circle-of-Trust Demo** | Successfully demonstrated 3-node boot sequence (A, B, C) where each node autonomously discovers and mutually attests peers. | Proves end-to-end automation of discovery and trust establishment across multiple nodes. |
| **Multi-Node Automation Script** | Enhanced `run_three_nodes.sh` to auto-start, wait, summarize logs, and verify Circle of Trust completeness. | Enables reproducible multi-node testing and automated validation of distributed attestation. |
| **Peer Log Merging** | Added JSON merge logic (`jq -s 'add | unique_by(.peer_id)'`) to consolidate peer states from all nodes. | Ensures unified trusted peer view even when nodes write separate logs. |



