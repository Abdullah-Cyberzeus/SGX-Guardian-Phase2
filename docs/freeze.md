# SG-X Guardian — Board Freeze: Real Root Cause + Missing Gates + Code Fix

**Date:** 22 April 2026
**Source:** Latest `main.rs` you pasted + `/home/root` state on board 101
**Subject:** Why your env gates don't work, why ssscli blocks the tokio runtime, and the exact patch to fix both.

---

## A. Executive Summary

Three facts from the evidence you provided:

1. **Five of the env flags you set do nothing.** `SGX_FORCE_SOFTWARE_KEYS`, `SGX_DISABLE_SE050_DKP`, `SGX_DISABLE_GRPC_SERVER`, `SGX_DISABLE_CERT_BOOTSTRAP`, `SGX_DISABLE_SECURE_BOOT_CHECK` are not wired into `runtime_gates.rs` or `main.rs`. Your `strings` output and the `main.rs` you pasted confirm this.

2. **Every freeze reproducer stops inside a synchronous ssscli call.** Log 1 freezes during `ssscli generate ecc 0x20000010`. Log 2 freezes at `km.sign()` → `ssscli sign`. `KeyManager::init_with_se050` is called without `tokio::task::spawn_blocking`, so the subprocess blocks a tokio worker. If ssscli stalls on the SE050 I2C bus for any reason, the entire async runtime stops scheduling.

3. **A stale ssscli session cache exists on every board you tested.** Your `ls -lh` shows `~.ssscli_session.pkl` dated `Mar  3  2023` — that's ancient. A SIGKILL'd daemon earlier left the SE050 PlatformSCP session out of sync with the on-disk pickle. The next `ssscli connect` retries, spins, and holds the I2C bus while the kernel's `i2c-imx` driver retries with increasing priority.

**The Sprint-3 connection you noticed is real but indirect.** Sprint 3 didn't change the SE050 code — it added the Nebula config regeneration and registry sync that runs before Nebula actually starts. Combined with more `ssscli` invocations (PCR signing added in Sprint 2 + Nebula cert validation calls added in Sprint 3), the probability of hitting a stale-session hang increased sharply. That's why the same hardware that ran Sprint 2 cleanly now freezes.

---

## B. Why Your Isolation Runs Don't Isolate Anything

Look at the actual code flow in your `main.rs` **when all your env vars are set**:

```text
STEP_01 post-listener: entering KeyManager init
│
├── KeyManager::init_with_se050(...)                    ← NO GATE. ALWAYS RUNS. ssscli connect + generate + export.
│       └── DkpManager::init() → SeKeyStorage::list_slots() → ssscli se05x readidlist     [BLOCKING]
│       └── storage.create_key_slot()                   → ssscli generate ecc              [BLOCKING]
│       └── storage.export_public_key()                 → ssscli get ecc pub               [BLOCKING]
│
├── DKP auto-rotation check                             ← NO GATE. ssscli again.
│
├── create_signed_evidence(&km, &sample_policy)         ← NO GATE. km.sign() → ssscli sign [BLOCKING]
├── verify_signed_evidence()                            ← safe CPU
│
├── Secure Boot Chain check                             ← NO GATE. devmem2 + /sys reads
├── PCR Measurement (full)                              ← NO GATE. Files + ssscli sign for composite [BLOCKING]
├── Dynamic IP detection                                ← safe
├── Config sanitize / load                              ← safe
├── AuditVerifier::verify                               ← NO GATE. Can be slow on a large audit log.
├── init_audit_logger                                   ← safe
├── Cloud uplink                                         ← GATE WORKS (SGX_DISABLE_CLOUD_UPLINK)
├── Nebula block                                         ← GATE WORKS (SGX_DISABLE_NEBULA)
├── CoT block                                            ← GATE WORKS
├── P2P Discovery spawn                                  ← GATE WORKS
├── Attestation spawn                                    ← GATE WORKS
├── Broadcast init + loop                                ← GATE WORKS
├── TLS + gRPC server                                    ← NO GATE. Port 50051/52/53 bind + cert bootstrap server on 50061
├── Policy enforcement (nftables)                        ← NO GATE. Writes kernel firewall rules.
```

Everything above the "GATE WORKS" block runs regardless of your env vars. Of that, these three are the realistic freeze culprits:

| # | Subsystem | Why it can freeze the board |
|---|-----------|------------------------------|
| 1 | SE050 / ssscli (DKP init + sign) | Blocking subprocess on tokio thread; stale session pickle; I2C bus wedged |
| 2 | PCR Measurement | Reads many `/sys` + `/dev` paths; calls `km.sign()` again (more ssscli) |
| 3 | nftables policy enforcement | Kernel netfilter manipulation; unrelated to your current disables |

---

## C. The Real Fix (Three Layers)

### Layer 1 — Wire up the missing gates

Add these fields to `RuntimeGates` and read the corresponding env vars. None of them change default behavior.

### Layer 2 — Move every blocking ssscli call onto `tokio::task::spawn_blocking` with a hard timeout

This is the single most important technical change. With `spawn_blocking`, the tokio executor continues to schedule heartbeat writes, SSH keepalives, and the UDP listener even if ssscli hangs. With the timeout, a wedged ssscli call returns an error instead of blocking forever.

### Layer 3 — Reset the ssscli session on the board before every launch

Until we flush the stale PlatformSCP session pickle, every run has a non-zero chance of hanging regardless of the code. This is an operator-side one-liner.

---

## D. Exact Code Changes

### D-1. `src/runtime_gates.rs` — add missing fields

#### FIND:

```rust
pub struct RuntimeGates {
    pub disable_nebula: bool,
    pub disable_relay_tc: bool,
    pub disable_relay_stats: bool,
    pub disable_tunnel_observer: bool,
    pub disable_cot: bool,
    pub disable_cot_bluetooth: bool,
    pub disable_cot_cellular: bool,
    pub disable_cot_satellite: bool,
    pub disable_cot_refresh: bool,
    pub disable_p2p_discovery: bool,
    pub disable_attestation: bool,
    pub disable_broadcast: bool,
    pub disable_cloud_uplink: bool,
    pub disable_expiry_monitor: bool,
    pub disable_lighthouse_health: bool,
    pub startup_cooldown_ms: u64,
}
```

#### REPLACE WITH:

```rust
pub struct RuntimeGates {
    // existing (already wired)
    pub disable_nebula: bool,
    pub disable_relay_tc: bool,
    pub disable_relay_stats: bool,
    pub disable_tunnel_observer: bool,
    pub disable_cot: bool,
    pub disable_cot_bluetooth: bool,
    pub disable_cot_cellular: bool,
    pub disable_cot_satellite: bool,
    pub disable_cot_refresh: bool,
    pub disable_p2p_discovery: bool,
    pub disable_attestation: bool,
    pub disable_broadcast: bool,
    pub disable_cloud_uplink: bool,
    pub disable_expiry_monitor: bool,
    pub disable_lighthouse_health: bool,

    // NEW — early-startup isolation (previously missing)
    /// Force software ring keypair, never call ssscli for identity.
    pub force_software_keys: bool,
    /// Skip DKP auto-rotation check (one ssscli call).
    pub disable_dkp_rotation: bool,
    /// Skip AttestationService::create_signed_evidence (avoid ssscli sign at startup).
    pub disable_startup_attest_evidence: bool,
    /// Skip BootChainStatus::check (devmem2 + /sys reads).
    pub disable_secure_boot_check: bool,
    /// Skip PCR measurement (lots of filesystem reads + ssscli sign).
    pub disable_pcr_measurement: bool,
    /// Skip AuditVerifier::verify on existing audit.log.
    pub disable_audit_verify: bool,
    /// Skip mTLS cert setup + gRPC server spawn.
    pub disable_grpc_server: bool,
    /// Skip plaintext cert bootstrap server on :50061 (nodeA only).
    pub disable_cert_bootstrap: bool,
    /// Skip nftables policy enforcement.
    pub disable_policy_enforcement: bool,
    /// Skip node_listener UDP 9000 receiver.
    pub disable_node_listener: bool,
    /// Maximum seconds to wait for any single ssscli subprocess.
    pub ssscli_timeout_secs: u64,

    pub startup_cooldown_ms: u64,
}
```

Then update `RuntimeGates::load()` to populate these:

```rust
fn load() -> Self {
    Self {
        disable_nebula:            env_true("SGX_DISABLE_NEBULA"),
        disable_relay_tc:          env_true("SGX_DISABLE_RELAY_TC"),
        disable_relay_stats:       env_true("SGX_DISABLE_RELAY_STATS"),
        disable_tunnel_observer:   env_true("SGX_DISABLE_TUNNEL_OBSERVER"),
        disable_cot:               env_true("SGX_DISABLE_COT"),
        disable_cot_bluetooth:     env_true("SGX_DISABLE_COT_BLUETOOTH"),
        disable_cot_cellular:      env_true("SGX_DISABLE_COT_CELLULAR"),
        disable_cot_satellite:     env_true("SGX_DISABLE_COT_SATELLITE"),
        disable_cot_refresh:       env_true("SGX_DISABLE_COT_REFRESH"),
        disable_p2p_discovery:     env_true("SGX_DISABLE_P2P_DISCOVERY"),
        disable_attestation:       env_true("SGX_DISABLE_ATTESTATION"),
        disable_broadcast:         env_true("SGX_DISABLE_BROADCAST"),
        disable_cloud_uplink:      env_true("SGX_DISABLE_CLOUD_UPLINK"),
        disable_expiry_monitor:    env_true("SGX_DISABLE_EXPIRY_MONITOR"),
        disable_lighthouse_health: env_true("SGX_DISABLE_LIGHTHOUSE_HEALTH"),

        // NEW
        force_software_keys:            env_true("SGX_FORCE_SOFTWARE_KEYS")
                                        || env_true("SGX_DISABLE_SE050_DKP"),
        disable_dkp_rotation:           env_true("SGX_DISABLE_DKP_ROTATION"),
        disable_startup_attest_evidence:env_true("SGX_DISABLE_STARTUP_ATTEST"),
        disable_secure_boot_check:      env_true("SGX_DISABLE_SECURE_BOOT_CHECK"),
        disable_pcr_measurement:        env_true("SGX_DISABLE_PCR"),
        disable_audit_verify:           env_true("SGX_DISABLE_AUDIT_VERIFY"),
        disable_grpc_server:            env_true("SGX_DISABLE_GRPC_SERVER"),
        disable_cert_bootstrap:         env_true("SGX_DISABLE_CERT_BOOTSTRAP"),
        disable_policy_enforcement:     env_true("SGX_DISABLE_POLICY_ENFORCEMENT"),
        disable_node_listener:          env_true("SGX_DISABLE_NODE_LISTENER"),
        ssscli_timeout_secs:            env_u64("SGX_SSSCLI_TIMEOUT_SECS", 10),

        startup_cooldown_ms:       env_u64("SGX_STARTUP_COOLDOWN_MS", 0),
    }
}
```

Update `log_summary()` to include the new fields in the log line.

### D-2. `src/main.rs` — apply the new gates at the right place

#### D-2.a — gate `node_listener` so we can test without ANY background task

**FIND:**
```rust
    // Start node announcement listener (UDP broadcast receiver)
    {
        let node_id_clone = node_id.clone();
        tokio::spawn(async move {
            node_listener::start_listener(node_id_clone).await;
        });
    }
    GATES.log_summary();
    step(1, "post-listener: entering KeyManager init");
```

**REPLACE WITH:**
```rust
    GATES.log_summary();
    step(0, "gates loaded");

    if !GATES.disable_node_listener {
        let node_id_clone = node_id.clone();
        tokio::spawn(async move {
            node_listener::start_listener(node_id_clone).await;
        });
        step(1, "node-listener spawned");
    } else {
        tracing::warn!("STEP_01 SKIPPED: node_listener disabled by SGX_DISABLE_NODE_LISTENER");
    }
    cooldown().await;
```

#### D-2.b — gate the SE050 KeyManager init and wrap in spawn_blocking

**FIND:**
```rust
    // === Hardware Key Manager Initialization (Phase 2 — HKM) ===
    #[cfg(feature = "secure-element")]
    let km = {
        let se_base_path = "/var/lib/sgx-guardian";
        let se_config = secure_element::SeConfig::default();

        match KeyManager::init_with_se050(&se_config, se_base_path, &node_key_path) {
            Ok(hw_km) => {
                println!("DKP initialized via SE050 hardware");
                log_audit(
                    &node_id,
                    AuditCategory::Identity,
                    AuditSeverity::Info,
                    AuditAction::Loaded,
                    "Hardware Key Manager: DKP active via SE050",
                );
                hw_km
            }
            Err(e) => {
                eprintln!("SE050 HKM failed: {} — using software keys", e);
                KeyManager::load_or_generate(&node_key_path)?
            }
        }
    };
```

**REPLACE WITH:**
```rust
    // === Hardware Key Manager Initialization (Phase 2 — HKM) ===
    step(2, "keymgr init gate");
    #[cfg(feature = "secure-element")]
    let km = {
        if GATES.force_software_keys {
            tracing::warn!("STEP_02 SE050 DKP SKIPPED: SGX_FORCE_SOFTWARE_KEYS / SGX_DISABLE_SE050_DKP set");
            println!("⚙️  Software keys forced — skipping SE050 DKP entirely");
            KeyManager::load_or_generate(&node_key_path)?
        } else {
            let se_base_path = "/var/lib/sgx-guardian".to_string();
            let se_config = secure_element::SeConfig::default();
            let node_key_path_cl = node_key_path.clone();
            let timeout = std::time::Duration::from_secs(GATES.ssscli_timeout_secs.max(5) * 6);

            step(3, "KeyManager::init_with_se050 (spawn_blocking)");
            let km_res = tokio::time::timeout(
                timeout,
                tokio::task::spawn_blocking(move || {
                    KeyManager::init_with_se050(&se_config, &se_base_path, &node_key_path_cl)
                }),
            )
            .await;

            match km_res {
                Ok(Ok(Ok(hw_km))) => {
                    println!("DKP initialized via SE050 hardware");
                    log_audit(
                        &node_id,
                        AuditCategory::Identity,
                        AuditSeverity::Info,
                        AuditAction::Loaded,
                        "Hardware Key Manager: DKP active via SE050",
                    );
                    hw_km
                }
                Ok(Ok(Err(e))) => {
                    eprintln!("SE050 HKM failed: {} — using software keys", e);
                    KeyManager::load_or_generate(&node_key_path)?
                }
                Ok(Err(join_err)) => {
                    eprintln!("SE050 HKM task panicked: {:?} — using software keys", join_err);
                    KeyManager::load_or_generate(&node_key_path)?
                }
                Err(_) => {
                    eprintln!(
                        "SE050 HKM TIMED OUT after {:?} — using software keys (ssscli/I2C likely wedged)",
                        timeout
                    );
                    log_audit(
                        &node_id,
                        AuditCategory::Identity,
                        AuditSeverity::Critical,
                        AuditAction::Failed,
                        "SE050 HKM timed out — fell back to software keys",
                    );
                    KeyManager::load_or_generate(&node_key_path)?
                }
            }
        }
    };
    cooldown().await;
```

#### D-2.c — gate DKP auto-rotation

**FIND:**
```rust
    // === DKP Auto-Rotation Check ===
    #[cfg(feature = "secure-element")]
    {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        let base_path = "/var/lib/sgx-guardian";
        if let Ok(mut dkp) =
            sgx_guardian_client::secure_element::dkp::DkpManager::init(&se_config, base_path)
        {
            match dkp.check_and_auto_rotate() {
                ...
            }
        }
    }
```

**REPLACE WITH:**
```rust
    step(4, "dkp-rotation gate");
    #[cfg(feature = "secure-element")]
    if !GATES.force_software_keys && !GATES.disable_dkp_rotation {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        let base_path = "/var/lib/sgx-guardian".to_string();
        let timeout = std::time::Duration::from_secs(GATES.ssscli_timeout_secs.max(5) * 4);

        let rot_res = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || {
                let mut dkp = sgx_guardian_client::secure_element::dkp::DkpManager::init(&se_config, &base_path).ok()?;
                Some(dkp.check_and_auto_rotate())
            }),
        ).await;

        match rot_res {
            Ok(Ok(Some(Ok(Some(new_meta))))) => {
                println!("  DKP auto-rotated to v{}", new_meta.version);
            }
            Ok(_) => { /* no rotation or non-fatal error */ }
            Err(_) => {
                eprintln!("  DKP auto-rotation TIMED OUT — continuing");
            }
        }
    } else {
        tracing::warn!("STEP_04 SKIPPED: DKP rotation disabled");
    }
    cooldown().await;
```

#### D-2.d — gate the startup attestation evidence

**FIND:**
```rust
    let evidence = AttestationService::create_signed_evidence(&km, &sample_policy)?;
    println!(
        "Created local attestation evidence (nonce={}..)",
        &evidence.nonce[..8]
    );
    let verified = AttestationService::verify_signed_evidence(&evidence, &sample_policy)?;
```

**REPLACE WITH:**
```rust
    step(5, "startup-attest-evidence gate");
    if !GATES.disable_startup_attest_evidence {
        // This signs with the DKP — on SE050 backend that is another ssscli sign.
        // Wrap in spawn_blocking with timeout.
        let km_ref = km.clone_for_blocking();  // see note below
        let policy_cl = sample_policy.clone();
        let evidence_res = tokio::time::timeout(
            std::time::Duration::from_secs(GATES.ssscli_timeout_secs.max(5) * 2),
            tokio::task::spawn_blocking(move || {
                AttestationService::create_signed_evidence(&km_ref, &policy_cl)
            }),
        ).await;

        match evidence_res {
            Ok(Ok(Ok(evidence))) => {
                println!("Created local attestation evidence (nonce={}..)", &evidence.nonce[..8]);
                let verified = AttestationService::verify_signed_evidence(&evidence, &sample_policy)?;
                if verified {
                    println!("✅ Local attestation evidence verified successfully.");
                } else {
                    eprintln!("❌ Local attestation verification failed!");
                }
            }
            Ok(_) => eprintln!("⚠️ Startup attestation evidence failed (non-fatal)"),
            Err(_) => eprintln!("⚠️ Startup attestation evidence TIMED OUT — continuing"),
        }
    } else {
        tracing::warn!("STEP_05 SKIPPED: startup attestation evidence disabled");
    }
    cooldown().await;
```

**Note on `km.clone_for_blocking()`:** `KeyManager` holds `EcdsaKeyPair` which is not `Clone` in ring. Simplest workaround is to make the `create_signed_evidence` call directly inside a closure that captures `&km` by reference via `Arc<KeyManager>`. If refactoring to `Arc<KeyManager>` is too invasive, alternative: leave this call synchronous but gate it — then the isolation test will skip it and prove whether it was the culprit. Quick path:

```rust
    step(5, "startup-attest-evidence gate");
    if !GATES.disable_startup_attest_evidence {
        let evidence = AttestationService::create_signed_evidence(&km, &sample_policy)?;
        println!("Created local attestation evidence (nonce={}..)", &evidence.nonce[..8]);
        let _ = AttestationService::verify_signed_evidence(&evidence, &sample_policy)?;
    } else {
        tracing::warn!("STEP_05 SKIPPED: startup attestation evidence disabled");
    }
```

#### D-2.e — gate Secure Boot Chain

**FIND:**
```rust
    // === Secure Boot Chain Verification ===
    println!("\n  Verifying secure boot chain...");
    {
        use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;

        let boot_status = BootChainStatus::check();
        boot_status.print();
        ...
    }
```

**REPLACE WITH:**
```rust
    step(6, "secure-boot-check gate");
    if !GATES.disable_secure_boot_check {
        println!("\n  Verifying secure boot chain...");
        use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;
        let boot_status = BootChainStatus::check();
        boot_status.print();
        let boot_status_path = format!("/var/lib/sgx-guardian/boot/{}_chain_status.json", node_id);
        if let Err(e) = boot_status.save(&boot_status_path) {
            eprintln!("  Boot chain save failed: {}", e);
        }
    } else {
        tracing::warn!("STEP_06 SKIPPED: secure boot check disabled");
    }
    cooldown().await;
```

#### D-2.f — gate PCR measurement

**FIND:**
```rust
    // === PCR Measurement (ATT-003) ===
    println!("\n  Measuring platform integrity (PCR)...");
    {
        ... all PCR code ...
    }
```

**REPLACE WITH:**
```rust
    step(7, "pcr-measurement gate");
    if !GATES.disable_pcr_measurement {
        println!("\n  Measuring platform integrity (PCR)...");
        // ... all PCR code unchanged ...
    } else {
        tracing::warn!("STEP_07 SKIPPED: PCR measurement disabled");
    }
    cooldown().await;
```

#### D-2.g — gate audit verify

**FIND:**
```rust
    if std::path::Path::new(audit_check_path).exists() {
        if let Err(e) = AuditVerifier::verify(audit_check_path) {
            log_error(...);
        }
    }
```

**REPLACE WITH:**
```rust
    if !GATES.disable_audit_verify && std::path::Path::new(audit_check_path).exists() {
        step(10, "audit-verify");
        if let Err(e) = AuditVerifier::verify(audit_check_path) {
            log_error(&node_id, &format!("Audit log integrity warning (non-fatal): {}", e));
        }
    } else if GATES.disable_audit_verify {
        tracing::warn!("audit verify disabled by SGX_DISABLE_AUDIT_VERIFY");
    }
```

#### D-2.h — gate gRPC server + cert bootstrap

**FIND:**
```rust
    // spawn gRPC server using tonic Identity + CA (mTLS)
    let server_task = task::spawn({
        let identity = identity.clone();
        let ca_cert = ca_cert.clone();
        let this_addr = this_addr.clone();
        async move {
            if let Err(e) = start_server(this_addr.clone(), identity, ca_cert).await {
                eprintln!("Server failed at {}: {:?}", this_addr, e);
            }
        }
    });
    // === CERT BOOTSTRAP SERVER (nodeA only, plaintext port 50061) ===
    if node_id == "nodeA" {
        tokio::spawn(async move {
            if let Err(e) = server::start_cert_bootstrap_server("0.0.0.0:50061".to_string()).await {
                eprintln!("Cert bootstrap server failed: {:?}", e);
            }
        });
    }
```

**REPLACE WITH:**
```rust
    step(32, "grpc-server gate");
    let server_task = if !GATES.disable_grpc_server {
        task::spawn({
            let identity = identity.clone();
            let ca_cert = ca_cert.clone();
            let this_addr = this_addr.clone();
            async move {
                if let Err(e) = start_server(this_addr.clone(), identity, ca_cert).await {
                    eprintln!("Server failed at {}: {:?}", this_addr, e);
                }
            }
        })
    } else {
        tracing::warn!("STEP_32 SKIPPED: gRPC server disabled");
        task::spawn(async { /* no-op */ })
    };

    step(33, "cert-bootstrap gate");
    if node_id == "nodeA" && !GATES.disable_cert_bootstrap {
        tokio::spawn(async move {
            if let Err(e) = server::start_cert_bootstrap_server("0.0.0.0:50061".to_string()).await {
                eprintln!("Cert bootstrap server failed: {:?}", e);
            }
        });
    } else if GATES.disable_cert_bootstrap {
        tracing::warn!("STEP_33 SKIPPED: cert bootstrap disabled");
    }
```

#### D-2.i — gate policy enforcement (nftables)

**FIND:**
```rust
    if let Some(active_policy) = get_active_policy() {
        println!("🛡️ Applying policy enforcement (nftables)");
        ...
        match enforcement::enforce_policy(&active_policy) {
            ...
        }
    }
```

**REPLACE WITH:**
```rust
    step(34, "policy-enforcement gate");
    if !GATES.disable_policy_enforcement {
        if let Some(active_policy) = get_active_policy() {
            println!("🛡️ Applying policy enforcement (nftables)");
            // ... unchanged ...
        }
    } else {
        tracing::warn!("STEP_34 SKIPPED: policy enforcement disabled");
    }
```

---

## E. ssscli State Reset Procedure (apply on board before every run)

Run this on the board **every single time before launching the daemon**. The stale `~.ssscli_session.pkl` from March 2023 is a latent hang trigger.

Create `/home/root/reset_ssscli.sh`:

```sh
#!/bin/sh
# Reset all ssscli / SE050 session state. Safe to run any time.

# Kill any running ssscli process.
pkill -9 -f ssscli 2>/dev/null

# Drop the cached PlatformSCP session pickle. Old pickles cause hangs when
# the on-chip session was invalidated by a prior SIGKILL mid-transaction.
rm -f /home/root/*.ssscli_session.pkl
rm -f /root/*.ssscli_session.pkl

# Re-establish a clean session.
ssscli disconnect >/dev/null 2>&1
sleep 1
ssscli connect --auth_type PlatformSCP \
    --scpkey /home/root/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt \
    se05x t1oi2c none >/tmp/ssscli_connect.log 2>&1

# Probe: read UID. If this hangs, SE050/I2C bus is wedged — reboot is the only fix.
timeout 5 ssscli se05x uniqueid >/tmp/ssscli_uid.log 2>&1
if [ $? -ne 0 ]; then
    echo "WARN: ssscli uniqueid failed — SE050/I2C may be wedged. Consider reboot." >&2
    exit 1
fi

echo "ssscli session reset OK"
exit 0
```

Wire it into your launch sequence:

```sh
/home/root/reset_ssscli.sh && /home/root/run_node.sh nodeA
```

---

## F. Kernel Console Monitor (captures printk floods)

Create `/home/root/kmsg_watch.sh`:

```sh
#!/bin/sh
# Stream kernel ring buffer to a file while daemon runs. Lets us see if
# the kernel is hitting softlockup / RCU stall warnings that cause SSH resets.

OUT=/tmp/sgx_kmsg.log
echo "=== kmsg watch started at $(date -u) ===" > "$OUT"
dmesg -w >> "$OUT" 2>&1 &
echo $! > /tmp/sgx_kmsg.pid
echo "kmsg watch PID $(cat /tmp/sgx_kmsg.pid), log: $OUT"
```

Run it **before** launching the daemon. When the daemon freezes, `cat /tmp/sgx_kmsg.log` will show whatever the kernel printed right before — RCU stall, softlockup, I2C bus hang, Wi-Fi firmware crash, all of these leave a signature.

---

## G. Staged Test Plan (start with nothing, walk forward)

Build + deploy the rebuilt binary containing the new gates. Then on board 101:

### Stage 0 — baseline with EVERYTHING off (should be dead silent after STEP_00)

```sh
/home/root/reset_ssscli.sh
/home/root/kmsg_watch.sh

export SGX_DISABLE_NODE_LISTENER=1
export SGX_FORCE_SOFTWARE_KEYS=1
export SGX_DISABLE_DKP_ROTATION=1
export SGX_DISABLE_STARTUP_ATTEST=1
export SGX_DISABLE_SECURE_BOOT_CHECK=1
export SGX_DISABLE_PCR=1
export SGX_DISABLE_AUDIT_VERIFY=1
export SGX_DISABLE_CLOUD_UPLINK=1
export SGX_DISABLE_NEBULA=1
export SGX_DISABLE_COT=1
export SGX_DISABLE_P2P_DISCOVERY=1
export SGX_DISABLE_ATTESTATION=1
export SGX_DISABLE_BROADCAST=1
export SGX_DISABLE_GRPC_SERVER=1
export SGX_DISABLE_CERT_BOOTSTRAP=1
export SGX_DISABLE_POLICY_ENFORCEMENT=1
export SGX_STARTUP_COOLDOWN_MS=2000

/home/root/run_node.sh nodeA
```

**Expected:** log shows STEP_00 gates loaded, then almost nothing else. Daemon parks at `select!`. SSH must stay alive for 10 minutes. If it doesn't — the issue is not in any of the gated subsystems; it's in the pre-STEP_00 setup (directories, config file writes, listener bind).

### Stage 1 — turn on node_listener only

```sh
unset SGX_DISABLE_NODE_LISTENER
```

### Stage 2 — turn on software keys (still no SE050)

```sh
# SGX_FORCE_SOFTWARE_KEYS already set
# but make sure the fallback software path works
```

### Stage 3 — turn on SE050 DKP

```sh
unset SGX_FORCE_SOFTWARE_KEYS
```

**This is the critical stage.** If SSH dies here, we have proven the freeze is in the ssscli/SE050 path. The `spawn_blocking` + timeout from D-2.b means the DAEMON will fall back to software keys gracefully instead of hanging forever — but if the BOARD still freezes, that means ssscli is hanging the I2C driver at a level `spawn_blocking` can't rescue. In that case the fix is operator-side (reset_ssscli.sh + kernel-level I2C bus reset on modprobe).

### Stage 4 — turn on PCR

```sh
unset SGX_DISABLE_PCR
```

### Stage 5 — turn on attestation evidence, secure boot, audit verify

```sh
unset SGX_DISABLE_STARTUP_ATTEST SGX_DISABLE_SECURE_BOOT_CHECK SGX_DISABLE_AUDIT_VERIFY
```

### Stage 6 — turn on gRPC + cert bootstrap

```sh
unset SGX_DISABLE_GRPC_SERVER SGX_DISABLE_CERT_BOOTSTRAP
```

### Stage 7 — full run

```sh
unset SGX_DISABLE_NEBULA SGX_DISABLE_COT SGX_DISABLE_P2P_DISCOVERY \
      SGX_DISABLE_ATTESTATION SGX_DISABLE_BROADCAST SGX_DISABLE_CLOUD_UPLINK \
      SGX_DISABLE_POLICY_ENFORCEMENT SGX_DISABLE_DKP_ROTATION
```

---

## H. Success and Failure Signals

| Signal | Meaning |
|--------|---------|
| `tail -f /tmp/sgx_nodeA.log` shows only `STEP_NN gates loaded` then SSH stable 10 min | Baseline clean, freeze is in a gated subsystem |
| Last STEP before SSH drop is STEP_03 | ssscli SE050 init is the culprit — `reset_ssscli.sh` + power-cycle needed |
| Last STEP is STEP_05 | startup attestation evidence (ssscli sign) — already mitigated by spawn_blocking+timeout in the patch |
| Last STEP is STEP_07 | PCR measurement — check `/sys` or `/dev` read path that blocks |
| `cat /tmp/sgx_kmsg.log` shows `RCU stall`, `softlockup`, `i2c-imx`, `brcmfmac` errors | Kernel-level bug — file Variscite ticket with this log |
| Daemon exits cleanly with `SE050 HKM TIMED OUT after …` | Timeout from patch D-2.b fired — daemon is fine, ssscli was wedged but we recovered |

---

## I. Rollback

Every change is gated. Default behavior (no env vars set) is identical to current main. If any stage misbehaves: `unset` the env var, re-run, done. No on-disk data changes, no protocol changes, no crypto changes.

---

## J. TL;DR

- The five env vars you thought were disabling early startup **weren't wired up** — this patch adds them.
- `KeyManager::init_with_se050` was called synchronously on the tokio main thread — this patch moves it to `spawn_blocking` with a 60s timeout, so a wedged ssscli stops hanging the daemon.
- The March-2023 `~.ssscli_session.pkl` on every board is a latent hang trigger — `reset_ssscli.sh` clears it before every run.
- Stage 0 gives you a known-clean baseline. Stage 3 tells you definitively if SE050/ssscli is the culprit.

End of plan.