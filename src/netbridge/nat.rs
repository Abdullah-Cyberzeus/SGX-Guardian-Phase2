//! Network Address Translation (NAT) Orchestrator
//!
//! Manages internet sharing between the local Access Point (ap0)
//! and the upstream Uplink (wlan1) by interacting dynamically
//! with the Enforcement engine.

use crate::enforcement;
use crate::policy::{Policy, Rule};
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

pub struct NatManager {
    is_enabled: AtomicBool,
}

impl NatManager {
    pub fn new() -> Self {
        Self {
            is_enabled: AtomicBool::new(false),
        }
    }
}

impl Default for NatManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NatManager {
    /// Generates the dynamic policy required to share internet from the uplink
    /// to the internal AP clients, and applies it via the enforcement engine.
    pub fn enable_nat(
        &self,
        in_iface: &str,
        out_iface: &str,
        client_isolation: bool,
    ) -> Result<()> {
        tracing::debug!("Generating NAT, Forwarding, and Isolation policies...");

        // 1. NAT Policy (Masquerade)
        let nat_rule = Rule {
            id: "dyn_nat_masquerade_01".to_string(),
            action: "masquerade".to_string(),
            src: in_iface.to_string(),
            dst: out_iface.to_string(),
            protocol: "any".to_string(),
            port: None,
        };

        // 2. Forwarding Policy (Allow AP -> Uplink)
        let fwd_out = Rule {
            id: "dyn_fwd_outbound_01".to_string(),
            action: "allow".to_string(),
            src: in_iface.to_string(),
            dst: out_iface.to_string(),
            protocol: "any".to_string(),
            port: None,
        };

        // 3. Forwarding Policy (Allow Established Uplink -> AP)
        let fwd_in = Rule {
            id: "dyn_fwd_inbound_established_01".to_string(),
            action: "allow".to_string(),
            src: out_iface.to_string(),
            dst: in_iface.to_string(),
            protocol: "state:established,related".to_string(),
            port: None,
        };

        // 4. Isolation Policy (Deny all other untracked Uplink -> AP traffic)
        let isolation = Rule {
            id: "dyn_isolate_inbound_01".to_string(),
            action: "deny".to_string(),
            src: out_iface.to_string(),
            dst: in_iface.to_string(),
            protocol: "any".to_string(),
            port: None,
        };

        // 6. API Protection Policy (ap0 -> local 8443 drop)
        let api_protection = Rule {
            id: "dyn_input_api_protection_01".to_string(),
            action: "deny".to_string(),
            src: in_iface.to_string(),
            dst: "local".to_string(),
            protocol: "tcp".to_string(),
            port: Some(8443),
        };

        let mut rules = vec![nat_rule, fwd_out, fwd_in, isolation, api_protection];

        // 5. Client Isolation Policy (ap0 -> ap0 drop)
        if client_isolation {
            let client_isolation_rule = Rule {
                id: "dyn_isolate_client_01".to_string(),
                action: "deny".to_string(),
                src: in_iface.to_string(),
                dst: in_iface.to_string(),
                protocol: "any".to_string(),
                port: None,
            };
            rules.push(client_isolation_rule);
        }

        // Assemble the dynamic routing policy
        let policy = Policy {
            policy_id: "netbridge_dynamic_nat".to_string(),
            version: "1.0".to_string(),
            rules,
        };

        tracing::debug!("Applying NAT policies to enforcement engine...");
        if let Err(e) = enforcement::apply_policy(&policy) {
            return Err(anyhow!("Failed to enable NAT: {:?}", e));
        }

        self.is_enabled.store(true, Ordering::SeqCst);
        info!("✅ Network routing and Firewall rules successfully applied.");

        Ok(())
    }

    /// Removes all NAT and forwarding policies by clearing the enforcement rules.
    pub fn disable_nat(&self) -> Result<()> {
        if !self.is_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }

        tracing::debug!("Removing NAT and Forwarding policies...");
        if let Err(e) = enforcement::remove_policy() {
            warn!("Failed to cleanly disable NAT rules: {}", e);
            return Err(anyhow!("Failed to disable NAT: {}", e));
        }

        self.is_enabled.store(false, Ordering::SeqCst);
        info!("🔴 Network routing safely disabled.");

        Ok(())
    }

    /// Tracks if NAT is currently enforced.
    pub fn is_enabled(&self) -> bool {
        self.is_enabled.load(Ordering::SeqCst)
    }
}
