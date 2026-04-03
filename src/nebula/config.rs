// src/nebula/config.rs  — FULL REPLACEMENT
// Key fix: generate_config_from_pool now accepts an optional
// lighthouse_lan_ip parameter so member nodes embed the real
// nodeA LAN IP instead of the placeholder "LIGHTHOUSE_PUBLIC_IP".

use crate::nebula::overlay::OverlayPool;
use std::fs;
use std::io::Write;
use std::path::Path;

pub struct NebulaConfig;

impl NebulaConfig {
    /// Legacy helper kept for backward compatibility.
    pub fn generate_config(
        node_name: &str,
        _overlay_ip: &str,
        is_lighthouse: bool,
        config_dir: &str,
    ) -> Result<(), std::io::Error> {
        let config_path = format!("{}/nebula.yaml", config_dir);

        if Path::new(&config_path).exists() {
            println!("ℹ️  Nebula config already exists at {}", config_path);
            return Ok(());
        }

        fs::create_dir_all(config_dir)?;

        let lighthouse_config = if is_lighthouse {
            "lighthouse:\n  am_lighthouse: true\n  interval: 60\n".to_string()
        } else {
            "lighthouse:\n  am_lighthouse: false\n  interval: 60\n  hosts:\n    - \"192.168.100.1\"\n".to_string()
        };

        let config_content = format!(
            r#"pki:
  ca: "{dir}/ca/ca.crt"
  cert: "{dir}/nodes/{node}.crt"
  key: "{dir}/nodes/{node}.key"

static_host_map: {{}}

listen:
  host: 0.0.0.0
  port: 4242

tun:
  dev: nebula0
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any

{lh}
"#,
            dir  = config_dir,
            node = node_name,
            lh   = lighthouse_config,
        );

        let mut file = fs::File::create(config_path)?;
        file.write_all(config_content.as_bytes())?;
        println!("✅ Nebula configuration generated (legacy).");
        Ok(())
    }

    /// PRIMARY entry point called from main.rs.
    ///
    /// `lighthouse_lan_ip` — the real LAN IP of nodeA (e.g. "192.168.1.42").
    ///   Pass `None` only for nodeA itself (it IS the lighthouse).
    ///   Pass `Some(ip)` for every member node so they can reach the lighthouse.
    ///
    /// The config is ALWAYS regenerated (the old file is removed first) so that
    /// an updated nodeA LAN IP is picked up on every restart.
    pub fn generate_config_from_pool(
        node_name: &str,
        pool: &OverlayPool,
        config_dir: &str,
    ) -> Result<(), std::io::Error> {
        // Delegate to the version that accepts an explicit lighthouse IP.
        // Derive it from the environment variable SGX_LIGHTHOUSE_IP if set,
        // otherwise fall back to a sensible default that callers may override.
        let lighthouse_ip = std::env::var("SGX_LIGHTHOUSE_IP").ok();
        Self::generate_config_from_pool_with_lighthouse(
            node_name,
            pool,
            config_dir,
            lighthouse_ip.as_deref(),
        )
    }

    /// Full version: takes an explicit lighthouse LAN IP.
    ///
    /// Called from `main.rs` with the detected nodeA LAN IP so we never
    /// embed a placeholder.
    pub fn generate_config_from_pool_with_lighthouse(
        node_name: &str,
        pool: &OverlayPool,
        config_dir: &str,
        lighthouse_lan_ip: Option<&str>,
    ) -> Result<(), std::io::Error> {
        let config_path = format!("{}/nebula.yaml", config_dir);

        fs::create_dir_all(config_dir)?;

        // Get this node's overlay IP from the pool.
        let overlay_ip = pool.get_ip_cidr(node_name).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No overlay IP allocated for {}", node_name),
            )
        })?;

        let is_lighthouse = node_name == pool.owner_node;

        let owner_overlay_ip = pool
            .get_ip(&pool.owner_node)
            .cloned()
            .unwrap_or_else(|| format!("{}.1", pool.subnet_base));

        // ── Lighthouse section ────────────────────────────────────────────
        let lighthouse_section = if is_lighthouse {
            "lighthouse:\n  am_lighthouse: true\n  interval: 60\n".to_string()
        } else {
            format!(
                "lighthouse:\n  am_lighthouse: false\n  interval: 60\n  hosts:\n    - \"{overlay_ip_lh}\"\n",
                overlay_ip_lh = owner_overlay_ip
            )
        };

        // ── static_host_map section ───────────────────────────────────────
        // The lighthouse node does not need a static_host_map entry for itself.
        // Member nodes MUST have a real LAN IP:port so they can bootstrap
        // before the overlay is up (they can't reach 192.168.100.1 yet!).
        let static_host_map_section = if is_lighthouse {
            // Lighthouse advertises nothing in static_host_map.
            "static_host_map: {}\n".to_string()
        } else {
            match lighthouse_lan_ip {
                Some(lan_ip) if !lan_ip.is_empty()
                    && lan_ip != "0.0.0.0"
                    && lan_ip != "127.0.0.1" =>
                {
                    // Use the actual LAN IP so members can reach nodeA's UDP 4242
                    // before the overlay tunnel is established.
                    format!(
                        "static_host_map:\n  \"{owner_ov}\": [\"{lan}:4242\"]\n",
                        owner_ov = owner_overlay_ip,
                        lan      = lan_ip,
                    )
                }
                _ => {
                    // Fallback: warn loudly; the overlay will not work until
                    // nodeA's real IP is known.
                    eprintln!(
                        "⚠️  [NebulaConfig] No valid lighthouse LAN IP provided for {}. \
                         Nebula tunnel will NOT work until nodeA's IP is discovered. \
                         Set SGX_LIGHTHOUSE_IP=<nodeA-lan-ip> or ensure nodeA broadcasts \
                         before this node starts.",
                        node_name
                    );
                    format!(
                        "static_host_map:\n  \"{owner_ov}\": [\"NEEDS_NODEА_LAN_IP:4242\"]\n",
                        owner_ov = owner_overlay_ip
                    )
                }
            }
        };

        // ── Relay section (Nebula ≥ 1.7) ─────────────────────────────────
        // Members should relay through the lighthouse if direct path fails.
        let relay_section = if is_lighthouse {
            "relay:\n  am_relay: true\n  use_relays: false\n".to_string()
        } else {
            format!(
                "relay:\n  am_relay: false\n  use_relays: true\n  relays:\n    - \"{}\"\n",
                owner_overlay_ip
            )
        };

        let config_content = format!(
            r#"# Auto-generated by SG-X Guardian Overlay Manager
# REGENERATED on every start — edits will be overwritten.
# Circle: {circle}
# Node:   {node} | Overlay IP: {ov_ip}

pki:
  ca: "{dir}/ca/ca.crt"
  cert: "{dir}/nodes/{node}.crt"
  key: "{dir}/nodes/{node}.key"

{shm}
{lh}
listen:
  host: 0.0.0.0
  port: 4242

{relay}

tun:
  dev: nebula0
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500

# Logging — set to debug for initial bring-up, then switch to info.
logging:
  level: info

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
"#,
            circle = pool.circle_id,
            node   = node_name,
            ov_ip  = overlay_ip,
            dir    = config_dir,
            shm    = static_host_map_section,
            lh     = lighthouse_section,
            relay  = relay_section,
        );

        // Always overwrite — we want fresh IPs on every start.
        let tmp_path = format!("{}.tmp", config_path);
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(config_content.as_bytes())?;
        drop(file);
        fs::rename(&tmp_path, &config_path)?;

        println!(
            "✅ Nebula config written: {} → {} (tun: nebula0, lighthouse_lan: {})",
            node_name,
            overlay_ip,
            lighthouse_lan_ip.unwrap_or("self"),
        );
        Ok(())
    }
}

// ── Unit Tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::nebula::overlay::OverlayPool;

    fn tmp(suffix: &str) -> String {
        format!("/tmp/test_nebula_cfg_{}", suffix)
    }

    #[test]
    fn test_lighthouse_config_has_no_static_host_map_entry() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        let dir  = tmp("lh");
        let _    = std::fs::create_dir_all(&dir);
        NebulaConfig::generate_config_from_pool_with_lighthouse("nodeA", &pool, &dir, None)
            .unwrap();
        let c = std::fs::read_to_string(format!("{}/nebula.yaml", dir)).unwrap();
        assert!(c.contains("am_lighthouse: true"));
        assert!(c.contains("static_host_map: {}"));
        assert!(c.contains("dev: nebula0"));
        assert!(!c.contains("LIGHTHOUSE_PUBLIC_IP"));
        assert!(!c.contains("NEEDS_NODE"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_member_embeds_real_lan_ip() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        pool.allocate("nodeB").unwrap();
        let dir = tmp("mb");
        let _   = std::fs::create_dir_all(&dir);
        NebulaConfig::generate_config_from_pool_with_lighthouse(
            "nodeB", &pool, &dir, Some("192.168.1.42"),
        ).unwrap();
        let c = std::fs::read_to_string(format!("{}/nebula.yaml", dir)).unwrap();
        assert!(c.contains("am_lighthouse: false"));
        assert!(c.contains("192.168.1.42:4242"),
            "Expected real LAN IP in static_host_map, got:\n{}", c);
        assert!(!c.contains("LIGHTHOUSE_PUBLIC_IP"));
        assert!(!c.contains("NEEDS_NODE"));
        assert!(c.contains("192.168.100.2/24"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_member_warns_when_no_lan_ip() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        pool.allocate("nodeB").unwrap();
        let dir = tmp("mb_no_ip");
        let _   = std::fs::create_dir_all(&dir);
        // None → should still succeed but embed placeholder warning text
        NebulaConfig::generate_config_from_pool_with_lighthouse(
            "nodeB", &pool, &dir, None,
        ).unwrap();
        let c = std::fs::read_to_string(format!("{}/nebula.yaml", dir)).unwrap();
        assert!(c.contains("NEEDS_NODE"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_always_overwritten() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        let dir  = tmp("overwrite");
        let _    = std::fs::create_dir_all(&dir);
        // Write once with old IP
        NebulaConfig::generate_config_from_pool_with_lighthouse(
            "nodeA", &pool, &dir, Some("10.0.0.1"),
        ).unwrap();
        // Write again with new IP — should overwrite
        NebulaConfig::generate_config_from_pool_with_lighthouse(
            "nodeA", &pool, &dir, Some("10.0.0.99"),
        ).unwrap();
        let c = std::fs::read_to_string(format!("{}/nebula.yaml", dir)).unwrap();
        // The second write should win
        assert!(!c.contains("10.0.0.1"), "Old IP should have been overwritten");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_config_unallocated_node_fails() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        let dir  = tmp("unalloc");
        let result = NebulaConfig::generate_config_from_pool_with_lighthouse(
            "nodeZ", &pool, &dir, None,
        );
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tun_device_is_nebula0() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        let dir  = tmp("tun");
        let _    = std::fs::create_dir_all(&dir);
        NebulaConfig::generate_config_from_pool_with_lighthouse("nodeA", &pool, &dir, None).unwrap();
        let c = std::fs::read_to_string(format!("{}/nebula.yaml", dir)).unwrap();
        assert!(c.contains("dev: nebula0"));
        assert!(!c.contains("dev: nebula1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_relay_section_present() {
        let mut pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        pool.allocate("nodeB").unwrap();
        let dir = tmp("relay");
        let _   = std::fs::create_dir_all(&dir);
        NebulaConfig::generate_config_from_pool_with_lighthouse(
            "nodeB", &pool, &dir, Some("10.1.2.3"),
        ).unwrap();
        let c = std::fs::read_to_string(format!("{}/nebula.yaml", dir)).unwrap();
        assert!(c.contains("use_relays: true"));
        assert!(c.contains("192.168.100.1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}