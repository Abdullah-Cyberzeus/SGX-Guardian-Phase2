// src/nebula/relay_tc.rs
// ============================================================
// Relay traffic shaping via Linux tc (HTB).
// ============================================================

use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct TcStats {
    pub bytes_sent: u64,
    pub packets_sent: u64,
    pub current_mbps: f64,
}

pub struct RelayTrafficControl;

impl RelayTrafficControl {
    /// Apply HTB rate limit to nebula0 outbound traffic.
    pub fn apply_bandwidth_limit(mbps: u32) -> Result<(), String> {
        if mbps == 0 {
            return Self::clear();
        }

        // Verify TUN is fully registered BEFORE applying tc.
        // Without this, a partially-registered netdev caused kernel RCU
        // stalls on i.MX8 boards (observed post-Sprint-4).
        if !std::path::Path::new("/sys/class/net/nebula0/flags").exists() {
            return Err("nebula0 not registered — skip tc (fixes RCU stall on i.MX8)".into());
        }

        Self::clear()?;
        Self::run(&[
            "qdisc", "add", "dev", "nebula0", "root", "handle", "1:", "htb", "default", "10",
        ])?;
        let rate = format!("{}mbit", mbps);
        Self::run(&[
            "class", "add", "dev", "nebula0", "parent", "1:", "classid", "1:1", "htb", "rate",
            &rate, "ceil", &rate,
        ])?;
        println!("🚦 Relay bandwidth limit applied: {} Mbps via tc", mbps);
        Ok(())
    }

    pub fn clear() -> Result<(), String> {
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", "nebula0", "root"])
            .output();
        Ok(())
    }

    pub fn current_stats() -> Option<TcStats> {
        let output = Command::new("tc")
            .args(["-s", "class", "show", "dev", "nebula0"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        Self::parse_stats(&text)
    }

    pub fn parse_stats(text: &str) -> Option<TcStats> {
        let mut bytes_sent = 0u64;
        let mut packets_sent = 0u64;
        let mut current_mbps = 0.0f64;

        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("Sent ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 3 {
                    bytes_sent = parts[0].parse::<u64>().ok().unwrap_or(0);
                    packets_sent = parts[2].parse::<u64>().ok().unwrap_or(0);
                }
            }
            if trimmed.contains("rate ") {
                // Example: "... rate 5Mbit ceil 5Mbit ..."
                if let Some(rate_token) = trimmed
                    .split_whitespace()
                    .skip_while(|t| *t != "rate")
                    .nth(1)
                {
                    current_mbps = parse_rate_token_to_mbps(rate_token).unwrap_or(0.0);
                }
            }
        }

        if bytes_sent == 0 && packets_sent == 0 && current_mbps == 0.0 {
            return None;
        }

        Some(TcStats {
            bytes_sent,
            packets_sent,
            current_mbps,
        })
    }

    fn run(args: &[&str]) -> Result<(), String> {
        let out = Command::new("tc")
            .args(args)
            .output()
            .map_err(|e| format!("tc spawn failed: {}", e))?;
        if !out.status.success() {
            return Err(format!(
                "tc {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }
}

fn parse_rate_token_to_mbps(rate_token: &str) -> Option<f64> {
    let lower = rate_token.to_ascii_lowercase();
    if let Some(v) = lower.strip_suffix("mbit") {
        return v.parse::<f64>().ok();
    }
    if let Some(v) = lower.strip_suffix("kbit") {
        return v.parse::<f64>().ok().map(|x| x / 1000.0);
    }
    if let Some(v) = lower.strip_suffix("gbit") {
        return v.parse::<f64>().ok().map(|x| x * 1000.0);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tc_stats() {
        let sample = r#"
class htb 1:1 root rate 5Mbit ceil 5Mbit burst 1599b cburst 1599b
 Sent 1234567 bytes 2345 pkt (dropped 0, overlimits 0 requeues 0)
"#;
        let parsed = RelayTrafficControl::parse_stats(sample).unwrap();
        assert_eq!(parsed.bytes_sent, 1_234_567);
        assert_eq!(parsed.packets_sent, 2345);
        assert!((parsed.current_mbps - 5.0).abs() < 0.001);
    }
}
