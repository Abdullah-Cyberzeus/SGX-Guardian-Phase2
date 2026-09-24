use anyhow::{anyhow, Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const DEFAULT_RULE_DIR: &str = "/etc/suricata/rules";
const DEFAULT_GUARDIAN_RULES: &str = "/etc/suricata/rules/guardian-custom.rules";

const RECON_MARKER: &str = "SGX GUARDIAN RECON TCP PORT SCAN";
const SID_START: u32 = 19_900_001;
const SID_END: u32 = 19_900_099;

fn rule_dir() -> PathBuf {
    std::env::var("SGX_SURICATA_RULE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_RULE_DIR))
}

fn guardian_rules_path() -> PathBuf {
    std::env::var("SGX_SURICATA_GUARDIAN_RULES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_GUARDIAN_RULES))
}

fn sid_in_use(content: &str, sid: u32) -> bool {
    content.contains(&format!("sid:{sid};"))
}

fn read_all_rule_content(dir: &Path) -> Result<String> {
    let mut combined = String::new();

    if !dir.exists() {
        return Ok(combined);
    }

    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed reading Suricata rule directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|v| v.to_str()) != Some("rules") {
            continue;
        }

        match fs::read_to_string(&path) {
            Ok(content) => {
                combined.push_str(&content);
                combined.push('\n');
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "unable to inspect Suricata rule file while allocating SGX SID"
                );
            }
        }
    }

    Ok(combined)
}

fn allocate_sid(all_rules: &str) -> Result<u32> {
    (SID_START..=SID_END)
        .find(|sid| !sid_in_use(all_rules, *sid))
        .ok_or_else(|| {
            anyhow!(
                "no free SGX Suricata SID available in reserved range {}..={}",
                SID_START,
                SID_END
            )
        })
}

/// Ensure the Task4 reconnaissance precursor rule exists.
///
/// Properties:
/// - idempotent across Guardian restarts
/// - does not overwrite administrator/ET rules
/// - detects SID collisions across installed .rules files
/// - does not restart Suricata
/// - uses the Guardian rule file already referenced by suricata.yaml
pub fn ensure_task4_recon_rule() -> Result<()> {
    let rules_path = guardian_rules_path();
    let rules_dir = rule_dir();

    if let Ok(existing) = fs::read_to_string(&rules_path) {
        if existing.contains(RECON_MARKER) {
            tracing::info!(
                path = %rules_path.display(),
                "Task4 reconnaissance Suricata rule already provisioned"
            );
            return Ok(());
        }
    }

    if let Some(parent) = rules_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating Suricata Guardian rule directory {}",
                parent.display()
            )
        })?;
    }

    let all_rules = read_all_rule_content(&rules_dir)?;
    let sid = allocate_sid(&all_rules)?;

    let rule = format!(
        "\n# SG-X Guardian Task4 D5 reconnaissance precursor.\n\
         # Detect repeated TCP SYN reconnaissance from one source.\n\
         alert tcp any any -> $HOME_NET any \
         (msg:\"{RECON_MARKER}\"; flags:S; flow:stateless; \
         detection_filter:track by_src,count 10,seconds 10; \
         classtype:attempted-recon; priority:2; sid:{sid}; rev:1;)\n"
    );

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rules_path)
        .with_context(|| {
            format!(
                "failed opening Guardian Suricata rules {}",
                rules_path.display()
            )
        })?;

    file.write_all(rule.as_bytes())?;
    file.sync_all()?;

    tracing::info!(
        path = %rules_path.display(),
        sid,
        "Task4 reconnaissance Suricata rule provisioned"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_used_sid() {
        let rules = "alert tcp any any -> any any (sid:19900001; rev:1;)";
        assert!(sid_in_use(rules, 19_900_001));
        assert!(!sid_in_use(rules, 19_900_002));
    }

    #[test]
    fn allocates_next_free_sid() {
        let rules = concat!(
            "alert tcp any any -> any any (sid:19900001; rev:1;)\n",
            "alert tcp any any -> any any (sid:19900002; rev:1;)\n"
        );

        assert_eq!(allocate_sid(rules).unwrap(), 19_900_003);
    }
}
