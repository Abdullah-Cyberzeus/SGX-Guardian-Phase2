use super::models::CircleMembership;
use super::utils::validate_circle_membership;
use std::fs;
use std::io::Error;
use std::path::Path;
use std::process::Command;
pub struct NebulaCA;

impl NebulaCA {
    /// Generate new Nebula CA (only once per Circle)
    pub fn generate_ca(base_dir: &str) -> Result<(), Error> {
        let ca_dir = format!("{}/ca", base_dir);

        if Path::new(&format!("{}/ca.key", ca_dir)).exists() {
            println!("ℹ️ CA already exists.");
            return Ok(());
        }

        fs::create_dir_all(&ca_dir)?;

        let output = Command::new("nebula-cert")
            .arg("ca")
            .arg("-name")
            .arg("guardian-circle-ca")
            .current_dir(&ca_dir)
            .output()?;

        if !output.status.success() {
            return Err(Error::other(format!(
                "CA generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        println!("✅ Nebula CA generated successfully.");
        Ok(())
    }

    /// Issue certificate for a Guardian node
    pub fn issue_node_cert(
        base_dir: &str,
        membership: &CircleMembership,
        ip: &str,
    ) -> Result<(), Error> {
        if !validate_circle_membership(membership) {
            return Err(Error::other("Circle membership validation failed"));
        }

        let ca_dir = format!("{}/ca", base_dir);
        let nodes_dir = format!("{}/nodes", base_dir);

        fs::create_dir_all(&nodes_dir)?;

        let cert_path = format!("{}/{}.crt", nodes_dir, membership.node_name);
        let key_path = format!("{}/{}.key", nodes_dir, membership.node_name);

        let cert_exists = Path::new(&cert_path).exists();
        let key_exists = Path::new(&key_path).exists();

        if cert_exists && key_exists {
            println!(
                "ℹ️ Certificate and key already exist for {}",
                membership.node_name
            );
            return Ok(());
        }

        // Detect partial state (corruption / incomplete issuance)
        if cert_exists != key_exists {
            return Err(Error::other(
    format!(
            "Partial certificate state detected for {} (cert: {}, key: {}). Manual intervention required.",
            membership.node_name, cert_exists, key_exists
        ),
    ));
        }

        let output = Command::new("nebula-cert")
            .arg("sign")
            .arg("-name")
            .arg(&membership.node_name)
            .arg("-ip")
            .arg(ip)
            .arg("-duration")
            .arg("8700h")
            .arg("-groups")
            .arg("guardian,member")
            .arg("-ca-crt")
            .arg(format!("{}/ca.crt", ca_dir))
            .arg("-ca-key")
            .arg(format!("{}/ca.key", ca_dir))
            .arg("-out-crt")
            .arg(&cert_path)
            .arg("-out-key")
            .arg(&key_path)
            .output()?;

        if !output.status.success() {
            return Err(Error::other(format!(
                "Certificate signing failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        println!("✅ Certificate issued for {}", membership.node_name);

        Ok(())
    }
}
