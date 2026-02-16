use super::models::CircleMembership;
use super::utils::validate_circle_membership;
use std::fs;
use std::io::Error;
use std::path::Path;
use std::process::Command;
pub struct NebulaCA;

impl NebulaCA {
    /// Generate new Nebula CA (only once per Circle)
    pub fn generate_ca(ca_dir: &str) -> Result<(), Error> {
        if Path::new(&format!("{}/ca.key", ca_dir)).exists() {
            println!("ℹ️ CA already exists.");
            return Ok(());
        }

        fs::create_dir_all(ca_dir)?;

        let output = Command::new("nebula-cert")
            .arg("ca")
            .arg("-name")
            .arg("guardian-circle-ca")
            .current_dir(ca_dir)
            .output()?;

        if !output.status.success() {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "CA generation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        println!("✅ Nebula CA generated successfully.");
        Ok(())
    }

    /// Issue certificate for a Guardian node
    pub fn issue_node_cert(
        ca_dir: &str,
        membership: &CircleMembership,
        ip: &str,
    ) -> Result<(), Error> {
        if !validate_circle_membership(membership) {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                "Circle membership validation failed",
            ));
        }

        // check already node certificate exists
        let cert_path = format!("{}/{}.crt", ca_dir, membership.node_name);

        if Path::new(&cert_path).exists() {
            println!("ℹ️ Certificate already exists for {}", membership.node_name);
            return Ok(());
        }
        // if not exist then genreate certificate using nebula-cert command
        let output = Command::new("nebula-cert")
            .arg("sign")
            .arg("-name")
            .arg(&membership.node_name)
            .arg("-ip")
            .arg(ip)
            .arg("-duration")
            .arg("8760h") // 1 year validity
            .arg("-ca-crt")
            .arg("-groups")
            .arg("guardian,member")
            .arg(format!("{}/ca.crt", ca_dir))
            .arg("-ca-key")
            .arg(format!("{}/ca.key", ca_dir))
            .current_dir(ca_dir)
            .output()?;

        if !output.status.success() {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Certificate signing failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        println!("✅ Certificate issued for {}", membership.node_name);

        Ok(())
    }
}