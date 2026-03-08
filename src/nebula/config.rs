use std::fs;
use std::io::Write;
use std::path::Path;

pub struct NebulaConfig;

impl NebulaConfig {
    pub fn generate_config(
        node_name: &str,
        _overlay_ip: &str,
        is_lighthouse: bool,
        config_dir: &str,
    ) -> Result<(), std::io::Error> {
        let config_path = format!("{}/nebula.yaml", config_dir);

        if Path::new(&config_path).exists() {
            println!("ℹ️ Nebula config already exists.");
            return Ok(());
        }

        fs::create_dir_all(config_dir)?;

        let lighthouse_config = if is_lighthouse {
            r#"
lighthouse:
  am_lighthouse: true
  interval: 60
"#
            .to_string()
        } else {
            r#"
lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "192.168.100.1"
"#
            .to_string()
        };

        let config_content = format!(
            r#"
pki:
  ca: "{}/ca/ca.crt"
  cert: "{}/nodes/{}.crt"
  key: "{}/nodes/{}.key"

static_host_map:
  "192.168.100.1": ["YOUR_LIGHTHOUSE_PUBLIC_IP:4242"]

listen:
  host: 0.0.0.0
  port: 4242

firewall:
  outbound:
    - port: any
      proto: any
      host: any

tun:
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500

{}

"#,
            config_dir, config_dir, node_name, config_dir, node_name, lighthouse_config
        );

        let mut file = fs::File::create(config_path)?;
        file.write_all(config_content.as_bytes())?;

        println!("✅ Nebula configuration generated.");
        Ok(())
    }
}
