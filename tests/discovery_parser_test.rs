use sgx_guardian_client::discovery::{nmap_parser, ConnectedDevice, DeviceStatus};

const SAMPLE_NMAP_XML: &str = r#"
<nmaprun scanner="nmap" args="nmap -oX - 192.168.50.0/24">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.50.2" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="TestVendor"/>
    <hostnames>
      <hostname name="printer.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.3"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http" product="nginx" version="1.20.1"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="98"/>
    </os>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.50.3" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Apache httpd" version="2.4.54"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.50.4" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.50.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="camera.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="udp" portid="53">
        <state state="open"/>
        <service name="domain" product="dnsmasq"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 4.x" accuracy="95"/>
    </os>
  </host>
</nmaprun>
"#;

const ALIASED_MAC_XML: &str = r#"
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.50.103" addrtype="ipv4"/>
    <address addr="B2:95:75:0E:06:6A" addrtype="mac" vendor="Variscite"/>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.50.45" addrtype="ipv4"/>
    <address addr="B2:95:75:0E:06:6A" addrtype="mac" vendor="Variscite"/>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.42.0.7" addrtype="ipv4"/>
    <address addr="B2:95:75:0E:06:6A" addrtype="mac" vendor="Variscite"/>
  </host>
</nmaprun>
"#;

fn find_by_ip<'a>(devices: &'a [ConnectedDevice], ip: &str) -> &'a ConnectedDevice {
    devices
        .iter()
        .find(|d| d.ip == ip)
        .expect("device not found by ip")
}

#[test]
fn parse_canned_xml_returns_three_up_devices() {
    let devices = nmap_parser::parse(SAMPLE_NMAP_XML).expect("parser should succeed");

    // Deliverable #6 checklist expects 3 discovered devices from canned XML.
    assert_eq!(devices.len(), 3);

    let d1 = find_by_ip(&devices, "192.168.50.2");
    assert_eq!(d1.mac.as_deref(), Some("AA:BB:CC:11:22:33"));
    assert_eq!(d1.vendor.as_deref(), Some("TestVendor"));
    assert_eq!(d1.hostname.as_deref(), Some("printer.local"));
    assert_eq!(d1.os_fingerprint.as_deref(), Some("Linux 5.x"));
    assert_eq!(d1.status, DeviceStatus::Unauthorized);
    assert_eq!(d1.open_ports.len(), 1);
    assert_eq!(d1.open_ports[0].port, 22);
    assert_eq!(d1.open_ports[0].protocol, "tcp");
    assert_eq!(d1.open_ports[0].service.as_deref(), Some("ssh"));
    assert_eq!(
        d1.open_ports[0].product_version.as_deref(),
        Some("OpenSSH 9.3")
    );
    assert_eq!(d1.first_seen, d1.last_seen);
    assert!(!d1.vuln_triaged);

    let d2 = find_by_ip(&devices, "192.168.50.3");
    assert!(d2.mac.is_none());
    assert_eq!(d2.open_ports.len(), 1);
    assert_eq!(d2.open_ports[0].port, 443);
    assert_eq!(
        d2.open_ports[0].product_version.as_deref(),
        Some("Apache httpd 2.4.54")
    );

    let d3 = find_by_ip(&devices, "192.168.50.5");
    assert_eq!(d3.hostname.as_deref(), Some("camera.local"));
    assert_eq!(d3.os_fingerprint.as_deref(), Some("Linux 4.x"));
    assert_eq!(d3.open_ports.len(), 1);
    assert_eq!(d3.open_ports[0].port, 53);
    assert_eq!(d3.open_ports[0].protocol, "udp");
    assert_eq!(d3.open_ports[0].service.as_deref(), Some("domain"));
    assert_eq!(d3.open_ports[0].product_version.as_deref(), Some("dnsmasq"));
}

const AGGRESSIVE_XML: &str = r#"
<nmaprun scanner="nmap" args="nmap -sS -O -sV --script default,safe 192.168.50.0/24">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.50.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="TestVendor"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.20.1">
          <cpe>cpe:/a:igor_sysoev:nginx:1.20.1</cpe>
          <cpe>cpe:/a:nginx:nginx:1.20.1</cpe>
        </service>
        <script id="ssl-cert" output="Subject: commonName=example.local"/>
        <script id="http-title" output="Welcome"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="97">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="97">
          <cpe>cpe:/o:linux:linux_kernel:5.4</cpe>
        </osclass>
      </osmatch>
    </os>
    <hostscript>
      <script id="smb-os-discovery" output="OS: Windows Server 2019"/>
    </hostscript>
  </host>
</nmaprun>
"#;

#[test]
fn parse_captures_nse_scripts_and_cpe() {
    let devices = nmap_parser::parse(AGGRESSIVE_XML).expect("parser should succeed");
    assert_eq!(devices.len(), 1);
    let d = find_by_ip(&devices, "192.168.50.10");

    // OS CPE pulled from <osmatch>/<osclass>.
    assert_eq!(d.os_fingerprint.as_deref(), Some("Linux 5.4"));
    assert_eq!(d.os_cpe, vec!["cpe:/o:linux:linux_kernel:5.4".to_string()]);

    // Host-level NSE output.
    assert_eq!(d.host_scripts.len(), 1);
    assert_eq!(d.host_scripts[0].id, "smb-os-discovery");
    assert!(d.host_scripts[0].output.contains("Windows Server 2019"));

    // Port-level service CPE + NSE scripts.
    assert_eq!(d.open_ports.len(), 1);
    let p = &d.open_ports[0];
    assert_eq!(p.port, 443);
    assert_eq!(
        p.cpe,
        vec![
            "cpe:/a:igor_sysoev:nginx:1.20.1".to_string(),
            "cpe:/a:nginx:nginx:1.20.1".to_string()
        ]
    );
    assert_eq!(p.scripts.len(), 2);
    assert!(p.scripts.iter().any(|s| s.id == "ssl-cert"));
    assert!(p
        .scripts
        .iter()
        .any(|s| s.id == "http-title" && s.output == "Welcome"));
}

#[test]
fn parse_invalid_xml_returns_xml_parse_error() {
    let err = nmap_parser::parse("<nmaprun><host>").expect_err("parser should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("XML parse error"),
        "unexpected error message: {}",
        msg
    );
}

#[test]
fn parse_strips_mac_from_aliased_duplicates() {
    let devices = nmap_parser::parse(ALIASED_MAC_XML).expect("parser should succeed");
    assert_eq!(devices.len(), 3);

    let with_mac: Vec<_> = devices.iter().filter(|d| d.mac.is_some()).collect();
    let without_mac: Vec<_> = devices.iter().filter(|d| d.mac.is_none()).collect();

    assert_eq!(with_mac.len(), 1);
    assert_eq!(without_mac.len(), 2);

    for d in &without_mac {
        assert!(
            d.vendor
                .as_deref()
                .unwrap_or("")
                .starts_with("(mac_aliased"),
            "vendor should mark aliasing, got {:?}",
            d.vendor
        );
    }
}
