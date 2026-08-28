export const mockUser = {
  id: "usr_001",
  name: "Marcus Rivera",
  email: "marcus.rivera@cervais.com",
  role: "Field Security Engineer",
  avatar: "MR",
  did: "did:cervais:0x7a3f9b2c8d1e4a6f5c0b3e7d2a9f1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2f1c4b8e6d3",
};

export const mockGuardian = {
  id: "grd_001",
  name: "Guardian-TX-042",
  deviceId: "GX-2024-TX-042-A9F3",
  firmware: "v4.2.1",
  uptime: "14d 6h 32m",
  connectionType: "WiFi",
  signal: 87,
  peerCount: 8,
  status: "online" as const,
  lastSeen: "Just now",
  ip: "192.168.1.100",
  mac: "A4:C3:F0:85:7B:2E",
  model: "Guardian X Series",
  serialNumber: "GX2024TX042A9F3",
  // Node status fields (maps to: sgx-pa-cli status)
  hostname: "guardian-tx-042.local",
  port: 50052,
  publicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr3kVZxPQ8N9m7HcXdL4fYWqAKpT2dE6nM5aB9vC0xR8yH3jF2bG7nK4mP1qS5tU6wX0zA8dC2eF4gI5hJ7kL9M==",
  // Wi-Fi mode fields
  wifi_mode_enabled: true,
  wifi_operation_mode: 'dual' as const,
  wifi_ssid: 'ARMIA',
  wifi_profile: '2.4GHz' as const,
  wifi_client_ssid: 'HotelGuest',
  zero_trust_active: true,
};

export const mockAlerts = [
  {
    id: "alt_001",
    severity: "HIGH" as const,
    title: "Unauthorized Service Account Login",
    description: "Service account svc_monitor used for unauthorized SSH login from external IP",
    eventType: "Authentication Failure",
    status: "Active",
    timestamp: "9:14 AM",
    date: "Today",
    device: "PLC-Controller-03",
    deviceIp: "10.0.2.47",
    os: "Linux Embedded 5.4",
    aiSummary: "A privileged service account attempted lateral movement via SSH. This pattern matches known APT-29 techniques. Immediate isolation recommended.",
    aiDetail: {
      whatHappened: "At 09:14 AM, service account svc_monitor — a non-interactive account used for automated monitoring tasks — was observed initiating an SSH session from an external IP address (203.0.113.47) to PLC-Controller-03 at 10.0.2.47. This account is not authorized for interactive login and has never been used from outside the facility network.",
      whyItMatters: "Service accounts with lateral movement capability are a primary attack vector in ICS/SCADA environments. The external IP does not match any known VPN endpoint or partner network. This behavior is consistent with credential theft followed by targeted intrusion into the operational technology (OT) network segment.",
      actions: [
        "Immediately disable svc_monitor credentials in Active Directory and the local device auth store.",
        "Isolate PLC-Controller-03 from the network segment pending forensic review.",
        "Capture a memory dump and network packet capture from the affected system.",
        "Review access logs on all systems where svc_monitor has permissions.",
        "Notify the incident response team (Circle: Texas Grid Ops) and file an incident report.",
      ],
    },
    archived: false,
  },
  {
    id: "alt_002",
    severity: "HIGH" as const,
    title: "Anomalous Network Traffic Spike",
    description: "Outbound traffic 340% above baseline on port 443 — possible data exfiltration",
    eventType: "Network Anomaly",
    status: "Active",
    timestamp: "8:52 AM",
    date: "Today",
    device: "SCADA-Server-01",
    deviceIp: "10.0.1.12",
    os: "Windows Server 2019",
    aiSummary: "Traffic pattern suggests potential C2 communication or data staging. The volume and timing correlate with off-hours scheduled tasks.",
    aiDetail: {
      whatHappened: "SCADA-Server-01 generated 2.3GB of outbound HTTPS traffic over a 40-minute window beginning at 08:12 AM. Normal baseline for this server is under 200MB per day. The destination IPs resolve to Cloudflare-fronted endpoints with no legitimate business relationship.",
      whyItMatters: "This volume of outbound encrypted traffic from an air-gapped-adjacent OT server is a critical indicator of either data exfiltration or active C2 beacon communication. The use of HTTPS makes deep inspection difficult without a TLS inspection proxy.",
      actions: [
        "Block all outbound traffic from 10.0.1.12 at the perimeter firewall immediately.",
        "Capture full packet logs from the last 2 hours for forensic analysis.",
        "Review Windows Task Scheduler for unauthorized scheduled tasks.",
        "Check for unauthorized software installations in the last 72 hours.",
        "Escalate to IR team Alpha for full forensic investigation.",
      ],
    },
    archived: false,
  },
  {
    id: "alt_003",
    severity: "MEDIUM" as const,
    title: "Firmware Version Mismatch Detected",
    description: "Device firmware is 3 major versions behind — known CVEs exist for this version",
    eventType: "Vulnerability",
    status: "Acknowledged",
    timestamp: "7:30 AM",
    date: "Today",
    device: "SmartMeter-Bay-7",
    deviceIp: "10.0.3.91",
    os: "Embedded RTOS 2.1",
    aiSummary: "CVE-2023-4812 and CVE-2023-5109 affect this firmware version. Both allow remote code execution. Patch window should be scheduled within 48 hours.",
    aiDetail: {
      whatHappened: "SmartMeter-Bay-7 is running firmware v1.2.0, while the current vendor-approved version is v1.5.2. Guardian's vulnerability scanner identified two critical CVEs (CVE-2023-4812, CVE-2023-5109) that are present in versions prior to v1.4.0.",
      whyItMatters: "Both CVEs allow unauthenticated remote code execution via the device's web management interface. Smart meters in Bay-7 are accessible from the facility's secondary network segment which has 14 other connected devices.",
      actions: [
        "Schedule an emergency firmware update within the next 48 hours.",
        "Block web management port (TCP 80/443) on SmartMeter-Bay-7 at the segment firewall until patched.",
        "Audit all other Honeywell devices on the same firmware version.",
        "Download and verify the v1.5.2 firmware package from the vendor portal.",
      ],
    },
    archived: false,
  },
  {
    id: "alt_004",
    severity: "MEDIUM" as const,
    title: "New Unrecognized Device Connected",
    description: "MAC address not in approved device registry — requires manual approval",
    eventType: "Device Discovery",
    status: "Active",
    timestamp: "6:15 AM",
    date: "Today",
    device: "Unknown Device",
    deviceIp: "10.0.4.203",
    os: "Unknown",
    aiSummary: "Device fingerprint suggests a consumer-grade IoT device. It does not match any approved asset in the registry. Physical verification recommended.",
    aiDetail: {
      whatHappened: "An unregistered device with MAC address B2:4F:C9:12:8A:56 connected to the facility WiFi network at 06:15 AM. The OUI prefix maps to a consumer electronics manufacturer. DHCP fingerprinting suggests an Android-based device or generic IoT.",
      whyItMatters: "Unregistered devices on OT-adjacent networks represent a potential insider threat or unauthorized access point. Consumer IoT devices often carry unpatched vulnerabilities and may be used as pivot points.",
      actions: [
        "Identify the physical device by cross-referencing with facility access logs.",
        "Quarantine the device's IP at the network switch level.",
        "Approve or reject the device from the Devices > Pending Approvals screen.",
        "If device is unauthorized, escalate to physical security team.",
      ],
    },
    archived: false,
  },
  {
    id: "alt_005",
    severity: "LOW" as const,
    title: "Certificate Expiry Warning",
    description: "TLS certificate for SCADA API endpoint expires in 7 days",
    eventType: "Certificate",
    status: "Active",
    timestamp: "2:00 AM",
    date: "Today",
    device: "API-Gateway-01",
    deviceIp: "10.0.1.5",
    os: "Ubuntu 22.04",
    aiSummary: "Automated certificate renewal failed. Manual renewal required. Expired certificates will cause service disruption and potential security gaps.",
    aiDetail: {
      whatHappened: "The TLS certificate for the SCADA API endpoint (api.scada.internal) is scheduled to expire on March 24, 2026. The automated Let's Encrypt renewal process failed on March 10 with error: DNS-01 challenge timeout.",
      whyItMatters: "An expired certificate will cause service disruption for all systems that verify TLS certificates when connecting to the SCADA API. It may also trigger security alerts in monitoring systems that flag certificate errors as potential MITM attacks.",
      actions: [
        "Manually renew the TLS certificate using certbot with DNS challenge.",
        "Investigate why the automated renewal failed — check DNS configuration.",
        "Verify the renewed certificate is deployed across all load balancers.",
        "Test SCADA API connectivity after renewal.",
      ],
    },
    archived: false,
  },
  {
    id: "alt_006",
    severity: "HIGH" as const,
    title: "Failed Login Brute Force Attempt",
    description: "47 failed login attempts in 3 minutes from IP 198.51.100.22",
    eventType: "Brute Force",
    status: "Blocked",
    timestamp: "Yesterday",
    date: "Yesterday",
    device: "VPN-Gateway-01",
    deviceIp: "10.0.0.1",
    os: "pfSense 2.7.0",
    aiSummary: "IP has been auto-blocked. This IP appears on 3 threat intelligence feeds. No successful authentication occurred.",
    aiDetail: {
      whatHappened: "A rapid sequence of 47 failed SSH authentication attempts originated from IP 198.51.100.22 between 11:34 PM and 11:37 PM. The attempts used a dictionary attack pattern targeting common usernames (admin, root, user, operator).",
      whyItMatters: "While no successful authentication occurred, this is a reconnaissance indicator. The source IP appears on Spamhaus XBL, AbuseIPDB, and the Cervais Threat Intelligence feed as a known scanning host.",
      actions: [
        "IP has been auto-blocked by Guardian's threat response engine.",
        "Review VPN-Gateway-01 authentication logs for the past 24 hours.",
        "Ensure fail2ban or equivalent is active on all exposed services.",
        "Add IP range to permanent block list if attacks persist.",
      ],
    },
    archived: true,
  },
];

export const mockCircles = [
  {
    id: "cir_001",
    name: "Texas Grid Ops",
    memberCount: 6,
    onlineCount: 4,
    description: "Primary operations team for Texas energy grid monitoring and incident response.",
    inviteCode: "TXG-OPS-7X2K-9M4P",
    inviteLink: "https://sgx.cervais.com/join/TXG-OPS-7X2K-9M4P",
    messages: [
      { id: "msg_001", sender: "Sofia Chen", initials: "SC", content: "Alert alt_002 escalated — reviewing now", timestamp: "9:05 AM", isMe: false, read: true },
      { id: "msg_002", sender: "Me", initials: "MR", content: "On it. Isolating SCADA-01 from the network segment.", timestamp: "9:07 AM", isMe: true, read: true },
      { id: "msg_003", sender: "James Park", initials: "JP", content: "Running packet capture from my end. Will share findings in 10.", timestamp: "9:08 AM", isMe: false, read: true },
      { id: "msg_004", sender: "Sofia Chen", initials: "SC", content: "Good. Marcus, document every action for the incident report.", timestamp: "9:10 AM", isMe: false, read: true },
      { id: "msg_005", sender: "Me", initials: "MR", content: "Acknowledged. Packet capture started on my end too.", timestamp: "9:11 AM", isMe: true, read: false },
      { id: "msg_006", sender: "James Park", initials: "JP", content: "", timestamp: "9:19 AM", isMe: false, read: true, attachment: { name: "scada-01-capture.png", sizeBytes: 842_137, mime: "image/png", kind: "image" as const, url: "data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20width='280'%20height='200'%3E%3Crect%20width='280'%20height='200'%20fill='%231f2d3d'/%3E%3Crect%20x='40'%20y='44'%20width='200'%20height='72'%20rx='6'%20fill='%233b82f6'%20opacity='0.35'/%3E%3Ctext%20x='140'%20y='162'%20fill='%23cbd5e1'%20font-family='sans-serif'%20font-size='13'%20text-anchor='middle'%3ESCADA-01%20packet%20capture%3C/text%3E%3C/svg%3E" } },
      { id: "msg_007", sender: "Sofia Chen", initials: "SC", content: "", timestamp: "9:43 AM", isMe: false, read: true, attachment: { name: "incident-alt002-report.pdf", sizeBytes: 1_258_291, mime: "application/pdf", kind: "file" as const, url: "data:text/plain,SGX%20Guardian%20incident%20report%20alt_002%20(demo%20file)" } },
    ],
    members: [
      { id: "mem_001", name: "Sofia Chen", email: "sofia.chen@cervais.com", role: "Owner" as const, status: "online" as const, lastSeen: "Now", did: "did:cervais:0x9b2c5e8d1a4f7b0c3e6d9a2f1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2f1c4" },
      { id: "mem_002", name: "Marcus Rivera", email: "marcus.rivera@cervais.com", role: "Member" as const, status: "online" as const, lastSeen: "Now", did: "did:cervais:0x7a3f9b2c8d1e4a6f5c0b3e7d2a9f1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2" },
      { id: "mem_003", name: "James Park", email: "james.park@cervais.com", role: "Member" as const, status: "online" as const, lastSeen: "Now", did: "did:cervais:0x3e6d9a2f1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2f1c4b8e6d3a7f9b2c5e8" },
      { id: "mem_004", name: "Aisha Okonkwo", email: "aisha.okonkwo@cervais.com", role: "Member" as const, status: "offline" as const, lastSeen: "2h ago", did: "did:cervais:0xf1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2f1c4b8e6d3a7f9b2c5e8d1a4f7b" },
      { id: "mem_005", name: "Raj Patel", email: "raj.patel@cervais.com", role: "Member" as const, status: "offline" as const, lastSeen: "5h ago", did: "did:cervais:0xb8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2f1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e", pending: true },
      { id: "mem_006", name: "Dana Walsh", email: "dana.walsh@cervais.com", role: "Member" as const, status: "online" as const, lastSeen: "Now", did: "did:cervais:0xc5e8d1a4f7b0c3e6d9a2f1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2f1c4b8e6" },
    ],
    calls: [
      { id: "call_001", type: "voice" as const, participant: "Sofia Chen", duration: "12m 34s", timestamp: "Yesterday 3:00 PM" },
      { id: "call_002", type: "video" as const, participant: "James Park", duration: "5m 10s", timestamp: "Yesterday 9:30 AM" },
      { id: "call_003", type: "voice" as const, participant: "All Members", duration: "28m 05s", timestamp: "Mon 11:00 AM" },
    ],
  },
  {
    id: "cir_002",
    name: "Incident Response Alpha",
    memberCount: 3,
    onlineCount: 2,
    description: "Rapid response team for critical infrastructure incidents.",
    inviteCode: "IRA-RESP-4Q8N-2F7T",
    inviteLink: "https://sgx.cervais.com/join/IRA-RESP-4Q8N-2F7T",
    messages: [],
    members: [
      { id: "mem_001", name: "Sofia Chen", email: "sofia.chen@cervais.com", role: "Owner" as const, status: "online" as const, lastSeen: "Now", did: "did:cervais:0x9b2c5e8d1a4f7b0c3e6d9a2f1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2f1c4" },
      { id: "mem_002", name: "Marcus Rivera", email: "marcus.rivera@cervais.com", role: "Member" as const, status: "online" as const, lastSeen: "Now", did: "did:cervais:0x7a3f9b2c8d1e4a6f5c0b3e7d2a9f1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2" },
      { id: "mem_003", name: "Aisha Okonkwo", email: "aisha.okonkwo@cervais.com", role: "Member" as const, status: "offline" as const, lastSeen: "3h ago", did: "did:cervais:0xf1c4b8e6d3a7f9b2c5e8d1a4f7b0c3e6d9a2f1c4b8e6d3a7f9b2c5e8d1a4f7b" },
    ],
    calls: [],
  },
];

export const mockDevices = [
  {
    id: "dev_001",
    name: "PLC-Controller-03",
    type: "IoT" as const,
    manufacturer: "Siemens",
    protocol: "Modbus TCP",
    mac: "C8:5B:76:2A:F3:91",
    ip: "10.0.2.47",
    firmware: "v2.1.4",
    os: "Linux Embedded 5.4",
    status: "online" as const,
    secured: true,
    encrypted: true,
    securityScore: 72,
    privacyScore: 84,
    vulnerabilities: 2,
    autoUpdate: false,
    guardianMonitoring: true,
    category: "regular" as const,
    lastSeen: "Now",
    vulnerabilityList: [
      { id: "v1", title: "Outdated Modbus Library", severity: "HIGH" as const, description: "libmodbus v3.0.1 has a known buffer overflow vulnerability. Upgrade to v3.1.7+" },
      { id: "v2", title: "Default SNMP Community String", severity: "MEDIUM" as const, description: "SNMP community string is set to 'public'. Change to a strong, unique string." },
    ],
  },
  {
    id: "dev_002",
    name: "SCADA-Server-01",
    type: "Computer" as const,
    manufacturer: "Dell",
    protocol: "OPC-UA",
    mac: "A4:C3:F0:85:7B:2E",
    ip: "10.0.1.12",
    firmware: "N/A",
    os: "Windows Server 2019",
    status: "online" as const,
    secured: true,
    encrypted: true,
    securityScore: 88,
    privacyScore: 91,
    vulnerabilities: 0,
    autoUpdate: true,
    guardianMonitoring: true,
    category: "regular" as const,
    lastSeen: "Now",
    vulnerabilityList: [],
  },
  {
    id: "dev_003",
    name: "SmartMeter-Bay-7",
    type: "IoT" as const,
    manufacturer: "Honeywell",
    protocol: "Zigbee",
    mac: "00:1A:22:F3:88:B1",
    ip: "10.0.3.91",
    firmware: "v1.2.0",
    os: "Embedded RTOS 2.1",
    status: "online" as const,
    secured: false,
    encrypted: false,
    securityScore: 41,
    privacyScore: 55,
    vulnerabilities: 4,
    autoUpdate: false,
    guardianMonitoring: true,
    category: "smart-home" as const,
    lastSeen: "4m ago",
    vulnerabilityList: [
      { id: "v1", title: "CVE-2023-4812 — RCE via Web Interface", severity: "HIGH" as const, description: "Unauthenticated remote code execution through the device web interface." },
      { id: "v2", title: "CVE-2023-5109 — Authentication Bypass", severity: "HIGH" as const, description: "Authentication can be bypassed using a crafted HTTP request." },
      { id: "v3", title: "Unencrypted Zigbee Traffic", severity: "MEDIUM" as const, description: "Zigbee network key is broadcast in plaintext during pairing." },
      { id: "v4", title: "Outdated Firmware v1.2.0", severity: "MEDIUM" as const, description: "Current version is v1.5.2. Multiple security patches in between." },
    ],
  },
  {
    id: "dev_004",
    name: "Security-Drone-Alpha",
    type: "Drone" as const,
    manufacturer: "DJI",
    protocol: "WiFi 6",
    mac: "78:D2:94:C1:5F:33",
    ip: "10.0.5.200",
    firmware: "v3.0.1",
    os: "DJI RTOS",
    status: "offline" as const,
    secured: true,
    encrypted: true,
    securityScore: 79,
    privacyScore: 68,
    vulnerabilities: 1,
    autoUpdate: true,
    guardianMonitoring: true,
    category: "drones" as const,
    lastSeen: "6h ago",
    vulnerabilityList: [
      { id: "v1", title: "Outdated DJI SDK", severity: "LOW" as const, description: "DJI SDK v4.14 has 1 known issue. Update to v4.16 when drone is next available." },
    ],
  },
  {
    id: "dev_005",
    name: "Unknown-B24FC9",
    type: "Unknown" as const,
    manufacturer: "Unknown",
    protocol: "WiFi",
    mac: "B2:4F:C9:12:8A:56",
    ip: "10.0.4.203",
    firmware: "Unknown",
    os: "Unknown",
    status: "online" as const,
    secured: false,
    encrypted: false,
    securityScore: 0,
    privacyScore: 0,
    vulnerabilities: 0,
    autoUpdate: false,
    guardianMonitoring: false,
    category: "pending" as const,
    lastSeen: "Now",
    vulnerabilityList: [],
  },
];

export const mockGeofenceZones = [
  { id: "zone_001", name: "Facility Perimeter", radius: 500, lat: 30.2672, lng: -97.7431, active: true },
  { id: "zone_002", name: "Control Room", radius: 50, lat: 30.2675, lng: -97.7428, active: true },
];

export const mockNotificationPrefs = {
  alertHigh: true,
  alertMedium: true,
  alertLow: false,
  deviceNewDiscovered: false,
  devicePendingApproval: true,
  deviceGuardianOffline: true,
  circleMessages: true,
  circleCalls: true,
  circleMemberJoined: false,
};

export const mockAlertRules = [
  { id: "rule_001", name: "Block on 5 Failed Logins", enabled: true, event: "Authentication Failure", condition: "count >= 5", action: "Block Device", notify: "Team Lead via Push" },
  { id: "rule_002", name: "Alert on USB Device Insert", enabled: true, event: "USB Device Connected", condition: "device not in whitelist", action: "Send Alert", notify: "All Members via Push" },
  { id: "rule_003", name: "Quarantine on Malware Detect", enabled: false, event: "Malware Detected", condition: "confidence >= 80%", action: "Quarantine Device", notify: "SOC Team via SMS" },
];

// ============================================================================
// DKP (Device Key Pair) Management Mock Data
// Maps to: sgx-pa-cli dkp-status, dkp-rotate, dkp-revoke, emergency-rotate
// ============================================================================

export type DKPKeyStatus = "active" | "deprecated" | "revoked";

export interface DKPKeyVersion {
  version: number;
  keyId: string;
  algorithm: string;
  status: DKPKeyStatus;
  created: string;
  rotatedFrom?: string;
  revokedAt?: string;
  revokeReason?: string;
}

export const mockDKPKeys: DKPKeyVersion[] = [
  {
    version: 3,
    keyId: "0x20000012",
    algorithm: "ECDSA-P256",
    status: "active",
    created: "2026-04-01T14:30:00Z",
    rotatedFrom: "0x20000011",
  },
  {
    version: 2,
    keyId: "0x20000011",
    algorithm: "ECDSA-P256",
    status: "deprecated",
    created: "2026-03-15T10:30:00Z",
    rotatedFrom: "0x20000010",
  },
  {
    version: 1,
    keyId: "0x20000010",
    algorithm: "ECDSA-P256",
    status: "revoked",
    created: "2026-02-01T08:00:00Z",
    revokedAt: "2026-03-20T09:15:00Z",
    revokeReason: "Scheduled rotation policy",
  },
];

export const mockDKPMetadata = {
  totalVersions: 3,
  activePublicKeyPath: "/var/lib/sgx-guardian/keys/dkp_pub.der",
  activePublicKeySize: 91,
  se050Available: true,
  hardwareMode: true,
};

// Emergency Rotation History
export interface EmergencyRotationLog {
  id: string;
  timestamp: string;
  mode: "hardware" | "software";
  keysRotated: number;
  keysFailed: number;
  details: {
    dkp: "success" | "failed";
    softwareKey: "success" | "failed";
    tlsCertificate: "success" | "failed";
  };
  triggeredBy: string;
  reason?: string;
}

export const mockEmergencyRotations: EmergencyRotationLog[] = [
  {
    id: "emr_001",
    timestamp: "2026-03-01T02:15:00Z",
    mode: "hardware",
    keysRotated: 3,
    keysFailed: 0,
    details: {
      dkp: "success",
      softwareKey: "success",
      tlsCertificate: "success",
    },
    triggeredBy: "Marcus Rivera",
    reason: "Suspected credential compromise during routine audit",
  },
];

// ============================================================================
// PCR (Platform Configuration Register) Mock Data
// Maps to: sgx-pa-cli pcr-status, pcr-baseline-create, pcr-baseline-verify
// ============================================================================

export type PCRStatus = "match" | "mismatch" | "no_baseline";

export interface PCRRegister {
  index: number;
  name: string;
  description: string;
  currentValue: string;
  baselineValue?: string;
  status: PCRStatus;
}

export const mockPCRRegisters: PCRRegister[] = [
  {
    index: 0,
    name: "PCR0",
    description: "BIOS/Bootloader",
    currentValue: "a3f4b2c81e9d7a02f5b6c8d9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
    baselineValue: "a3f4b2c81e9d7a02f5b6c8d9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
    status: "match",
  },
  {
    index: 1,
    name: "PCR1",
    description: "Firmware/DTB",
    currentValue: "b7c9d1e2f3a45678c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    baselineValue: "b7c9d1e2f3a45678c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    status: "match",
  },
  {
    index: 2,
    name: "PCR2",
    description: "Kernel",
    currentValue: "c8d2e3f4a5b67890d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
    baselineValue: "c8d2e3f4a5b67890d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
    status: "match",
  },
  {
    index: 3,
    name: "PCR3",
    description: "RootFS",
    currentValue: "d9e3f4a5b6c78901e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
    baselineValue: "d9e3f4a5b6c78901e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
    status: "match",
  },
  {
    index: 4,
    name: "PCR4",
    description: "Configuration",
    currentValue: "e0f4a5b6c7d89012f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
    baselineValue: "e0f4a5b6c7d89012f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
    status: "match",
  },
];

export interface PCRBaseline {
  id: string;
  nodeId: string;
  created: string;
  createdBy: string;
  compositeDigest: string;
  dkpVersion: number;
  signedBy: string;
  registers: {
    index: number;
    value: string;
  }[];
}

export const mockPCRBaseline: PCRBaseline = {
  id: "baseline_001",
  nodeId: "nodeA",
  created: "2026-04-01T10:00:00Z",
  createdBy: "Marcus Rivera",
  compositeDigest: "f1a5b6c7d8e90123a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
  dkpVersion: 3,
  signedBy: "DKP v3 (0x20000012)",
  registers: [
    { index: 0, value: "a3f4b2c81e9d7a02f5b6c8d9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9" },
    { index: 1, value: "b7c9d1e2f3a45678c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" },
    { index: 2, value: "c8d2e3f4a5b67890d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4" },
    { index: 3, value: "d9e3f4a5b6c78901e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5" },
    { index: 4, value: "e0f4a5b6c7d89012f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6" },
  ],
};

export interface PCRVerificationResult {
  id: string;
  timestamp: string;
  status: "pass" | "fail";
  matchCount: number;
  totalCount: number;
  mismatches: {
    index: number;
    name: string;
    expected: string;
    actual: string;
  }[];
}

export const mockPCRVerifications: PCRVerificationResult[] = [
  {
    id: "verify_001",
    timestamp: "2026-04-08T08:00:00Z",
    status: "pass",
    matchCount: 5,
    totalCount: 5,
    mismatches: [],
  },
  {
    id: "verify_002",
    timestamp: "2026-04-07T08:00:00Z",
    status: "pass",
    matchCount: 5,
    totalCount: 5,
    mismatches: [],
  },
  {
    id: "verify_003",
    timestamp: "2026-04-06T08:00:00Z",
    status: "pass",
    matchCount: 5,
    totalCount: 5,
    mismatches: [],
  },
];

export const mockPCRMetadata = {
  integrityStatus: "PASS" as const,
  compositeDigest: "f1a5b6c7d8e90123a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
  dkpVersion: 3,
  lastVerified: "2026-04-08T08:00:00Z",
  baselineExists: true,
  baselinePath: "/etc/sgx-guardian/pcr_nodeA_baseline.json",
};

// ============================================================================
// Boot Status Mock Data
// Maps to: sgx-pa-cli boot-status
// ============================================================================

export interface TrustChainStep {
  name: string;
  description: string;
  status: "verified" | "pending" | "failed";
}

export const mockBootStatus = {
  habEnabled: true,
  deviceClosed: true,
  habEvents: "None",
  deviceModel: "Variscite VAR-SOM-MX8M-PLUS",
  bootChain: "INTACT" as const,
  binaryHash: "a3f4b2c81e9d7a02f5b6c8d9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
  lastChecked: "2026-04-08T09:00:00Z",
  trustChain: [
    { name: "Boot ROM", description: "Hardware root of trust", status: "verified" as const },
    { name: "HAB verifies U-Boot", description: "High Assurance Boot validation", status: "verified" as const },
    { name: "U-Boot verifies Kernel", description: "Bootloader signature check", status: "verified" as const },
    { name: "Kernel loads verified RootFS", description: "dm-verity protected filesystem", status: "verified" as const },
    { name: "Guardian daemon", description: "SGX Guardian service started", status: "verified" as const },
    { name: "SE050 signs PCR", description: "Secure element attestation", status: "verified" as const },
  ] as TrustChainStep[],
};

// ============================================================================
// Attestation Mock Data
// Maps to: sgx-pa-cli attestation
// ============================================================================

export interface AttestationResult {
  id: string;
  peerId: string;
  peerIp: string;
  policyDigest: string;
  result: "success" | "failed";
  timestamp: string;
  details?: {
    pcrMatch: boolean;
    signatureValid: boolean;
    policyMatch: boolean;
    failureReason?: string;
  };
}

export const mockAttestationResults: AttestationResult[] = [
  {
    id: "att_001",
    peerId: "192.168.50.115:50052",
    peerIp: "192.168.50.115",
    policyDigest: "a7b9c3e4f5d6a8b2c1d9e7f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
    result: "success",
    timestamp: "2026-04-08T09:14:32.000Z",
    details: {
      pcrMatch: true,
      signatureValid: true,
      policyMatch: true,
    },
  },
  {
    id: "att_002",
    peerId: "192.168.50.248:50053",
    peerIp: "192.168.50.248",
    policyDigest: "a7b9c3e4f5d6a8b2c1d9e7f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
    result: "success",
    timestamp: "2026-04-08T09:14:35.000Z",
    details: {
      pcrMatch: true,
      signatureValid: true,
      policyMatch: true,
    },
  },
  {
    id: "att_003",
    peerId: "192.168.50.122:50054",
    peerIp: "192.168.50.122",
    policyDigest: "b8c2d4e5f6a7b9c3d1e0f2a4b6c8d0e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
    result: "failed",
    timestamp: "2026-04-07T14:22:10.000Z",
    details: {
      pcrMatch: false,
      signatureValid: true,
      policyMatch: true,
      failureReason: "PCR3 (RootFS) mismatch detected",
    },
  },
];

export const mockLastAttestation = mockAttestationResults[0];

// ============================================================================
// Policy Management Mock Data
// Maps to: sgx-pa-cli sign, verify, keygen
// ============================================================================

export type SignedPolicyStatus = "active" | "backup";

export interface SignedPolicy {
  id: string;
  name: string;
  path: string;
  digest: string;
  signature: string;
  signedAt: string;
  signedBy: string;
  verified: boolean;
  lastVerified?: string;
  envelopeVersion: string;
  status?: SignedPolicyStatus;
}

export const mockSignedPolicies: SignedPolicy[] = [
  {
    id: "pol_001",
    name: "production-uep-policy.yaml",
    path: "/etc/sgx-guardian/policies/production.yaml.sig",
    digest: "a7b9c3e4f5d6a8b2c1d9e7f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
    signature: "MEUCIQDKZokqnCjrRtE...",
    signedAt: "2026-04-05T11:30:00Z",
    signedBy: "guardian_primary",
    verified: true,
    lastVerified: "2026-04-08T08:00:00Z",
    envelopeVersion: "1.0",
    status: "active",
  },
  {
    id: "pol_002",
    name: "staging-uep-policy.yaml",
    path: "/etc/sgx-guardian/policies/staging.yaml.sig",
    digest: "b8c2d4e5f6a7b9c3d1e0f2a4b6c8d0e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
    signature: "MEQCIGKmVnRxU8Hj...",
    signedAt: "2026-04-03T09:15:00Z",
    signedBy: "guardian_primary",
    verified: true,
    lastVerified: "2026-04-07T14:30:00Z",
    envelopeVersion: "1.0",
    status: "backup",
  },
  {
    id: "pol_003",
    name: "dev-uep-policy.yaml",
    path: "/etc/sgx-guardian/policies/dev.yaml.sig",
    digest: "c9d3e5f6a7b8c0d2e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7",
    signature: "MEYCIQC7xWnPqM...",
    signedAt: "2026-04-01T16:45:00Z",
    signedBy: "guardian_primary",
    verified: false,
    lastVerified: "2026-04-02T10:00:00Z",
    envelopeVersion: "1.0",
    status: "backup",
  },
];

export interface PolicyAuthorityKey {
  id: string;
  name: string;
  algorithm: string;
  publicKeyPath: string;
  privateKeyExists: boolean;
  created: string;
  fingerprint: string;
}

export const mockPolicyAuthorityKey: PolicyAuthorityKey = {
  id: "pak_001",
  name: "guardian_primary",
  algorithm: "ECDSA-P256",
  publicKeyPath: "./guardian_public.key",
  privateKeyExists: true,
  created: "2026-01-15T10:00:00Z",
  fingerprint: "SHA256:xK3mBf2nP9qR7sT1vW5yZ8aD4gH6jL0",
};

// ============================================================================
// Logs Mock Data
// Maps to: sgx-pa-cli logs --node <node> --tail <n>
// ============================================================================

export type LogLevel = "info" | "warning" | "error" | "debug";
export type LogCategory = "attestation" | "peer" | "security" | "system" | "dkp" | "policy";

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  category: LogCategory;
  node: string;
  message: string;
  details?: string;
}

export const mockLogEntries: LogEntry[] = [
  {
    id: "log_001",
    timestamp: "2026-04-08T11:15:32.456Z",
    level: "info",
    category: "attestation",
    node: "nodeA",
    message: "Peer attestation completed successfully",
    details: "Peer 192.168.50.101:50052 verified with policy digest a7b9c3e4...",
  },
  {
    id: "log_002",
    timestamp: "2026-04-08T11:14:28.123Z",
    level: "info",
    category: "peer",
    node: "nodeA",
    message: "New peer discovered on network",
    details: "Peer ID: 192.168.50.105:50052, initiating attestation handshake",
  },
  {
    id: "log_003",
    timestamp: "2026-04-08T11:12:15.789Z",
    level: "warning",
    category: "security",
    node: "nodeA",
    message: "PCR measurement drift detected",
    details: "PCR4 (Configuration) value changed from baseline. Triggering re-verification.",
  },
  {
    id: "log_004",
    timestamp: "2026-04-08T11:10:45.234Z",
    level: "error",
    category: "attestation",
    node: "nodeB",
    message: "Peer attestation failed",
    details: "Peer 192.168.50.122:50054 failed PCR3 verification. Connection rejected.",
  },
  {
    id: "log_005",
    timestamp: "2026-04-08T11:08:12.567Z",
    level: "info",
    category: "system",
    node: "nodeA",
    message: "Guardian daemon started",
    details: "Version 4.2.1, PID 12847, listening on 0.0.0.0:50052",
  },
  {
    id: "log_006",
    timestamp: "2026-04-08T11:05:33.890Z",
    level: "info",
    category: "dkp",
    node: "nodeA",
    message: "DKP key rotation completed",
    details: "Rotated from version 2 to version 3. SE050 slot updated.",
  },
  {
    id: "log_007",
    timestamp: "2026-04-08T11:02:18.345Z",
    level: "debug",
    category: "peer",
    node: "nodeA",
    message: "Heartbeat received from peer",
    details: "Peer 192.168.50.101:50052, latency: 12ms",
  },
  {
    id: "log_008",
    timestamp: "2026-04-08T10:58:44.678Z",
    level: "info",
    category: "policy",
    node: "nodeA",
    message: "Policy file signed successfully",
    details: "production-uep-policy.yaml signed with guardian_primary key",
  },
  {
    id: "log_009",
    timestamp: "2026-04-08T10:55:22.901Z",
    level: "warning",
    category: "system",
    node: "nodeB",
    message: "High memory usage detected",
    details: "Memory usage at 87%. Consider increasing available memory.",
  },
  {
    id: "log_010",
    timestamp: "2026-04-08T10:52:11.234Z",
    level: "error",
    category: "security",
    node: "nodeA",
    message: "Unauthorized access attempt blocked",
    details: "IP 203.0.113.47 attempted connection without valid credentials",
  },
  {
    id: "log_011",
    timestamp: "2026-04-08T10:48:33.567Z",
    level: "info",
    category: "attestation",
    node: "nodeA",
    message: "Baseline verification passed",
    details: "All PCR registers match golden baseline",
  },
  {
    id: "log_012",
    timestamp: "2026-04-08T10:45:19.890Z",
    level: "debug",
    category: "system",
    node: "nodeA",
    message: "Configuration reload triggered",
    details: "Reloading /etc/sgx-guardian/config/nodeA.yaml",
  },
  {
    id: "log_013",
    timestamp: "2026-04-08T10:42:05.123Z",
    level: "info",
    category: "peer",
    node: "nodeA",
    message: "Peer connection established",
    details: "Connected to 192.168.50.103:50052 via secure channel",
  },
  {
    id: "log_014",
    timestamp: "2026-04-08T10:38:47.456Z",
    level: "warning",
    category: "dkp",
    node: "nodeA",
    message: "DKP key approaching rotation deadline",
    details: "Current key version 2 expires in 7 days. Schedule rotation.",
  },
  {
    id: "log_015",
    timestamp: "2026-04-08T10:35:28.789Z",
    level: "info",
    category: "security",
    node: "nodeA",
    message: "Secure boot chain verified",
    details: "HAB enabled, device closed, all boot stages verified",
  },
  {
    id: "log_016",
    timestamp: "2026-04-08T10:32:14.012Z",
    level: "error",
    category: "policy",
    node: "nodeB",
    message: "Policy verification failed",
    details: "dev-uep-policy.yaml signature invalid. Policy rejected.",
  },
  {
    id: "log_017",
    timestamp: "2026-04-08T10:28:55.345Z",
    level: "debug",
    category: "attestation",
    node: "nodeA",
    message: "Quote generation started",
    details: "Generating attestation quote for peer request",
  },
  {
    id: "log_018",
    timestamp: "2026-04-08T10:25:41.678Z",
    level: "info",
    category: "system",
    node: "nodeA",
    message: "Health check completed",
    details: "All subsystems operational. Uptime: 14d 6h 32m",
  },
  {
    id: "log_019",
    timestamp: "2026-04-08T10:22:27.901Z",
    level: "warning",
    category: "peer",
    node: "nodeA",
    message: "Peer connection timeout",
    details: "192.168.50.108:50052 did not respond within 30s. Retrying...",
  },
  {
    id: "log_020",
    timestamp: "2026-04-08T10:18:13.234Z",
    level: "info",
    category: "dkp",
    node: "nodeA",
    message: "Key backup created",
    details: "DKP version 3 backed up to secure storage",
  },
];

export const mockNodes = ["nodeA", "nodeB", "nodeC"];

// ============================================================================
// Cloud Storage / SGX Vault Mock Data
// Frontend-only — the Vault is the on-device, encrypted file store. Files
// shared in Circle chats are aggregated into it at runtime (see VaultContext).
// ============================================================================

export const mockVault = {
  deviceName: "Guardian-TX-042",
  capacityBytes: 8 * 1024 * 1024 * 1024, // 8 GB on-device encrypted store
  encryption: "AES-256-XTS",
};

/** Files uploaded straight to the Vault (not shared through a Circle chat). */
export const mockVaultFiles = [
  {
    id: "vf_seed_001",
    name: "guardian-tx-042-config-backup.json",
    sizeBytes: 2_201_472,
    mime: "application/json",
    sharedBy: "You",
    addedAt: "Today 7:02 AM",
  },
  {
    id: "vf_seed_002",
    name: "facility-network-map.png",
    sizeBytes: 3_563_110,
    mime: "image/png",
    sharedBy: "Marcus Rivera",
    addedAt: "Yesterday 5:40 PM",
    url: "data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20width='320'%20height='220'%3E%3Crect%20width='320'%20height='220'%20fill='%2316213a'/%3E%3Ccircle%20cx='160'%20cy='110'%20r='26'%20fill='none'%20stroke='%237042d2'%20stroke-width='3'/%3E%3Ccircle%20cx='70'%20cy='60'%20r='16'%20fill='%237042d2'%20opacity='0.7'/%3E%3Ccircle%20cx='255'%20cy='60'%20r='16'%20fill='%237042d2'%20opacity='0.7'/%3E%3Ccircle%20cx='70'%20cy='168'%20r='16'%20fill='%237042d2'%20opacity='0.7'/%3E%3Ccircle%20cx='255'%20cy='168'%20r='16'%20fill='%237042d2'%20opacity='0.7'/%3E%3Cg%20stroke='%234b5fae'%20stroke-width='2'%3E%3Cline%20x1='160'%20y1='110'%20x2='70'%20y2='60'/%3E%3Cline%20x1='160'%20y1='110'%20x2='255'%20y2='60'/%3E%3Cline%20x1='160'%20y1='110'%20x2='70'%20y2='168'/%3E%3Cline%20x1='160'%20y1='110'%20x2='255'%20y2='168'/%3E%3C/g%3E%3C/svg%3E",
  },
  {
    id: "vf_seed_003",
    name: "q1-2026-security-audit.pdf",
    sizeBytes: 6_082_560,
    mime: "application/pdf",
    sharedBy: "Sofia Chen",
    addedAt: "Mon 11:24 AM",
  },
  {
    id: "vf_seed_004",
    name: "firmware-v4.2.1-signed.bin",
    sizeBytes: 268_435_456,
    mime: "application/octet-stream",
    sharedBy: "You",
    addedAt: "Apr 28 · 9:15 AM",
  },
  {
    id: "vf_seed_005",
    name: "control-room-cctv-0418.mp4",
    sizeBytes: 2_576_980_378,
    mime: "video/mp4",
    sharedBy: "James Park",
    addedAt: "Apr 18 · 2:10 PM",
  },
  {
    id: "vf_seed_006",
    name: "perimeter-sensor-readings.csv",
    sizeBytes: 486_310,
    mime: "text/csv",
    sharedBy: "Dana Walsh",
    addedAt: "Apr 30 · 8:00 AM",
  },
];
