import { useState, useEffect } from "react";
import { PageHeader } from "../../components/PageHeader";
import { Wifi, Battery, Signal, Cpu, Clock, Radio, Server, Globe, Key, Copy, Check, Loader2, Shield } from "lucide-react";
import { toast } from "sonner";
import { guardianService } from "../../services/guardianService";
import { mockGuardian } from "../../data/mockData";

interface GuardianData {
  id: string;
  name: string;
  deviceId: string;
  firmware: string;
  uptime: string;
  connectionType: string;
  signal: number;
  battery: number;
  status: string;
  lastSeen: string;
  ip: string;
  mac: string;
  model: string;
  hostname: string;
  port: number;
  publicKey: string;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
      <div className="px-4 py-3 border-b border-border">
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
          {title}
        </span>
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, icon: Icon, accent }: { label: string; value: string; icon?: any; accent?: string }) {
  return (
    <div className="flex items-center justify-between px-4 py-3.5" style={{ borderBottom: "1px solid var(--border)" }}>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{label}</span>
      <div className="flex items-center gap-1.5">
        {Icon && <Icon size={13} style={{ color: accent || "var(--muted-foreground)" }} />}
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: accent || "var(--foreground)" }}>
          {value}
        </span>
      </div>
    </div>
  );
}

function LastRow({ label, value, icon: Icon }: { label: string; value: string; icon?: any }) {
  return (
    <div className="flex items-center justify-between px-4 py-3.5">
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{label}</span>
      <div className="flex items-center gap-1.5">
        {Icon && <Icon size={13} style={{ color: "var(--muted-foreground)" }} />}
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{value}</span>
      </div>
    </div>
  );
}

// Public Key Row with Copy
function PublicKeyRow({ publicKey }: { publicKey: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(publicKey);
    setCopied(true);
    toast.success("Public key copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  // Truncate for display
  const displayKey = publicKey.length > 40
    ? `${publicKey.slice(0, 20)}...${publicKey.slice(-16)}`
    : publicKey;

  return (
    <div className="px-4 py-3.5">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Key size={14} style={{ color: "var(--muted-foreground)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            Public Key
          </span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded transition-colors"
          style={{
            backgroundColor: copied ? "color-mix(in srgb, var(--chart-2) 15%, transparent)" : "var(--secondary)",
            border: "none",
            cursor: "pointer",
          }}
        >
          {copied ? (
            <Check size={12} style={{ color: "var(--chart-2)" }} />
          ) : (
            <Copy size={12} style={{ color: "var(--muted-foreground)" }} />
          )}
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: copied ? "var(--chart-2)" : "var(--muted-foreground)" }}>
            {copied ? "Copied" : "Copy"}
          </span>
        </button>
      </div>
      <code
        style={{
          display: "block",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "10px",
          color: "var(--foreground)",
          backgroundColor: "var(--muted)",
          padding: "10px 12px",
          borderRadius: "6px",
          wordBreak: "break-all",
          lineHeight: 1.5,
        }}
      >
        {displayKey}
      </code>
    </div>
  );
}

export function HM02GuardianDetail() {
  const [guardian, setGuardian] = useState<GuardianData | null>(null);
  const [loading, setLoading] = useState(true);
  const [dataSource, setDataSource] = useState<'api' | 'error'>('api');

  useEffect(() => {
    async function fetchData() {
      setLoading(true);
      try {
        const data = await guardianService.getInfo();
        setGuardian({
          id: (data as any).id || 'unknown',
          name: (data as any).name || 'SGX Guardian',
          deviceId: (data as any).deviceId || 'unknown',
          firmware: (data as any).firmware || 'v1.0.0',
          uptime: (data as any).uptime || 'Running',
          connectionType: (data as any).connectionType || 'Ethernet',
          signal: (data as any).signal ?? 100,
          battery: (data as any).battery ?? 100,
          status: (data as any).status || 'online',
          lastSeen: (data as any).lastSeen || 'Just now',
          ip: (data as any).ip || '—',
          mac: (data as any).mac || 'N/A',
          model: (data as any).model || 'SG-X Guardian',
          hostname: (data as any).hostname || '',
          port: (data as any).port || 0,
          publicKey: (data as any).publicKey || 'N/A',
        });
        setDataSource('api');
      } catch {
        setDataSource('error');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
    const id = setInterval(fetchData, 15000);
    return () => clearInterval(id);
  }, []);

  if (loading || !guardian) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
      </div>
    );
  }

  return (
    // h-full fills the <main> container; flex-col so the header is pinned
    // and the content area scrolls (desktop/tablet <main> is overflow:hidden)
    <div className="flex flex-col h-full">
      <PageHeader title={guardian.name} subtitle="Device Details" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto flex w-full max-w-2xl flex-col gap-4 p-4 md:p-6 pb-8">
        {/* Data source indicator */}
        {dataSource === 'error' && (
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>
            <span>API server unavailable</span>
          </div>
        )}

        {/* Status indicator */}
        <div
          className="flex items-center gap-3 px-4 py-3 rounded-lg border"
          style={{
            backgroundColor: "color-mix(in srgb, var(--chart-2) 8%, var(--card))",
            borderColor: "color-mix(in srgb, var(--chart-2) 30%, transparent)",
          }}
        >
          <div
            className="rounded-full"
            style={{ width: "10px", height: "10px", backgroundColor: "var(--chart-2)", boxShadow: "0 0 6px var(--chart-2)" }}
          />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--chart-2)" }}>
            Online · Monitoring Active
          </span>
        </div>

        {/* Device Info */}
        <Section title="Device Info">
          <div
            className="flex items-center justify-between px-4 py-3.5"
            style={{ borderBottom: "1px solid var(--border)" }}
          >
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Device ID</span>
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)", fontWeight: "var(--font-weight-medium)" }}>
              {guardian.deviceId}
            </span>
          </div>
          <Row label="Model" value={guardian.model} icon={Cpu} />
          <Row label="Firmware" value={guardian.firmware} />
          <LastRow label="Uptime" value={guardian.uptime} icon={Clock} />
        </Section>

        {/* Node Identity - maps to sgx-pa-cli status */}
        <Section title="Node Identity">
          <div className="flex items-center justify-between px-4 py-3.5" style={{ borderBottom: "1px solid var(--border)" }}>
            <div className="flex items-center gap-2">
              <Server size={14} style={{ color: "var(--muted-foreground)" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Hostname</span>
            </div>
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
              {guardian.hostname}
            </span>
          </div>
          <div className="flex items-center justify-between px-4 py-3.5" style={{ borderBottom: "1px solid var(--border)" }}>
            <div className="flex items-center gap-2">
              <Globe size={14} style={{ color: "var(--muted-foreground)" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Port</span>
            </div>
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--primary)" }}>
              {guardian.port}
            </span>
          </div>
          <PublicKeyRow publicKey={guardian.publicKey} />
        </Section>

        {/* Connection */}
        <Section title="Connection">
          <Row label="Type" value={guardian.connectionType} icon={Wifi} accent="var(--chart-2)" />
          <Row label="Signal Strength" value={`${guardian.signal}%`} icon={Signal} />
          <div className="flex items-center justify-between px-4 py-3.5" style={{ borderBottom: "1px solid var(--border)" }}>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>IP Address</span>
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{guardian.ip}</span>
          </div>
          <div className="flex items-center justify-between px-4 py-3.5" style={{ borderBottom: "1px solid var(--border)" }}>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>MAC Address</span>
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{guardian.mac}</span>
          </div>
          <LastRow label="Last Seen" value={guardian.lastSeen} />
        </Section>

        {/* Wi-Fi Mode */}
        <Section title="Wi-Fi Mode">
          <Row
            label="Operation Mode"
            value={mockGuardian.wifi_operation_mode === 'dual' ? 'Dual' : mockGuardian.wifi_operation_mode === 'hotspot_only' ? 'Hotspot Only' : 'Client Only'}
            icon={Wifi}
            accent="var(--primary)"
          />
          <Row
            label="Zero-Trust Active"
            value={mockGuardian.zero_trust_active ? 'Yes' : 'No'}
            icon={Shield}
            accent={mockGuardian.zero_trust_active ? "var(--chart-2)" : undefined}
          />
          <Row label="Hotspot SSID" value={mockGuardian.wifi_ssid} />
          <LastRow label="External Network" value={mockGuardian.wifi_client_ssid} />
        </Section>

        {/* Battery */}
        <Section title="Battery">
          <div className="px-4 pt-4 pb-3">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Battery size={18} style={{ color: guardian.battery > 20 ? "var(--chart-2)" : "var(--destructive)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                  {guardian.battery}%
                </span>
              </div>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                ~18h remaining
              </span>
            </div>
            <div className="rounded-full overflow-hidden" style={{ height: "8px", backgroundColor: "var(--muted)" }}>
              <div
                className="h-full rounded-full"
                style={{
                  width: `${guardian.battery}%`,
                  backgroundColor: guardian.battery > 20 ? "var(--chart-2)" : "var(--destructive)",
                }}
              />
            </div>
          </div>
          <LastRow label="Estimated Runtime" value="~18 hours" icon={Radio} />
        </Section>
        </div>
      </div>
    </div>
  );
}
