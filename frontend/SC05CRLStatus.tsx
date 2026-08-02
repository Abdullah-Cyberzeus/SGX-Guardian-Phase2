import { useState, useMemo } from "react";
import { useParams, useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { mockDevices } from "../../data/mockData";
import { Lock, Unlock, RefreshCw, Wifi, Ban, Trash2, Scan, AlertTriangle, Shield, Eye, Loader2 } from "lucide-react";
import { useDevices } from "../../hooks/useApiData";
import { SeverityBadge, StatusBadge } from "../../components/SeverityBadge";
import * as Dialog from "@radix-ui/react-dialog";
import * as Switch from "@radix-ui/react-switch";

type Tab = "info" | "security" | "actions";

function ScoreRing({ value, label }: { value: number; label: string }) {
  const color = value >= 80 ? "var(--chart-2)" : value >= 50 ? "var(--chart-5)" : "var(--destructive)";
  const r = 28;
  const circ = 2 * Math.PI * r;
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative" style={{ width: "72px", height: "72px" }}>
        <svg width="72" height="72" viewBox="0 0 72 72" style={{ transform: "rotate(-90deg)" }}>
          <circle cx="36" cy="36" r={r} fill="none" stroke="var(--muted)" strokeWidth="6" />
          <circle cx="36" cy="36" r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round" strokeDasharray={`${(value / 100) * circ} ${circ}`} />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "16px", fontWeight: 700, color, lineHeight: 1 }}>{value}</span>
        </div>
      </div>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
    </div>
  );
}

export function DV03DeviceDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<Tab>("info");
  const [monitoring, setMonitoring] = useState(true);
  const [blockDialogOpen, setBlockDialogOpen] = useState(false);
  const [removeDialogOpen, setRemoveDialogOpen] = useState(false);

  // Fetch devices from API with fallback to mock data
  const { data: devicesData, loading } = useDevices();

  const devices = useMemo(() => {
    if (!devicesData) return mockDevices;
    return devicesData.devices || mockDevices;
  }, [devicesData]);

  const device = useMemo(() => {
    return devices.find((d: any) => d.id === id);
  }, [devices, id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 className="w-8 h-8 animate-spin" style={{ color: "var(--primary)" }} />
      </div>
    );
  }

  if (!device) {
    return (
      <div className="flex flex-col h-full">
        <PageHeader title="Device" />
        <p style={{ padding: "16px", fontFamily: "Inter, sans-serif", color: "var(--muted-foreground)" }}>Device not found</p>
      </div>
    );
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "info", label: "Info" },
    { id: "security", label: "Security" },
    { id: "actions", label: "Actions" },
  ];

  return (
    <>
      <div className="flex flex-col h-full">
        <PageHeader title={device.name} subtitle={`${device.manufacturer} · ${device.protocol}`} />

        {/* Score cards */}
        <div className="flex items-center justify-around px-4 md:px-6 py-4 border-b border-border" style={{ backgroundColor: "var(--card)" }}>
          <ScoreRing value={device.securityScore} label="Security" />
          <div className="w-px h-12" style={{ backgroundColor: "var(--border)" }} />
          <ScoreRing value={device.privacyScore} label="Privacy" />
          <div className="w-px h-12" style={{ backgroundColor: "var(--border)" }} />
          <div className="flex flex-col items-center gap-1">
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: 700, color: device.vulnerabilities > 0 ? "var(--destructive)" : "var(--chart-2)", lineHeight: 1 }}>{device.vulnerabilities}</span>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Vulns</span>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-border" style={{ backgroundColor: "var(--card)" }}>
          {tabs.map(({ id, label }) => (
            <button key={id} onClick={() => setActiveTab(id)}
              className="flex-1 py-3 transition-opacity active:opacity-70"
              style={{ backgroundColor: "transparent", border: "none", cursor: "pointer", borderBottom: activeTab === id ? "2px solid var(--primary)" : "2px solid transparent", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: activeTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)", color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-2xl p-4 md:p-6">
          {/* INFO TAB (DV-03) */}
          {activeTab === "info" && (
            <div className="flex flex-col gap-4">
              <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                <div className="px-4 py-3 border-b border-border">
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>Device Information</span>
                </div>
                {[
                  { label: "Manufacturer", value: device.manufacturer },
                  { label: "Model", value: device.type },
                  { label: "Protocol", value: device.protocol },
                  { label: "MAC Address", value: device.mac },
                  { label: "IP Address", value: device.ip },
                  { label: "Firmware", value: device.firmware },
                  { label: "OS", value: device.os },
                  { label: "Last Seen", value: device.lastSeen },
                ].map(({ label, value }, i, arr) => (
                  <div key={label} className="flex items-center justify-between px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{label}</span>
                    <span style={{ fontFamily: label === "MAC Address" || label === "IP Address" ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: label === "MAC Address" ? "11px" : "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)", maxWidth: "55%", textAlign: "right" }}>
                      {value}
                    </span>
                  </div>
                ))}
              </div>

              {/* Guardian Monitoring toggle */}
              <div className="rounded-lg border border-border p-4 flex items-center justify-between" style={{ backgroundColor: "var(--card)" }}>
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)", marginBottom: "2px" }}>Guardian Monitoring</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Active threat detection for this device</p>
                </div>
                <Switch.Root
                  checked={monitoring}
                  onCheckedChange={setMonitoring}
                  style={{ width: "44px", height: "24px", borderRadius: "12px", backgroundColor: monitoring ? "var(--primary)" : "var(--muted)", border: "none", cursor: "pointer", position: "relative", transition: "background-color 0.2s" }}
                >
                  <Switch.Thumb style={{ display: "block", width: "18px", height: "18px", borderRadius: "50%", backgroundColor: "white", transform: monitoring ? "translateX(22px)" : "translateX(3px)", transition: "transform 0.2s" }} />
                </Switch.Root>
              </div>
            </div>
          )}

          {/* SECURITY TAB (DV-04) */}
          {activeTab === "security" && (
            <div className="flex flex-col gap-4">
              <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                <div className="px-4 py-3 border-b border-border">
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>Security Features</span>
                </div>
                {[
                  { label: "Encryption", value: device.encrypted ? "Enabled" : "Disabled", ok: device.encrypted, icon: device.encrypted ? Lock : Unlock },
                  { label: "Auto-Update", value: device.autoUpdate ? "Enabled" : "Disabled", ok: device.autoUpdate, icon: RefreshCw },
                  { label: "Connectivity", value: device.protocol, ok: true, icon: Wifi },
                ].map(({ label, value, ok, icon: Icon }, i, arr) => (
                  <div key={label} className="flex items-center justify-between px-4 py-3.5" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                    <div className="flex items-center gap-2">
                      <Icon size={15} style={{ color: ok ? "var(--chart-2)" : "var(--destructive)" }} />
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>{label}</span>
                    </div>
                    <StatusBadge status={value} variant={ok ? "success" : "danger"} />
                  </div>
                ))}
              </div>

              {/* Vulnerabilities */}
              {device.vulnerabilityList.length > 0 && (
                <div>
                  <div className="rounded-lg border p-4 mb-3" style={{ borderColor: "color-mix(in srgb, var(--destructive) 30%, transparent)", backgroundColor: "color-mix(in srgb, var(--destructive) 6%, var(--card))" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <AlertTriangle size={16} style={{ color: "var(--destructive)" }} />
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--destructive)" }}>
                        {device.vulnerabilities} Vulnerabilities Detected
                      </p>
                    </div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      Address these issues to improve your security score.
                    </p>
                  </div>
                  <div className="flex flex-col gap-3">
                    {device.vulnerabilityList.map((v) => (
                      <div key={v.id} className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", flex: 1 }}>{v.title}</p>
                          <SeverityBadge severity={v.severity} />
                        </div>
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>{v.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {device.vulnerabilityList.length === 0 && (
                <div className="flex flex-col items-center gap-3 py-8 text-center">
                  <Shield size={36} style={{ color: "var(--chart-2)" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--chart-2)" }}>No vulnerabilities detected</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>This device passed all security checks.</p>
                </div>
              )}
            </div>
          )}

          {/* ACTIONS TAB (DV-05) */}
          {activeTab === "actions" && (
            <div className="flex flex-col gap-3">
              <button
                onClick={() => navigate(`/devices/${id}/scan`)}
                className="w-full flex items-center gap-3 p-4 rounded-lg border border-border transition-opacity active:opacity-80 text-left"
                style={{ backgroundColor: "var(--primary)", cursor: "pointer", borderRadius: "var(--radius-card)", border: "none" }}
              >
                <Scan size={22} style={{ color: "var(--primary-foreground)" }} />
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary-foreground)" }}>Run Security Scan</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "color-mix(in srgb, var(--primary-foreground) 70%, transparent)" }}>Full vulnerability and configuration scan</p>
                </div>
              </button>
              <button
                onClick={() => setBlockDialogOpen(true)}
                className="w-full flex items-center gap-3 p-4 rounded-lg border transition-opacity active:opacity-80 text-left"
                style={{ backgroundColor: "color-mix(in srgb, var(--chart-5) 10%, var(--card))", borderColor: "color-mix(in srgb, var(--chart-5) 30%, transparent)", cursor: "pointer", borderRadius: "var(--radius-card)" }}
              >
                <Ban size={22} style={{ color: "var(--chart-5)" }} />
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--chart-5)" }}>Block from Network</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Immediately revoke this device's network access</p>
                </div>
              </button>
              <button
                onClick={() => setRemoveDialogOpen(true)}
                className="w-full flex items-center gap-3 p-4 rounded-lg border transition-opacity active:opacity-80 text-left"
                style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, var(--card))", borderColor: "color-mix(in srgb, var(--destructive) 25%, transparent)", cursor: "pointer", borderRadius: "var(--radius-card)" }}
              >
                <Trash2 size={22} style={{ color: "var(--destructive)" }} />
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--destructive)" }}>Remove Device</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Remove from Guardian monitoring permanently</p>
                </div>
              </button>
            </div>
          )}
          </div>
        </div>
      </div>

      {/* Block Dialog (DV-08) */}
      <Dialog.Root open={blockDialogOpen} onOpenChange={setBlockDialogOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
          <Dialog.Content className="fixed z-[70] rounded-xl border border-border p-6" style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "380px" }}>
            <div className="flex items-center gap-3 mb-3">
              <Ban size={20} style={{ color: "var(--chart-5)" }} />
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Block {device.name}?</Dialog.Title>
            </div>
            <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6, marginBottom: "20px" }}>
              This device will lose network access immediately. All active connections will be terminated. You can unblock it later from device settings.
            </Dialog.Description>
            <div className="flex gap-3">
              <Dialog.Close asChild>
                <button className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "44px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}>Cancel</button>
              </Dialog.Close>
              <button onClick={() => setBlockDialogOpen(false)} className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "44px", backgroundColor: "var(--destructive)", color: "var(--destructive-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}>Block Device</button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Remove Dialog (DV-09) */}
      <Dialog.Root open={removeDialogOpen} onOpenChange={setRemoveDialogOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
          <Dialog.Content className="fixed z-[70] rounded-xl border border-border p-6" style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "380px" }}>
            <div className="flex items-center gap-3 mb-3">
              <AlertTriangle size={20} style={{ color: "var(--destructive)" }} />
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Remove {device.name}?</Dialog.Title>
            </div>
            <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6, marginBottom: "20px" }}>
              This device will be removed from Guardian monitoring. All associated alerts and data will be cleared. This cannot be undone.
            </Dialog.Description>
            <div className="flex gap-3">
              <Dialog.Close asChild>
                <button className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "44px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}>Cancel</button>
              </Dialog.Close>
              <button onClick={() => { setRemoveDialogOpen(false); navigate("/devices"); }} className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "44px", backgroundColor: "var(--destructive)", color: "var(--destructive-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}>Remove</button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  );
}