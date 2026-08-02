import { useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import {
  Play, Square, Search, Trash2, Cloud, Usb, Home, Shield, Clock, MapPin,
  Thermometer, Plus, Bell, Camera, Zap, Video, Check, Loader2, ExternalLink, ArrowLeft,
} from "lucide-react";
import { StatusBadge } from "../../components/SeverityBadge";

type Tab = "hubs" | "dongles" | "cloud" | "rules";
type CyleniumFlow = null | "what-syncs" | "connecting" | "done";

const cloudServices = [
  { name: "Ring Security", icon: Bell, description: "Smart doorbells and cameras", connected: true },
  { name: "Google Nest", icon: Home, description: "Thermostats and cameras", connected: false },
  { name: "Wyze", icon: Camera, description: "Affordable smart cameras", connected: false },
  { name: "Ecobee", icon: Thermometer, description: "Smart thermostats", connected: true },
  { name: "TP-Link Kasa", icon: Zap, description: "Smart plugs and switches", connected: false },
  { name: "Arlo", icon: Video, description: "Wireless security cameras", connected: false },
];

const ruleTypes = [
  { icon: Shield, label: "Security Triggers", desc: "Lock doors when threat detected" },
  { icon: Clock, label: "Schedules", desc: "Turn lights on/off at specific times" },
  { icon: MapPin, label: "Geofencing", desc: "Actions when leaving/arriving" },
  { icon: Thermometer, label: "Sensors", desc: "React to sensor readings" },
];

const syncFeatures = [
  { label: "Security Alerts", desc: "Real-time threat notifications sent to Cylenium dashboard" },
  { label: "Device Telemetry", desc: "Guardian health, battery, and connectivity data" },
  { label: "Audit Logs", desc: "All events and actions logged to Cylenium Cloud" },
];

export function DV11SmartHome() {
  const [activeTab, setActiveTab] = useState<Tab>("hubs");
  const [serviceRunning, setServiceRunning] = useState(false);
  const [connectedServices, setConnectedServices] = useState<Set<string>>(new Set(["Ring Security", "Ecobee"]));
  const [cyleniumFlow, setCyleniumFlow] = useState<CyleniumFlow>(null);
  const [connectProgress, setConnectProgress] = useState(0);

  // Cylenium is "connected" if it was connected during onboarding OR this session
  const cyleniumConnected =
    localStorage.getItem("sgx_cylenium_connected") === "1" || cyleniumFlow === "done";

  const tabs: { id: Tab; label: string; icon: any }[] = [
    { id: "hubs", label: "Hubs", icon: Home },
    { id: "dongles", label: "Dongles", icon: Usb },
    { id: "cloud", label: "Cloud", icon: Cloud },
    { id: "rules", label: "Rules", icon: Shield },
  ];

  const toggleService = (name: string) => {
    setConnectedServices((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  };

  const startCyleniumConnect = () => {
    setCyleniumFlow("connecting");
    setConnectProgress(0);
    // Animate progress
    const steps = [15, 35, 55, 72, 88, 100];
    steps.forEach((val, i) => {
      setTimeout(() => {
        setConnectProgress(val);
        if (val === 100) {
          setTimeout(() => {
            localStorage.setItem("sgx_cylenium_connected", "1");
            setCyleniumFlow("done");
          }, 400);
        }
      }, i * 600 + 300);
    });
  };

  // ── Cylenium flow screens ─────────────────────────────────────────────────
  if (cyleniumFlow === "what-syncs") {
    return (
      <div className="flex flex-col h-full" style={{ backgroundColor: "var(--background)" }}>
        <PageHeader
          title="Connect Cylenium"
          showBack
          onBack={() => setCyleniumFlow(null)}
        />
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5">
          {/* Header */}
          <div className="flex flex-col items-center py-4 text-center gap-3">
            <div
              className="rounded-full flex items-center justify-center"
              style={{ width: "72px", height: "72px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "2px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}
            >
              <Cloud size={32} style={{ color: "var(--primary)" }} />
            </div>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--foreground)", marginBottom: "6px" }}>
                Cylenium Cloud Sync
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6, maxWidth: "260px" }}>
                Connect your Guardian to Cervais's enterprise monitoring platform.
              </p>
            </div>
          </div>

          {/* What syncs */}
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
              What will sync
            </p>
            <div className="flex flex-col gap-3">
              {syncFeatures.map(({ label, desc }) => (
                <div
                  key={label}
                  className="rounded-lg border border-border p-4 flex items-start gap-3"
                  style={{ backgroundColor: "var(--card)" }}
                >
                  <div
                    className="rounded-full flex items-center justify-center flex-shrink-0 mt-0.5"
                    style={{ width: "28px", height: "28px", backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)", border: "1px solid color-mix(in srgb, var(--chart-2) 30%, transparent)" }}
                  >
                    <Check size={13} style={{ color: "var(--chart-2)" }} />
                  </div>
                  <div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "2px" }}>{label}</p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
          </div>
        </div>

        <div className="mx-auto w-full max-w-2xl px-4 md:px-6 pb-10 pt-4">
          <button
            onClick={startCyleniumConnect}
            className="w-full flex items-center justify-center gap-2 transition-opacity active:opacity-80"
            style={{
              height: "52px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)",
              borderRadius: "var(--radius)", border: "none", cursor: "pointer",
              boxShadow: "0 0 24px color-mix(in srgb, var(--primary) 22%, transparent)",
            }}
          >
            Connect Now
          </button>
        </div>
      </div>
    );
  }

  if (cyleniumFlow === "connecting") {
    return (
      <div
        className="flex flex-col items-center justify-center px-6 gap-6 h-full"
        style={{ backgroundColor: "var(--background)" }}
      >
        <div
          className="rounded-full flex items-center justify-center"
          style={{ width: "80px", height: "80px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1.5px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}
        >
          <Loader2 size={36} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
        </div>
        <div className="text-center">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "4px" }}>
            Connecting to Cylenium…
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            Establishing secure tunnel
          </p>
        </div>
        <div className="w-full" style={{ maxWidth: "260px" }}>
          <div className="rounded-full overflow-hidden" style={{ height: "6px", backgroundColor: "var(--muted)" }}>
            <div
              className="h-full rounded-full"
              style={{ width: `${connectProgress}%`, backgroundColor: "var(--primary)", transition: "width 0.5s ease" }}
            />
          </div>
          <div className="flex items-center justify-between mt-2">
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              {connectProgress < 100 ? "Syncing…" : "Complete"}
            </span>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              {connectProgress}%
            </span>
          </div>
        </div>
        <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  if (cyleniumFlow === "done") {
    return (
      <div
        className="flex flex-col items-center justify-center px-6 gap-5 h-full"
        style={{ backgroundColor: "var(--background)" }}
      >
        <div
          className="rounded-full flex items-center justify-center"
          style={{
            width: "88px", height: "88px",
            backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
            border: "2px solid color-mix(in srgb, var(--chart-2) 35%, transparent)",
            animation: "popIn 0.35s ease-out forwards",
          }}
        >
          <Check size={44} strokeWidth={2.5} style={{ color: "var(--chart-2)" }} />
        </div>
        <div className="text-center">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--foreground)", marginBottom: "6px" }}>
            Cylenium Connected!
          </p>
          <div className="flex flex-col gap-1 mt-3">
            {syncFeatures.map(({ label }) => (
              <div key={label} className="flex items-center gap-2 justify-center">
                <Check size={13} style={{ color: "var(--chart-2)", flexShrink: 0 }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label} active</span>
              </div>
            ))}
          </div>
        </div>
        <button
          onClick={() => { setCyleniumFlow(null); setActiveTab("cloud"); }}
          className="flex items-center gap-2 transition-opacity active:opacity-80"
          style={{
            height: "48px", paddingLeft: "24px", paddingRight: "24px",
            backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
            fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)", border: "none", cursor: "pointer",
          }}
        >
          Back to Cloud
        </button>
        <style>{`@keyframes popIn{0%{transform:scale(0.85)}60%{transform:scale(1.08)}100%{transform:scale(1)}}`}</style>
      </div>
    );
  }

  // ── Main screen ───────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Smart Home Integration" />

      {/* Tabs */}
      <div className="flex border-b border-border" style={{ backgroundColor: "var(--card)" }}>
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className="flex-1 flex flex-col items-center gap-0.5 py-3 transition-opacity active:opacity-70"
            style={{
              backgroundColor: "transparent", border: "none", cursor: "pointer",
              borderBottom: activeTab === id ? "2px solid var(--primary)" : "2px solid transparent",
            }}
          >
            <Icon size={16} style={{ color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: activeTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)", color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }}>
              {label}
            </span>
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6">

        {/* HUBS TAB */}
        {activeTab === "hubs" && (
          <div className="flex flex-col gap-4">
            <div className="flex gap-2">
              <button
                onClick={() => setServiceRunning(!serviceRunning)}
                className="flex-1 flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
                style={{
                  height: "48px",
                  backgroundColor: serviceRunning ? "color-mix(in srgb, var(--destructive) 12%, transparent)" : "color-mix(in srgb, var(--chart-2) 12%, transparent)",
                  color: serviceRunning ? "var(--destructive)" : "var(--chart-2)",
                  border: `1px solid ${serviceRunning ? "color-mix(in srgb, var(--destructive) 30%, transparent)" : "color-mix(in srgb, var(--chart-2) 30%, transparent)"}`,
                  cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)",
                }}
              >
                {serviceRunning ? <><Square size={15} /> Stop Service</> : <><Play size={15} /> Start Service</>}
              </button>
              <button
                className="flex-1 flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
                style={{ height: "48px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
              >
                <Search size={15} /> Discover Hubs
              </button>
            </div>

            {serviceRunning && (
              <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                <div className="px-4 py-3 border-b border-border">
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>Discovered Hubs</span>
                </div>
                {[
                  { name: "Zigbee Hub v2", ip: "192.168.1.45", type: "Zigbee" },
                  { name: "Z-Wave Controller", ip: "192.168.1.72", type: "Z-Wave" },
                ].map((hub, i, arr) => (
                  <div key={hub.name} className="flex items-center gap-3 px-4 py-3.5" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                    <div>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{hub.name}</p>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{hub.ip} · {hub.type}</p>
                    </div>
                    <button className="ml-auto px-3 rounded-md transition-opacity active:opacity-80" style={{ height: "32px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius-sm)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}>Add</button>
                  </div>
                ))}
              </div>
            )}

            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>Recent Activity</p>
              <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                {[
                  { event: "Hub service started", time: "9:15 AM" },
                  { event: "Zigbee device joined network", time: "9:02 AM" },
                  { event: "Hub offline — reconnecting", time: "8:45 AM" },
                  { event: "2 Z-Wave devices discovered", time: "8:30 AM" },
                ].map((item, i, arr) => (
                  <div key={i} className="flex items-center justify-between px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{item.event}</span>
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>{item.time}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* DONGLES TAB */}
        {activeTab === "dongles" && (
          <div className="flex flex-col gap-4">
            <div className="flex flex-col items-center py-12 gap-3 text-center">
              <Usb size={40} style={{ color: "var(--muted-foreground)" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>No USB dongles detected</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", maxWidth: "220px", lineHeight: 1.5 }}>Connect a dongle to your Guardian's USB port to get started.</p>
            </div>
          </div>
        )}

        {/* CLOUD TAB */}
        {activeTab === "cloud" && (
          <div className="flex flex-col gap-4">

            {/* ── Cylenium Cloud featured card ── */}
            <div
              className="rounded-lg p-4 flex flex-col gap-3"
              style={{
                backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))",
                border: "1.5px solid var(--primary)",
              }}
            >
              {/* CERVAIS label */}
              <div className="flex items-center justify-between">
                <span
                  style={{
                    fontFamily: "Inter, sans-serif", fontSize: "9px", fontWeight: "var(--font-weight-semibold)",
                    color: "var(--primary)", letterSpacing: "0.14em",
                  }}
                >
                  CERVAIS
                </span>
                {cyleniumConnected && (
                  <StatusBadge status="Connected" variant="success" />
                )}
              </div>

              <div className="flex items-center gap-3">
                <div
                  className="rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{ width: "44px", height: "44px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}
                >
                  <Cloud size={22} style={{ color: "var(--primary)" }} />
                </div>
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "2px" }}>
                    Cylenium Cloud
                  </p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                    Unified security visibility for your Guardian network
                  </p>
                </div>
              </div>

              {cyleniumConnected ? (
                <>
                  {/* Connected state */}
                  <div className="rounded-md p-3 flex flex-col gap-2" style={{ backgroundColor: "color-mix(in srgb, var(--chart-2) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--chart-2) 20%, transparent)" }}>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "4px" }}>
                      Last sync: Just now
                    </p>
                    {syncFeatures.map(({ label }) => (
                      <div key={label} className="flex items-center gap-2">
                        <Check size={12} style={{ color: "var(--chart-2)", flexShrink: 0 }} />
                        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{label}</span>
                      </div>
                    ))}
                  </div>
                  <a
                    href="#"
                    className="flex items-center gap-1.5 transition-opacity active:opacity-70"
                    style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--primary)", textDecoration: "none" }}
                  >
                    <ExternalLink size={12} />
                    View in Cylenium Dashboard
                  </a>
                </>
              ) : (
                <button
                  onClick={() => setCyleniumFlow("what-syncs")}
                  className="w-full flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
                  style={{
                    height: "44px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
                    border: "none", cursor: "pointer", borderRadius: "var(--radius)",
                    fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)",
                    boxShadow: "0 0 20px color-mix(in srgb, var(--primary) 20%, transparent)",
                  }}
                >
                  <Cloud size={15} />
                  Connect Cylenium
                </button>
              )}
            </div>

            {/* Third-party separator */}
            <div className="flex items-center gap-3">
              <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", flexShrink: 0 }}>
                Third-party services
              </span>
              <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
            </div>

            {/* 3rd party grid */}
            <div className="grid grid-cols-2 gap-3">
              {cloudServices.map((service) => {
                const isConnected = connectedServices.has(service.name);
                const ServiceIcon = service.icon;
                return (
                  <div key={service.name} className="rounded-lg border border-border p-4 flex flex-col gap-2" style={{ backgroundColor: "var(--card)" }}>
                    <div className="rounded-lg flex items-center justify-center" style={{ width: "36px", height: "36px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
                      <ServiceIcon size={18} style={{ color: "var(--primary)" }} />
                    </div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{service.name}</p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", lineHeight: 1.4 }}>{service.description}</p>
                    {isConnected ? (
                      <div className="flex items-center justify-between mt-1">
                        <StatusBadge status="Connected" variant="success" />
                        <button onClick={() => toggleService(service.name)} style={{ background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textDecoration: "underline" }}>Disconnect</button>
                      </div>
                    ) : (
                      <button onClick={() => toggleService(service.name)} className="w-full flex items-center justify-center rounded-md transition-opacity active:opacity-80 mt-1" style={{ height: "32px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius-sm)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}>Connect</button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* RULES TAB */}
        {activeTab === "rules" && (
          <div className="flex flex-col gap-4">
            <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", marginBottom: "4px" }}>Device Automation</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>Create rules to automatically control your smart home devices based on security events, time schedules, location, or sensor readings.</p>
            </div>
            <button className="w-full flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80" style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}>
              <Plus size={16} /> Manage Automation Rules
            </button>
            <div className="grid grid-cols-2 gap-3">
              {ruleTypes.map(({ icon: Icon, label, desc }) => (
                <div key={label} className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
                  <Icon size={20} style={{ color: "var(--primary)", marginBottom: "8px" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "4px" }}>{label}</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", lineHeight: 1.4 }}>{desc}</p>
                </div>
              ))}
            </div>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>Recent Activity</p>
              <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                {[
                  { event: "Rule triggered: Lock on Threat", time: "9:14 AM" },
                  { event: "Lights off scheduled task ran", time: "12:00 AM" },
                ].map((item, i, arr) => (
                  <div key={i} className="flex items-center justify-between px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{item.event}</span>
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>{item.time}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
        </div>
      </div>
    </div>
  );
}