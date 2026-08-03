import { useState, useEffect } from "react";
import { PageHeader } from "../../components/PageHeader";
import {
  Wifi,
  WifiOff,
  Shield,
  Eye,
  EyeOff,
  Loader2,
  ChevronRight,
  Lock,
  Radio,
} from "lucide-react";
import { toast } from "sonner";
import wifiService, {
  WifiModeResponse,
  ScannedNetwork,
  WifiClient,
} from "../../services/wifiService";

type OperationMode = "hotspot_only" | "client_only" | "dual";

type WifiState =
  | "DUAL_ACTIVE"
  | "DUAL_STARTING"
  | "HOTSPOT_ACTIVE"
  | "CLIENT_ACTIVE"
  | "ERROR"
  | "IDLE";

function stateFromMode(mode: OperationMode): WifiState {
  if (mode === "dual") return "DUAL_ACTIVE";
  if (mode === "hotspot_only") return "HOTSPOT_ACTIVE";
  if (mode === "client_only") return "CLIENT_ACTIVE";
  return "IDLE";
}

function SignalBars({ dbm }: { dbm: number }) {
  const strength = dbm > -55 ? 100 : dbm > -65 ? 75 : dbm > -75 ? 50 : 25;
  const bars = [25, 50, 75, 100];
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: "2px", height: "14px" }}>
      {bars.map((threshold) => (
        <div
          key={threshold}
          style={{
            width: "3px",
            height: `${(threshold / 100) * 14}px`,
            borderRadius: "1px",
            backgroundColor:
              strength >= threshold ? "var(--chart-2)" : "var(--muted-foreground)",
            opacity: strength >= threshold ? 1 : 0.3,
          }}
        />
      ))}
    </div>
  );
}

function StateBadge({ state }: { state: WifiState }) {
  const map: Record<WifiState, { label: string; color: string; bg: string }> = {
    DUAL_ACTIVE: { label: "DUAL ACTIVE", color: "var(--chart-2)", bg: "color-mix(in srgb, var(--chart-2) 12%, transparent)" },
    DUAL_STARTING: { label: "STARTING", color: "var(--chart-4)", bg: "color-mix(in srgb, var(--chart-4) 12%, transparent)" },
    HOTSPOT_ACTIVE: { label: "HOTSPOT", color: "var(--primary)", bg: "color-mix(in srgb, var(--primary) 12%, transparent)" },
    CLIENT_ACTIVE: { label: "CLIENT", color: "var(--primary)", bg: "color-mix(in srgb, var(--primary) 12%, transparent)" },
    ERROR: { label: "ERROR", color: "var(--destructive)", bg: "color-mix(in srgb, var(--destructive) 12%, transparent)" },
    IDLE: { label: "IDLE", color: "var(--muted-foreground)", bg: "var(--muted)" },
  };
  const s = map[state];
  return (
    <span
      style={{
        fontFamily: "Inter, sans-serif",
        fontSize: "10px",
        fontWeight: "var(--font-weight-semibold)",
        letterSpacing: "0.07em",
        color: s.color,
        backgroundColor: s.bg,
        borderRadius: "4px",
        padding: "2px 7px",
      }}
    >
      {s.label}
    </span>
  );
}

const MODE_OPTIONS: {
  key: OperationMode;
  label: string;
  description: string;
  Icon: React.ElementType;
}[] = [
  { key: "hotspot_only", label: "Hotspot Only", description: "Guardian acts as an AP for your devices", Icon: Radio },
  { key: "client_only", label: "Client Only", description: "Guardian connects to an external network", Icon: WifiOff },
  { key: "dual", label: "Dual Mode", description: "Hotspot + upstream client with Zero-Trust inspection", Icon: Shield },
];

export function ST13DualWifi() {
  const [currentMode, setCurrentMode] = useState<OperationMode>("dual");
  const [selectedMode, setSelectedMode] = useState<OperationMode>("dual");
  const [wifiState, setWifiState] = useState<WifiState>("DUAL_ACTIVE");
  const [suricataRunning, setSuricataRunning] = useState(false);
  const [zeroTrustActive, setZeroTrustActive] = useState(false);

  const [hotspotSsid, setHotspotSsid] = useState("ARMIA");
  const [hotspotPassword, setHotspotPassword] = useState("");
  const [hotspotBand, setHotspotBand] = useState<"2.4GHz" | "5GHz">("2.4GHz");
  const [showHotspotPw, setShowHotspotPw] = useState(false);

  const [scannedNetworks, setScannedNetworks] = useState<ScannedNetwork[]>([]);
  const [scanning, setScanning] = useState(false);
  const [selectedNetwork, setSelectedNetwork] = useState<string | null>(null);
  const [networkPasswords, setNetworkPasswords] = useState<Record<string, string>>({});
  const [connectedSsid, setConnectedSsid] = useState<string | null>(null);

  const [clients, setClients] = useState<WifiClient[]>([]);

  const [applying, setApplying] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const [modeData, clientData] = await Promise.all([
          wifiService.getWifiMode(),
          wifiService.getConnectedClients(),
        ]);
        applyModeData(modeData);
        setClients(clientData.clients);
      } catch {
        setWifiState("ERROR");
      }
    }
    load();

    // Live updates for the connected-clients KPI only — mode is not re-polled
    // because the user may have unsaved edits in the form.
    const id = setInterval(async () => {
      try {
        const clientData = await wifiService.getConnectedClients();
        setClients(clientData.clients);
      } catch { /* ignore transient polling errors */ }
    }, 10000);
    return () => clearInterval(id);
  }, []);

  function applyModeData(data: WifiModeResponse) {
    setCurrentMode(data.mode);
    setSelectedMode(data.mode);
    setWifiState(stateFromMode(data.mode));
    setHotspotSsid(data.module1.ssid || "ARMIA");
    setHotspotBand((data.module1.band as "2.4GHz" | "5GHz") || "2.4GHz");
    setConnectedSsid(data.module2.connected_ssid);
    setSuricataRunning(data.security.suricata_running);
    setZeroTrustActive(data.security.zero_trust_active);
  }

  const showHotspot = selectedMode !== "client_only";
  const showExternal = selectedMode === "dual" || selectedMode === "client_only";
  const showClients = selectedMode !== "client_only";

  async function handleScan() {
    setScanning(true);
    try {
      const res = await wifiService.scanNetworks();
      setScannedNetworks(res.networks);
    } catch {
      toast.error("Scan failed. Check Wi-Fi module.");
    } finally {
      setScanning(false);
    }
  }

  async function handleApply() {
    setApplying(true);
    setWifiState("DUAL_STARTING");
    try {
      const payload: Parameters<typeof wifiService.setWifiMode>[0] = {
        mode: selectedMode,
      };
      if (showHotspot) {
        payload.module1 = { ssid: hotspotSsid, password: hotspotPassword, band: hotspotBand };
      }
      if (showExternal && selectedNetwork) {
        payload.module2 = { ssid: selectedNetwork, password: networkPasswords[selectedNetwork] || "" };
      }
      await wifiService.setWifiMode(payload);
      setCurrentMode(selectedMode);
      setWifiState(stateFromMode(selectedMode));
      toast.success("Configuration applied");
    } catch (err: any) {
      setWifiState("ERROR");
      toast.error(err?.message || "Failed to apply configuration");
    } finally {
      setApplying(false);
    }
  }

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Dual Wi-Fi Mode" />

      <div style={{ flex: 1, overflowY: "auto" }}>
        <div
          className="mx-auto w-full max-w-2xl"
          style={{
            padding: "16px",
            display: "flex",
            flexDirection: "column",
            gap: "16px",
            paddingBottom: "100px",
          }}
        >
        {/* State badge row */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <StateBadge state={wifiState} />
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            Current: {currentMode.replace("_", " ")}
          </span>
        </div>

        {/* Zero-Trust Protection Banner */}
        {selectedMode === "dual" && suricataRunning && zeroTrustActive && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              padding: "12px 14px",
              borderRadius: "var(--radius)",
              backgroundColor: "color-mix(in srgb, var(--chart-2) 10%, transparent)",
              border: "1px solid color-mix(in srgb, var(--chart-2) 30%, transparent)",
            }}
          >
            <Shield size={16} style={{ color: "var(--chart-2)", flexShrink: 0 }} />
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--chart-2)",
                lineHeight: 1.5,
              }}
            >
              Zero-Trust Protection Active — All traffic inspected by Guardian security engine
            </p>
          </div>
        )}

        {/* Mode Selector */}
        <div>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--muted-foreground)",
              letterSpacing: "0.08em",
              marginBottom: "8px",
              paddingLeft: "4px",
            }}
          >
            Operation Mode
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {MODE_OPTIONS.map(({ key, label, description, Icon }) => {
              const active = selectedMode === key;
              return (
                <button
                  key={key}
                  onClick={() => setSelectedMode(key)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "14px",
                    padding: "14px 16px",
                    borderRadius: "var(--radius)",
                    backgroundColor: active
                      ? "color-mix(in srgb, var(--primary) 8%, var(--card))"
                      : "var(--card)",
                    border: active
                      ? "1.5px solid var(--primary)"
                      : "1.5px solid var(--border)",
                    cursor: "pointer",
                    textAlign: "left",
                    transition: "border-color 0.15s, background-color 0.15s",
                  }}
                >
                  <div
                    style={{
                      width: "36px",
                      height: "36px",
                      borderRadius: "8px",
                      backgroundColor: active
                        ? "color-mix(in srgb, var(--primary) 15%, transparent)"
                        : "var(--muted)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0,
                    }}
                  >
                    <Icon
                      size={18}
                      style={{ color: active ? "var(--primary)" : "var(--muted-foreground)" }}
                    />
                  </div>
                  <div style={{ flex: 1 }}>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-sm)",
                        fontWeight: "var(--font-weight-semibold)",
                        color: active ? "var(--primary)" : "var(--foreground)",
                        marginBottom: "2px",
                      }}
                    >
                      {label}
                    </p>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-xs)",
                        color: "var(--muted-foreground)",
                      }}
                    >
                      {description}
                    </p>
                  </div>
                  {active && (
                    <div
                      style={{
                        width: "10px",
                        height: "10px",
                        borderRadius: "50%",
                        backgroundColor: "var(--primary)",
                        flexShrink: 0,
                      }}
                    />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Traffic Flow Diagram — dual only */}
        {selectedMode === "dual" && (
          <div
            style={{
              borderRadius: "var(--radius)",
              border: "1px solid var(--border)",
              backgroundColor: "var(--card)",
              padding: "16px",
            }}
          >
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.08em",
                marginBottom: "12px",
              }}
            >
              Traffic Flow
            </p>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "4px",
                overflowX: "auto",
                paddingBottom: "4px",
              }}
            >
              {[
                { label: "Your Devices", accent: false },
                null,
                { label: "Wi-Fi 1", accent: false },
                null,
                { label: "GUARDIAN", accent: true },
                null,
                { label: "Wi-Fi 2", accent: false },
                null,
                { label: "Internet", accent: false },
              ].map((item, idx) => {
                if (item === null) {
                  return (
                    <ChevronRight
                      key={idx}
                      size={12}
                      style={{ color: "var(--muted-foreground)", flexShrink: 0 }}
                    />
                  );
                }
                return (
                  <div
                    key={idx}
                    style={{
                      padding: "5px 10px",
                      borderRadius: "6px",
                      backgroundColor: item.accent
                        ? "var(--primary)"
                        : "var(--muted)",
                      border: item.accent ? "none" : "1px solid var(--border)",
                      flexShrink: 0,
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "10px",
                        fontWeight: "var(--font-weight-semibold)",
                        color: item.accent ? "var(--primary-foreground)" : "var(--foreground)",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {item.label}
                    </span>
                  </div>
                );
              })}
            </div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
                marginTop: "8px",
                textAlign: "center",
              }}
            >
              All traffic inspected &amp; protected
            </p>
          </div>
        )}

        {/* Hotspot Config */}
        {showHotspot && (
          <div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.08em",
                marginBottom: "8px",
                paddingLeft: "4px",
              }}
            >
              Hotspot Config (Module 1)
            </p>
            <div
              style={{
                borderRadius: "var(--radius)",
                border: "1px solid var(--border)",
                backgroundColor: "var(--card)",
                padding: "16px",
                display: "flex",
                flexDirection: "column",
                gap: "14px",
              }}
            >
              <div>
                <label
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-medium)",
                    color: "var(--muted-foreground)",
                    marginBottom: "6px",
                    display: "block",
                  }}
                >
                  SSID
                </label>
                <input
                  value={hotspotSsid}
                  onChange={(e) => setHotspotSsid(e.target.value)}
                  placeholder="Hotspot SSID"
                  className="w-full px-4 outline-none"
                  style={{
                    height: "44px",
                    backgroundColor: "var(--input-background)",
                    border: "1.5px solid var(--border)",
                    borderRadius: "var(--radius)",
                    color: "var(--foreground)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                  }}
                />
              </div>
              <div>
                <label
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-medium)",
                    color: "var(--muted-foreground)",
                    marginBottom: "6px",
                    display: "block",
                  }}
                >
                  Password
                </label>
                <div style={{ position: "relative" }}>
                  <input
                    type={showHotspotPw ? "text" : "password"}
                    value={hotspotPassword}
                    onChange={(e) => setHotspotPassword(e.target.value)}
                    placeholder="Hotspot password"
                    className="w-full outline-none"
                    style={{
                      height: "44px",
                      backgroundColor: "var(--input-background)",
                      border: "1.5px solid var(--border)",
                      borderRadius: "var(--radius)",
                      color: "var(--foreground)",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      paddingLeft: "16px",
                      paddingRight: "44px",
                      width: "100%",
                      boxSizing: "border-box",
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowHotspotPw((v) => !v)}
                    style={{
                      position: "absolute",
                      right: "12px",
                      top: "50%",
                      transform: "translateY(-50%)",
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      padding: "4px",
                    }}
                  >
                    {showHotspotPw ? (
                      <EyeOff size={16} style={{ color: "var(--muted-foreground)" }} />
                    ) : (
                      <Eye size={16} style={{ color: "var(--muted-foreground)" }} />
                    )}
                  </button>
                </div>
              </div>
              <div>
                <label
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-medium)",
                    color: "var(--muted-foreground)",
                    marginBottom: "6px",
                    display: "block",
                  }}
                >
                  Band
                </label>
                <div style={{ display: "flex", gap: "8px" }}>
                  {(["2.4GHz", "5GHz"] as const).map((band) => (
                    <button
                      key={band}
                      onClick={() => setHotspotBand(band)}
                      style={{
                        flex: 1,
                        height: "40px",
                        borderRadius: "var(--radius)",
                        backgroundColor:
                          hotspotBand === band
                            ? "var(--primary)"
                            : "var(--secondary)",
                        color:
                          hotspotBand === band
                            ? "var(--primary-foreground)"
                            : "var(--secondary-foreground)",
                        border:
                          hotspotBand === band
                            ? "none"
                            : "1px solid var(--border)",
                        cursor: "pointer",
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-sm)",
                        fontWeight: "var(--font-weight-medium)",
                        transition: "background-color 0.15s",
                      }}
                    >
                      {band}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* External Network Section */}
        {showExternal && (
          <div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.08em",
                marginBottom: "8px",
                paddingLeft: "4px",
              }}
            >
              External Network (Module 2)
            </p>
            <div
              style={{
                borderRadius: "var(--radius)",
                border: "1px solid var(--border)",
                backgroundColor: "var(--card)",
                overflow: "hidden",
              }}
            >
              <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
                <button
                  onClick={handleScan}
                  disabled={scanning}
                  style={{
                    width: "100%",
                    height: "44px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "8px",
                    borderRadius: "var(--radius)",
                    backgroundColor: "var(--secondary)",
                    color: "var(--secondary-foreground)",
                    border: "1px solid var(--border)",
                    cursor: scanning ? "not-allowed" : "pointer",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-medium)",
                    opacity: scanning ? 0.7 : 1,
                  }}
                >
                  {scanning ? (
                    <Loader2 size={15} className="animate-spin" />
                  ) : (
                    <Wifi size={15} />
                  )}
                  {scanning ? "Scanning…" : "Scan for Networks"}
                </button>
              </div>

              {scannedNetworks.length === 0 && !scanning && (
                <div style={{ padding: "20px 16px", textAlign: "center" }}>
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                    }}
                  >
                    Tap "Scan for Networks" to discover nearby APs
                  </p>
                </div>
              )}

              {scannedNetworks.map((net, i) => {
                const isConnected = net.ssid === connectedSsid;
                const isSelected = selectedNetwork === net.ssid;
                return (
                  <div key={net.ssid}>
                    <div
                      onClick={() =>
                        setSelectedNetwork((prev) => (prev === net.ssid ? null : net.ssid))
                      }
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "12px",
                        padding: "14px 16px",
                        borderBottom:
                          i < scannedNetworks.length - 1 || isSelected
                            ? "1px solid var(--border)"
                            : undefined,
                        cursor: "pointer",
                        backgroundColor: isSelected
                          ? "color-mix(in srgb, var(--primary) 5%, var(--card))"
                          : undefined,
                        transition: "background-color 0.1s",
                      }}
                    >
                      <Wifi
                        size={16}
                        style={{
                          color: isConnected ? "var(--chart-2)" : "var(--muted-foreground)",
                          flexShrink: 0,
                        }}
                      />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                          <p
                            style={{
                              fontFamily: "Inter, sans-serif",
                              fontSize: "var(--text-sm)",
                              fontWeight: "var(--font-weight-medium)",
                              color: "var(--foreground)",
                            }}
                          >
                            {net.ssid}
                          </p>
                          {isConnected && (
                            <span
                              style={{
                                fontFamily: "Inter, sans-serif",
                                fontSize: "10px",
                                fontWeight: "var(--font-weight-semibold)",
                                color: "var(--chart-2)",
                              }}
                            >
                              Connected
                            </span>
                          )}
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "2px" }}>
                          {net.security !== "Open" && (
                            <Lock size={10} style={{ color: "var(--muted-foreground)" }} />
                          )}
                          <span
                            style={{
                              fontFamily: "Inter, sans-serif",
                              fontSize: "var(--text-xs)",
                              color: "var(--muted-foreground)",
                            }}
                          >
                            {net.security} · {net.band}
                          </span>
                        </div>
                      </div>
                      <SignalBars dbm={net.signal_dbm} />
                    </div>

                    {isSelected && (
                      <div
                        style={{
                          padding: "12px 16px",
                          borderBottom:
                            i < scannedNetworks.length - 1 ? "1px solid var(--border)" : undefined,
                          backgroundColor: "color-mix(in srgb, var(--primary) 3%, var(--card))",
                        }}
                      >
                        <input
                          type="password"
                          value={networkPasswords[net.ssid] || ""}
                          onChange={(e) =>
                            setNetworkPasswords((prev) => ({
                              ...prev,
                              [net.ssid]: e.target.value,
                            }))
                          }
                          placeholder={`Password for ${net.ssid}`}
                          className="w-full px-4 outline-none"
                          style={{
                            height: "40px",
                            backgroundColor: "var(--input-background)",
                            border: "1.5px solid var(--border)",
                            borderRadius: "var(--radius)",
                            color: "var(--foreground)",
                            fontFamily: "Inter, sans-serif",
                            fontSize: "var(--text-sm)",
                          }}
                          autoFocus
                        />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Connected Clients */}
        {showClients && (
          <div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.08em",
                marginBottom: "8px",
                paddingLeft: "4px",
              }}
            >
              Devices on Hotspot
            </p>
            <div
              style={{
                borderRadius: "var(--radius)",
                border: "1px solid var(--border)",
                backgroundColor: "var(--card)",
                overflow: "hidden",
              }}
            >
              {clients.length === 0 ? (
                <div style={{ padding: "24px 16px", textAlign: "center" }}>
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      color: "var(--muted-foreground)",
                    }}
                  >
                    No devices connected
                  </p>
                </div>
              ) : (
                clients.map((client, i) => (
                  <div
                    key={client.mac}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "12px",
                      padding: "12px 16px",
                      borderBottom:
                        i < clients.length - 1 ? "1px solid var(--border)" : undefined,
                    }}
                  >
                    <div
                      style={{
                        width: "34px",
                        height: "34px",
                        borderRadius: "8px",
                        backgroundColor: "var(--muted)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}
                    >
                      <Wifi size={15} style={{ color: "var(--muted-foreground)" }} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p
                        style={{
                          fontFamily: "Inter, sans-serif",
                          fontSize: "var(--text-sm)",
                          fontWeight: "var(--font-weight-medium)",
                          color: "var(--foreground)",
                          marginBottom: "2px",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {client.hostname}
                      </p>
                      <p
                        style={{
                          fontFamily: "JetBrains Mono, monospace",
                          fontSize: "10px",
                          color: "var(--muted-foreground)",
                        }}
                      >
                        {client.mac.slice(0, 11)}… · {client.ip}
                      </p>
                    </div>
                    <SignalBars dbm={client.signal_dbm} />
                  </div>
                ))
              )}
            </div>
          </div>
        )}
        </div>
      </div>

      {/* Sticky Apply Button */}
      <div
        style={{
          position: "sticky",
          bottom: 0,
          padding: "12px 16px 20px",
          backgroundColor: "var(--background)",
          borderTop: "1px solid var(--border)",
        }}
      >
        <div className="mx-auto w-full max-w-2xl">
        {selectedMode !== currentMode && (
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
              textAlign: "center",
              marginBottom: "8px",
            }}
          >
            ~3 seconds downtime when switching modes
          </p>
        )}
        <button
          onClick={handleApply}
          disabled={applying}
          style={{
            width: "100%",
            height: "50px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
            borderRadius: "var(--radius)",
            backgroundColor: applying ? "var(--muted)" : "var(--primary)",
            color: applying ? "var(--muted-foreground)" : "var(--primary-foreground)",
            border: "none",
            cursor: applying ? "not-allowed" : "pointer",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-semibold)",
            transition: "background-color 0.15s",
          }}
        >
          {applying && <Loader2 size={16} className="animate-spin" />}
          {applying ? "Applying…" : "Apply Configuration"}
        </button>
        </div>
      </div>
    </div>
  );
}
