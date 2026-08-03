import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Eye,
  EyeOff,
  Loader2,
  Lock,
  Power,
  Radio,
  RefreshCw,
  Shield,
  Smartphone,
  Wifi,
  WifiOff,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../../components/ui/alert-dialog";
import wifiService, {
  type ScannedNetwork,
  type WifiBand,
  type WifiClient,
  type WifiMode,
  type WifiModePayload,
  type WifiModeRequest,
  type WifiModeResponse,
} from "../../services/wifiService";

const MODE_REQUEST: Record<WifiMode, WifiModeRequest> = {
  off: "Off",
  hotspot_only: "HotspotOnly",
  client_only: "ClientOnly",
  dual: "DualWifi",
};

const MODE_OPTIONS: Array<{
  key: WifiMode;
  label: string;
  description: string;
  icon: typeof Wifi;
}> = [
  { key: "dual", label: "Dual Wi-Fi", description: "Hotspot and upstream Wi-Fi with protected routing", icon: Shield },
  { key: "hotspot_only", label: "Hotspot only", description: "Broadcast a local network using the AP module", icon: Radio },
  { key: "client_only", label: "Client only", description: "Connect Guardian directly to an upstream Wi-Fi network", icon: Wifi },
  { key: "off", label: "Off", description: "Stop Wi-Fi orchestration, DHCP, DNS and NAT", icon: Power },
];

const TRANSITION_STATES = new Set([
  "ApplyingChange",
  "HotspotStarting",
  "ClientConnecting",
  "DualStarting",
]);

function sleep(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function stateTone(state: string) {
  if (state === "Error") return { color: "var(--destructive)", background: "color-mix(in srgb, var(--destructive) 12%, transparent)" };
  if (TRANSITION_STATES.has(state)) return { color: "var(--chart-4)", background: "color-mix(in srgb, var(--chart-4) 12%, transparent)" };
  if (["DualActive", "HotspotActive", "ClientConnected"].includes(state)) return { color: "var(--chart-2)", background: "color-mix(in srgb, var(--chart-2) 12%, transparent)" };
  return { color: "var(--muted-foreground)", background: "var(--muted)" };
}

function SignalBars({ dbm }: { dbm: number }) {
  const strength = dbm > -55 ? 4 : dbm > -65 ? 3 : dbm > -75 ? 2 : 1;
  return (
    <div className="flex h-4 items-end gap-0.5" aria-label={`${dbm} dBm`}>
      {[1, 2, 3, 4].map((bar) => (
        <span
          key={bar}
          className="w-[3px] rounded-sm"
          style={{ height: `${bar * 3 + 2}px`, background: bar <= strength ? "var(--chart-2)" : "var(--border)" }}
        />
      ))}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h2 className="px-1 text-xs font-semibold uppercase tracking-[0.08em] text-muted-foreground">{title}</h2>
      <div className="rounded-lg border bg-card p-4">{children}</div>
    </section>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return <label className="mb-1.5 block text-xs font-medium text-muted-foreground">{children}</label>;
}

const inputClass = "h-11 w-full rounded-lg border bg-input-background px-3 text-sm outline-none transition focus:border-primary focus:ring-2 focus:ring-primary/15";

export function ST13DualWifi() {
  const [modeData, setModeData] = useState<WifiModeResponse | null>(null);
  const [selectedMode, setSelectedMode] = useState<WifiMode>("dual");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const [hotspotSsid, setHotspotSsid] = useState("SGX_Hotspot");
  const [hotspotPassword, setHotspotPassword] = useState("");
  const [showHotspotPassword, setShowHotspotPassword] = useState(false);
  const [band, setBand] = useState<WifiBand>("2.4GHz");
  const [channel, setChannel] = useState(6);
  const [clientIsolation, setClientIsolation] = useState(true);
  const [restoreOnBoot, setRestoreOnBoot] = useState(true);

  const [networks, setNetworks] = useState<ScannedNetwork[]>([]);
  const [selectedNetworkKey, setSelectedNetworkKey] = useState<string | null>(null);
  const [uplinkPassword, setUplinkPassword] = useState("");
  const [showUplinkPassword, setShowUplinkPassword] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [clients, setClients] = useState<WifiClient[]>([]);
  const [clientsLoading, setClientsLoading] = useState(false);

  const selectedNetwork = useMemo(
    () => networks.find((network) => (network.bssid || network.ssid) === selectedNetworkKey) ?? null,
    [networks, selectedNetworkKey],
  );
  const showHotspot = selectedMode === "dual" || selectedMode === "hotspot_only";
  const showUplink = selectedMode === "dual" || selectedMode === "client_only";

  const syncMode = useCallback((data: WifiModeResponse, syncForm = false) => {
    setModeData(data);
    setLoadError(null);
    if (syncForm) {
      setSelectedMode(data.mode);
      setHotspotSsid(data.module1.ssid || "SGX_Hotspot");
      setChannel(data.module1.channel || 6);
      setBand(data.module1.channel >= 30 ? "5GHz" : "2.4GHz");
      setRestoreOnBoot(data.mode !== "off" && data.mode !== "hotspot_only");
    }
  }, []);

  const refreshStatus = useCallback(async (syncForm = false) => {
    const data = await wifiService.getWifiMode();
    syncMode(data, syncForm);
    return data;
  }, [syncMode]);

  const refreshClients = useCallback(async (announce = false) => {
    setClientsLoading(true);
    try {
      const response = await wifiService.getConnectedClients();
      setClients(response.clients);
      if (announce) toast.success("Connected clients refreshed");
    } catch (error) {
      if (announce) toast.error(error instanceof Error ? error.message : "Could not load hotspot clients");
    } finally {
      setClientsLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    Promise.all([wifiService.getWifiMode(), wifiService.getConnectedClients()])
      .then(([status, clientResponse]) => {
        if (cancelled) return;
        syncMode(status, true);
        setClients(clientResponse.clients);
      })
      .catch((error) => {
        if (!cancelled) setLoadError(error instanceof Error ? error.message : "Network orchestration is unavailable");
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    const timer = window.setInterval(() => {
      void wifiService.getConnectedClients().then((response) => {
        if (!cancelled) setClients(response.clients);
      }).catch(() => undefined);
    }, 15_000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [syncMode]);

  useEffect(() => {
    setChannel(band === "5GHz" ? 36 : 6);
  }, [band]);

  async function scan() {
    setScanning(true);
    try {
      const response = await wifiService.scanNetworks();
      const unique = response.networks.filter(
        (network, index, all) => all.findIndex((item) => (item.bssid || item.ssid) === (network.bssid || network.ssid)) === index,
      );
      setNetworks(unique.sort((a, b) => b.signal_dbm - a.signal_dbm));
      toast.success(unique.length ? `Found ${unique.length} Wi-Fi network${unique.length === 1 ? "" : "s"}` : "Scan completed; no networks found");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Wi-Fi scan failed");
    } finally {
      setScanning(false);
    }
  }

  function validationError() {
    if (showHotspot) {
      if (!hotspotSsid.trim()) return "Enter a hotspot SSID.";
      if (hotspotPassword.length < 8) return "Hotspot password must contain at least 8 characters.";
      if (!/[^a-zA-Z0-9]/.test(hotspotPassword)) return "Hotspot password must contain a symbol such as !, @, # or $.";
    }
    if (showUplink && !selectedNetwork) return "Scan and select an upstream Wi-Fi network.";
    if (showUplink && selectedNetwork?.security.toLowerCase() !== "open" && !uplinkPassword) return "Enter the upstream Wi-Fi password.";
    return null;
  }

  function requestApply() {
    const error = validationError();
    if (error) { toast.error(error); return; }
    setConfirmOpen(true);
  }

  function buildPayload(): WifiModePayload {
    return {
      mode: MODE_REQUEST[selectedMode],
      flags: { restore_on_boot: selectedMode === "off" ? false : restoreOnBoot },
      hotspot: showHotspot
        ? {
            interface: "uap0",
            ssid: hotspotSsid.trim(),
            password: hotspotPassword,
            channel,
            band,
            client_isolation: clientIsolation,
          }
        : { interface: "uap0", ssid: "", password: "", channel: 1, band: "2.4GHz", client_isolation: false },
      uplink: {
        interface: "wlan1",
        networks: showUplink && selectedNetwork
          ? [{ ssid: selectedNetwork.ssid, bssid: selectedNetwork.bssid || null, password: uplinkPassword }]
          : [],
      },
    };
  }

  async function applyConfiguration() {
    setConfirmOpen(false);
    setApplying(true);
    try {
      const response = await wifiService.setWifiMode(buildPayload());
      toast.info(`Configuration accepted. Expected interruption: ${response.estimated_downtime_seconds ?? 3}s`);

      let finalStatus: WifiModeResponse | null = null;
      for (let attempt = 0; attempt < 15; attempt += 1) {
        await sleep(attempt === 0 ? 1_000 : 2_000);
        const status = await refreshStatus(false);
        finalStatus = status;
        if (status.status.state === "Error") {
          throw new Error(status.status.metadata.message || status.status.metadata.error_code || "Network transition failed");
        }
        if (!TRANSITION_STATES.has(status.status.state) && status.mode === selectedMode) break;
      }

      if (!finalStatus || TRANSITION_STATES.has(finalStatus.status.state)) {
        toast.warning("Configuration is still applying. Status monitoring will continue when the page refreshes.");
      } else {
        toast.success(`${MODE_OPTIONS.find((option) => option.key === selectedMode)?.label} is active`);
      }
      setHotspotPassword("");
      setUplinkPassword("");
      await refreshClients(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to apply Wi-Fi configuration");
      await refreshStatus(false).catch(() => undefined);
    } finally {
      setApplying(false);
    }
  }

  const runtimeState = modeData?.status.state ?? (loading ? "Loading" : "Unavailable");
  const tone = stateTone(runtimeState);

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Dual Wi-Fi Mode" />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto flex w-full max-w-2xl flex-col gap-4 px-4 pb-28 pt-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-card p-4">
            <div className="flex items-center gap-3">
              <span className="rounded px-2 py-1 text-[10px] font-semibold uppercase tracking-wider" style={tone}>{runtimeState}</span>
              <div>
                <p className="text-sm font-semibold">Network orchestrator</p>
                <p className="text-xs text-muted-foreground">Current mode: {modeData?.mode.replaceAll("_", " ") ?? "unknown"}</p>
              </div>
            </div>
            <button
              className="flex h-9 items-center gap-2 rounded-lg border px-3 text-xs font-medium hover:bg-muted disabled:opacity-50"
              disabled={loading || applying}
              onClick={() => void refreshStatus(true).then(() => toast.success("Status refreshed")).catch((error) => toast.error(error.message))}
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
          </div>

          {loadError && (
            <div className="flex gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
              <AlertCircle size={18} className="shrink-0" />
              <div><p className="font-semibold">Could not load Wi-Fi state</p><p className="mt-1 text-xs opacity-90">{loadError}</p></div>
            </div>
          )}

          {modeData?.status.metadata.message && (
            <div className="flex gap-3 rounded-lg border bg-muted/50 p-4 text-sm">
              {runtimeState === "Error" ? <AlertCircle size={18} className="text-destructive" /> : <Clock3 size={18} className="text-muted-foreground" />}
              <span>{modeData.status.metadata.message}</span>
            </div>
          )}

          {modeData?.security.zero_trust_active && (
            <div className="flex items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-600">
              <CheckCircle2 size={18} />
              <div><p className="font-semibold">Zero-Trust routing active</p><p className="text-xs">NAT and enforcement are active between hotspot and uplink.</p></div>
            </div>
          )}

          <Section title="Operation mode">
            <div className="grid gap-2 sm:grid-cols-2">
              {MODE_OPTIONS.map((option) => {
                const Icon = option.icon;
                const active = selectedMode === option.key;
                return (
                  <button
                    key={option.key}
                    disabled={applying}
                    onClick={() => setSelectedMode(option.key)}
                    className={`flex items-start gap-3 rounded-lg border p-3 text-left transition ${active ? "border-primary bg-primary/5 ring-1 ring-primary" : "hover:bg-muted/50"}`}
                  >
                    <span className={`rounded-lg p-2 ${active ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"}`}><Icon size={17} /></span>
                    <span><span className="block text-sm font-semibold">{option.label}</span><span className="mt-1 block text-xs leading-relaxed text-muted-foreground">{option.description}</span></span>
                  </button>
                );
              })}
            </div>
          </Section>

          {selectedMode === "dual" && (
            <Section title="Protected traffic flow">
              <div className="flex items-center justify-between gap-1 overflow-x-auto text-[10px] font-semibold">
                {["Devices", "Guardian AP", "Zero Trust", "Uplink", "Internet"].map((label, index) => (
                  <div key={label} className="contents">
                    <span className={label === "Zero Trust" ? "rounded-md bg-primary px-2 py-2 text-primary-foreground" : "whitespace-nowrap rounded-md bg-muted px-2 py-2"}>{label}</span>
                    {index < 4 && <ChevronRight size={13} className="shrink-0 text-muted-foreground" />}
                  </div>
                ))}
              </div>
            </Section>
          )}

          {showHotspot && (
            <Section title="Hotspot configuration · uap0">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="sm:col-span-2"><FieldLabel>SSID</FieldLabel><input className={inputClass} value={hotspotSsid} onChange={(event) => setHotspotSsid(event.target.value)} placeholder="SGX_Hotspot" maxLength={32} /></div>
                <div className="sm:col-span-2">
                  <FieldLabel>Secure password</FieldLabel>
                  <div className="relative"><input className={`${inputClass} pr-11`} type={showHotspotPassword ? "text" : "password"} value={hotspotPassword} onChange={(event) => setHotspotPassword(event.target.value)} placeholder="8+ characters with at least one symbol" autoComplete="new-password" /><button type="button" className="absolute right-3 top-3 text-muted-foreground" onClick={() => setShowHotspotPassword((value) => !value)}>{showHotspotPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
                  <p className="mt-1.5 text-[11px] text-muted-foreground">Common passwords are rejected by Guardian.</p>
                </div>
                <div><FieldLabel>Band</FieldLabel><div className="flex gap-2">{(["2.4GHz", "5GHz"] as WifiBand[]).map((value) => <button key={value} onClick={() => setBand(value)} className={`h-11 flex-1 rounded-lg border text-sm font-medium ${band === value ? "border-primary bg-primary text-primary-foreground" : "hover:bg-muted"}`}>{value}</button>)}</div></div>
                <div><FieldLabel>Channel</FieldLabel><select className={inputClass} value={channel} onChange={(event) => setChannel(Number(event.target.value))}>{(band === "2.4GHz" ? [1, 6, 11] : [36, 40, 44, 48]).map((value) => <option key={value} value={value}>{value}</option>)}</select></div>
                <label className="flex items-center justify-between gap-4 rounded-lg border p-3 sm:col-span-2"><span><span className="block text-sm font-medium">Client isolation</span><span className="block text-xs text-muted-foreground">Prevent hotspot clients from directly reaching one another.</span></span><input type="checkbox" checked={clientIsolation} onChange={(event) => setClientIsolation(event.target.checked)} className="h-4 w-4 accent-primary" /></label>
              </div>
            </Section>
          )}

          {showUplink && (
            <Section title="Upstream Wi-Fi · wlan1">
              <button disabled={scanning || applying} onClick={() => void scan()} className="flex h-11 w-full items-center justify-center gap-2 rounded-lg border bg-secondary text-sm font-medium hover:bg-muted disabled:opacity-60">{scanning ? <Loader2 size={16} className="animate-spin" /> : <Wifi size={16} />}{scanning ? "Scanning…" : "Scan visible networks"}</button>
              {networks.length === 0 ? <p className="py-6 text-center text-xs text-muted-foreground">Scan to select an upstream access point.</p> : (
                <div className="mt-3 max-h-64 divide-y overflow-y-auto rounded-lg border">
                  {networks.map((network) => {
                    const key = network.bssid || network.ssid;
                    const active = key === selectedNetworkKey;
                    return <button key={key} onClick={() => { setSelectedNetworkKey(key); setUplinkPassword(""); }} className={`flex w-full items-center gap-3 p-3 text-left transition ${active ? "bg-primary/10" : "hover:bg-muted/50"}`}><Wifi size={16} className={active ? "text-primary" : "text-muted-foreground"} /><span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{network.ssid || "Hidden network"}</span><span className="block text-[11px] text-muted-foreground">{network.security} · {network.band} · {network.bssid}</span></span>{network.security.toLowerCase() !== "open" && <Lock size={12} className="text-muted-foreground" />}<SignalBars dbm={network.signal_dbm} /></button>;
                  })}
                </div>
              )}
              {selectedNetwork && selectedNetwork.security.toLowerCase() !== "open" && <div className="mt-4"><FieldLabel>Password for {selectedNetwork.ssid}</FieldLabel><div className="relative"><input className={`${inputClass} pr-11`} type={showUplinkPassword ? "text" : "password"} value={uplinkPassword} onChange={(event) => setUplinkPassword(event.target.value)} autoComplete="new-password" /><button type="button" className="absolute right-3 top-3 text-muted-foreground" onClick={() => setShowUplinkPassword((value) => !value)}>{showUplinkPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></div>}
              {modeData?.module2.saved_networks.length ? <p className="mt-3 text-xs text-muted-foreground">Saved: {modeData.module2.saved_networks.join(", ")}</p> : null}
            </Section>
          )}

          {selectedMode !== "off" && (
            <Section title="Persistence">
              <label className="flex items-center justify-between gap-4"><span><span className="block text-sm font-medium">Restore on boot</span><span className="block text-xs text-muted-foreground">Reapply this network mode after Guardian restarts.</span></span><input type="checkbox" checked={restoreOnBoot} onChange={(event) => setRestoreOnBoot(event.target.checked)} className="h-4 w-4 accent-primary" /></label>
            </Section>
          )}

          {selectedMode !== "client_only" && selectedMode !== "off" && (
            <Section title="Hotspot clients">
              <div className="mb-3 flex items-center justify-between"><p className="text-xs text-muted-foreground">{clients.length} active DHCP lease{clients.length === 1 ? "" : "s"}</p><button onClick={() => void refreshClients(true)} disabled={clientsLoading} className="rounded-md border p-2 text-muted-foreground hover:bg-muted"><RefreshCw size={14} className={clientsLoading ? "animate-spin" : ""} /></button></div>
              {clients.length === 0 ? <div className="py-6 text-center"><WifiOff className="mx-auto mb-2 text-muted-foreground" size={22} /><p className="text-sm text-muted-foreground">No clients connected</p></div> : <div className="divide-y rounded-lg border">{clients.map((client) => <div key={`${client.mac_address}-${client.client_id}`} className="flex items-center gap-3 p-3"><span className="rounded-lg bg-muted p-2"><Smartphone size={15} /></span><span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{client.hostname || "Unknown client"}</span><span className="block text-[11px] text-muted-foreground">{client.ip_address} · {client.mac_address}</span></span><span className="text-[10px] text-muted-foreground">expires {new Date(client.expiry * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span></div>)}</div>}
            </Section>
          )}
        </div>
      </main>

      <footer className="border-t bg-background px-4 py-3">
        <div className="mx-auto max-w-2xl"><button disabled={applying || loading} onClick={requestApply} className="flex h-12 w-full items-center justify-center gap-2 rounded-lg bg-primary text-sm font-semibold text-primary-foreground transition hover:opacity-90 disabled:cursor-not-allowed disabled:bg-muted disabled:text-muted-foreground">{applying && <Loader2 size={16} className="animate-spin" />}{applying ? `Applying ${MODE_OPTIONS.find((option) => option.key === selectedMode)?.label}…` : "Review and apply configuration"}</button></div>
      </footer>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader><AlertDialogTitle>Apply {MODE_OPTIONS.find((option) => option.key === selectedMode)?.label}?</AlertDialogTitle><AlertDialogDescription>This changes physical Wi-Fi routing and may interrupt access for approximately three seconds. The hotspot starts first in Dual Wi-Fi mode so local recovery remains available.</AlertDialogDescription></AlertDialogHeader>
          <div className="rounded-lg border bg-muted/40 p-3 text-xs"><dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2"><dt className="text-muted-foreground">Mode</dt><dd className="font-medium">{MODE_REQUEST[selectedMode]}</dd>{showHotspot && <><dt className="text-muted-foreground">Hotspot</dt><dd className="font-medium">{hotspotSsid} · {band} channel {channel}</dd></>}{showUplink && <><dt className="text-muted-foreground">Uplink</dt><dd className="font-medium">{selectedNetwork?.ssid}</dd></>}<dt className="text-muted-foreground">Restore</dt><dd className="font-medium">{selectedMode !== "off" && restoreOnBoot ? "On boot" : "No"}</dd></dl></div>
          <AlertDialogFooter><AlertDialogCancel disabled={applying}>Cancel</AlertDialogCancel><AlertDialogAction disabled={applying} onClick={(event) => { event.preventDefault(); void applyConfiguration(); }}>{selectedMode === "off" ? "Turn Wi-Fi off" : "Apply configuration"}</AlertDialogAction></AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
