import { useState, useEffect, useCallback, useRef } from "react";
import { useNavigate } from "react-router";
import {
  Plus, Search, Cpu, Shield, ShieldAlert, Trash2, Loader2, Info, LayoutList, ChevronRight,
  Ban, ShieldCheck, ScanSearch, Pencil, Check, X as XIcon2, UserX, RefreshCw,
} from "lucide-react";
import { toast } from "sonner";
import { deviceService, type PairedDevice, type DiscoveredDevice, type DeviceDetail } from "../../services/deviceService";
import {
  managedDeviceService,
  type ManagedDevice,
  type ManagedDevicesSummary,
  type DeviceScanRun,
} from "../../services/managedDeviceService";
import { StatusBadge } from "../../components/SeverityBadge";
import * as Dialog from "@radix-ui/react-dialog";
import * as Switch from "@radix-ui/react-switch";

type Tab = "paired" | "unpaired" | "fleet";

// ── Status dot for paired guardian ──────────────────────────────────────────
function StatusDot({ status }: { status: string }) {
  const isPending = status === "pending_bootstrap";
  return (
    <span
      style={{
        display: "inline-block",
        width: "8px",
        height: "8px",
        borderRadius: "50%",
        flexShrink: 0,
        backgroundColor: isPending ? "var(--chart-5)" : "var(--chart-2)",
        animation: isPending ? "pulse 2s ease-in-out infinite" : undefined,
      }}
    />
  );
}

// ── DeviceDetailPanel ────────────────────────────────────────────────────────
function DeviceDetailPanel({
  deviceId,
  onClose,
  onUnpair
}: {
  deviceId: string;
  onClose: () => void;
  onUnpair: (id: string) => void;
}) {
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    deviceService.getDevice(deviceId)
      .then((data) => {
        if (active) setDetail(data);
      })
      .catch((e: any) => {
        if (active) toast.error(e.message || "Failed to load device details");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [deviceId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 size={32} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Info size={32} style={{ color: "var(--muted-foreground)" }} />
        <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Failed to load details</p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", backgroundColor: "var(--card)", borderLeft: "1px solid var(--border)" }}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="rounded-lg flex items-center justify-center" style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
            <Shield size={20} style={{ color: "var(--primary)" }} />
          </div>
          <div>
            <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Guardian Node</h3>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{detail.serial}</p>
          </div>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)" }}>
          <XIcon />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-6">
        {/* Status */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>STATUS</p>
          <div className="flex items-center gap-2">
            <StatusDot status={detail.status} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", textTransform: "capitalize" }}>{detail.status}</span>
          </div>
        </div>

        {/* Info list */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>DEVICE INFO</p>
          <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--background)" }}>
            {[
              { label: "Node ID", value: detail.nodeId, mono: true },
              { label: "DID", value: detail.did, mono: true },
              { label: "Overlay IP", value: detail.overlayIp || "N/A", mono: true },
              { label: "Bootstrap Status", value: detail.bootstrapStatus },
            ].map(({ label, value, mono }, i, arr) => (
              <div key={label} className="flex items-center justify-between px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
                <span style={{ fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-all", maxWidth: "200px", textAlign: "right" }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        {detail.status !== 'unpaired' && (
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>ACTIONS</p>
            <button
              onClick={() => { onClose(); onUnpair(detail.deviceId); }}
              className="w-full flex items-center justify-center gap-2 rounded-lg"
              style={{ height: "44px", backgroundColor: "color-mix(in srgb, var(--destructive) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)", color: "var(--destructive)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer" }}
            >
              <Trash2 size={16} /> Unpair Guardian
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function XIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"></line>
      <line x1="6" y1="6" x2="18" y2="18"></line>
    </svg>
  );
}

// ── Fleet security helpers ───────────────────────────────────────────────────
function riskVariant(level: string): "success" | "warning" | "danger" | "muted" {
  switch (level) {
    case "critical":
    case "high":
      return "danger";
    case "medium":
      return "warning";
    case "low":
      return "success";
    default:
      return "muted";
  }
}

function scoreColor(score: number | null): string {
  if (score === null) return "var(--muted-foreground)";
  if (score >= 70) return "var(--chart-2)";
  if (score >= 40) return "var(--chart-5)";
  return "var(--destructive)";
}

function fleetDeviceLabel(device: ManagedDevice): string {
  return device.display_name || device.hostname || device.ip || device.mac || device.device_id;
}

function ScoreStat({ label, score }: { label: string; score: number | null }) {
  return (
    <div className="flex-1 rounded-lg border border-border p-3 flex flex-col items-center gap-1" style={{ backgroundColor: "var(--background)" }}>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.06em" }}>{label}</span>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "22px", fontWeight: "var(--font-weight-bold)", color: scoreColor(score) }}>
        {score === null ? "—" : score}
      </span>
    </div>
  );
}

// ── FleetDetailPanel ─────────────────────────────────────────────────────────
function FleetDetailPanel({
  device,
  onClose,
  onReject,
  onDelete,
  onChanged,
}: {
  device: ManagedDevice;
  onClose: () => void;
  onReject: (device: ManagedDevice) => void;
  onDelete: (device: ManagedDevice) => void;
  onChanged: () => void;
}) {
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState(device.display_name ?? "");
  const [savingName, setSavingName] = useState(false);
  const [togglingMonitor, setTogglingMonitor] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [scanRun, setScanRun] = useState<DeviceScanRun | null>(null);
  const [scanning, setScanning] = useState(false);
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    setEditingName(false);
    setNameDraft(device.display_name ?? "");
    setScanRun(null);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [device.device_id]);

  const stopPolling = () => {
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const handleStartScan = async () => {
    setScanning(true);
    try {
      const run = await managedDeviceService.startScan(device.device_id);
      setScanRun(run);
      if (run.state === "running") {
        pollRef.current = window.setInterval(async () => {
          try {
            const status = await managedDeviceService.scanStatus(device.device_id, run.scan_id);
            setScanRun(status);
            if (status.state !== "running") {
              stopPolling();
              onChanged();
            }
          } catch {
            stopPolling();
          }
        }, 2000);
      } else {
        onChanged();
      }
    } catch (error: any) {
      toast.error(error.message || "Failed to start scan");
    } finally {
      setScanning(false);
    }
  };

  const handleSaveName = async () => {
    setSavingName(true);
    try {
      await managedDeviceService.edit(device.device_id, { display_name: nameDraft.trim() || null });
      toast.success("Device name updated");
      setEditingName(false);
      onChanged();
    } catch (error: any) {
      toast.error(error.message || "Failed to update device name");
    } finally {
      setSavingName(false);
    }
  };

  const handleToggleMonitoring = async (checked: boolean) => {
    setTogglingMonitor(true);
    try {
      await managedDeviceService.edit(device.device_id, { monitoring_enabled: checked });
      onChanged();
    } catch (error: any) {
      toast.error(error.message || "Failed to update monitoring");
    } finally {
      setTogglingMonitor(false);
    }
  };

  const handleToggleBlock = async () => {
    setBlocking(true);
    try {
      if (device.blocked) {
        await managedDeviceService.unblock(device.device_id);
        toast.success("Device unblocked");
      } else {
        await managedDeviceService.block(device.device_id);
        toast.success("Device blocked");
      }
      onChanged();
    } catch (error: any) {
      toast.error(error.message || "Block/unblock failed");
    } finally {
      setBlocking(false);
    }
  };

  const hasIp = !!device.ip;
  const scanActive = scanning || scanRun?.state === "running";

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", backgroundColor: "var(--card)", borderLeft: "1px solid var(--border)" }}>
      <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-border">
        <div className="flex items-center gap-3 min-w-0">
          <div className="rounded-lg flex items-center justify-center flex-shrink-0" style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
            <Cpu size={20} style={{ color: "var(--primary)" }} />
          </div>
          <div className="min-w-0">
            {editingName ? (
              <div className="flex items-center gap-1.5">
                <input
                  autoFocus
                  value={nameDraft}
                  onChange={(e) => setNameDraft(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSaveName()}
                  className="outline-none"
                  style={{ width: "150px", height: "28px", fontSize: "var(--text-sm)", fontFamily: "Inter, sans-serif", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "0 6px", color: "var(--foreground)" }}
                />
                <button onClick={handleSaveName} disabled={savingName} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--chart-2)" }}>
                  {savingName ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
                </button>
                <button onClick={() => setEditingName(false)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)" }}>
                  <XIcon2 size={14} />
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-1.5">
                <h3 className="truncate" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", maxWidth: "160px" }}>
                  {fleetDeviceLabel(device)}
                </h3>
                <button onClick={() => setEditingName(true)} aria-label="Edit device name" style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)", flexShrink: 0 }}>
                  <Pencil size={12} />
                </button>
              </div>
            )}
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{device.ip || device.mac || device.device_id}</p>
          </div>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)", flexShrink: 0 }}>
          <XIcon />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-6">
        {/* Status badges */}
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={device.risk_level.toUpperCase()} variant={riskVariant(device.risk_level)} />
          {device.manual && <StatusBadge status="MANUAL" variant="info" />}
          {device.blocked && <StatusBadge status="BLOCKED" variant="danger" />}
          {device.rejected && <StatusBadge status="REJECTED" variant="danger" />}
          {device.monitoring_enabled && <StatusBadge status="MONITORED" variant="success" />}
        </div>

        {/* Scores */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>SCORES</p>
          <div className="flex gap-3">
            <ScoreStat label="SECURITY" score={device.security_score} />
            <ScoreStat label="PRIVACY" score={device.privacy_score} />
          </div>
          {(device.security_reasons.length > 0 || device.privacy_reasons.length > 0) && (
            <div className="mt-3 flex flex-col gap-1">
              {[...device.security_reasons, ...device.privacy_reasons].slice(0, 6).map((reason, i) => (
                <p key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>• {reason}</p>
              ))}
            </div>
          )}
        </div>

        {/* Info list */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>DEVICE INFO</p>
          <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--background)" }}>
            {[
              { label: "IP", value: device.ip || "N/A", mono: true },
              { label: "MAC", value: device.mac || "N/A", mono: true },
              { label: "Vendor", value: device.vendor || "N/A" },
              { label: "Hostname", value: device.hostname || "N/A" },
              { label: "OS Fingerprint", value: device.os_fingerprint || "N/A" },
              { label: "Open Ports", value: String(device.open_ports.length) },
              { label: "Last Seen", value: device.last_seen ? new Date(device.last_seen).toLocaleString() : "N/A" },
            ].map(({ label, value, mono }, i, arr) => (
              <div key={label} className="flex items-center justify-between px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
                <span style={{ fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-all", maxWidth: "200px", textAlign: "right" }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        {device.open_ports.length > 0 && (
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>OPEN PORTS</p>
            <div className="flex flex-wrap gap-1.5">
              {device.open_ports.slice(0, 12).map((port) => (
                <span key={`${port.port}-${port.protocol}`} className="rounded-md px-2 py-0.5" style={{ backgroundColor: "var(--secondary)", border: "1px solid var(--border)", fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)" }}>
                  {port.port}/{port.protocol}{port.service ? ` ${port.service}` : ""}
                </span>
              ))}
              {device.open_ports.length > 12 && (
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", color: "var(--muted-foreground)" }}>+{device.open_ports.length - 12} more</span>
              )}
            </div>
          </div>
        )}

        {/* Monitoring toggle */}
        <div className="flex items-center justify-between">
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>Guardian Monitoring</span>
          <Switch.Root
            checked={device.monitoring_enabled}
            disabled={togglingMonitor}
            onCheckedChange={handleToggleMonitoring}
            style={{ width: "40px", height: "22px", borderRadius: "11px", backgroundColor: device.monitoring_enabled ? "var(--primary)" : "var(--muted)", border: "none", cursor: togglingMonitor ? "wait" : "pointer", position: "relative", flexShrink: 0 }}
          >
            <Switch.Thumb style={{ display: "block", width: "16px", height: "16px", borderRadius: "50%", backgroundColor: "white", transform: device.monitoring_enabled ? "translateX(20px)" : "translateX(3px)", transition: "transform 0.2s" }} />
          </Switch.Root>
        </div>

        {/* Scan */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>SECURITY SCAN</p>
          <button
            onClick={handleStartScan}
            disabled={!hasIp || scanActive}
            title={!hasIp ? "Device has no IP target" : undefined}
            className="w-full flex items-center justify-center gap-2 rounded-lg"
            style={{ height: "44px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", color: "var(--secondary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: !hasIp || scanActive ? "default" : "pointer", opacity: !hasIp ? 0.5 : 1 }}
          >
            {scanActive ? <Loader2 size={16} className="animate-spin" /> : <ScanSearch size={16} />}
            {scanActive ? `Scanning… step ${scanRun?.step ?? 1}/5${scanRun?.step_label ? ` · ${scanRun.step_label}` : ""}` : "Run Security Scan"}
          </button>
          {scanRun && scanRun.state !== "running" && (
            <div className="mt-3 rounded-lg border border-border p-3 flex flex-col gap-2" style={{ backgroundColor: "var(--background)" }}>
              <div className="flex items-center gap-2">
                {scanRun.state === "complete" ? <ShieldCheck size={14} style={{ color: "var(--chart-2)" }} /> : <ShieldAlert size={14} style={{ color: "var(--destructive)" }} />}
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", textTransform: "capitalize" }}>{scanRun.state}</span>
              </div>
              {scanRun.findings.slice(0, 5).map((finding, i) => (
                <p key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>• {finding}</p>
              ))}
              {scanRun.recommendations.slice(0, 3).map((rec, i) => (
                <p key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-5)", lineHeight: 1.5 }}>→ {rec}</p>
              ))}
            </div>
          )}
        </div>

        {/* Actions */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>ACTIONS</p>
          <div className="flex flex-col gap-2">
            <button
              onClick={handleToggleBlock}
              disabled={blocking || !hasIp}
              title={!hasIp ? "Device has no IP target" : undefined}
              className="w-full flex items-center justify-center gap-2 rounded-lg"
              style={{
                height: "44px",
                backgroundColor: device.blocked ? "color-mix(in srgb, var(--chart-2) 12%, transparent)" : "color-mix(in srgb, var(--chart-5) 12%, transparent)",
                border: `1px solid color-mix(in srgb, ${device.blocked ? "var(--chart-2)" : "var(--chart-5)"} 25%, transparent)`,
                color: device.blocked ? "var(--chart-2)" : "var(--chart-5)",
                fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)",
                cursor: blocking || !hasIp ? "default" : "pointer", opacity: !hasIp ? 0.5 : 1,
              }}
            >
              {blocking ? <Loader2 size={16} className="animate-spin" /> : device.blocked ? <ShieldCheck size={16} /> : <Ban size={16} />}
              {device.blocked ? "Unblock Device" : "Block Device"}
            </button>
            {!device.rejected && (
              <button
                onClick={() => onReject(device)}
                className="w-full flex items-center justify-center gap-2 rounded-lg"
                style={{ height: "44px", backgroundColor: "color-mix(in srgb, var(--chart-5) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--chart-5) 25%, transparent)", color: "var(--chart-5)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer" }}
              >
                <UserX size={16} /> Reject & Block
              </button>
            )}
            <button
              onClick={() => onDelete(device)}
              className="w-full flex items-center justify-center gap-2 rounded-lg"
              style={{ height: "44px", backgroundColor: "color-mix(in srgb, var(--destructive) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)", color: "var(--destructive)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer" }}
            >
              <Trash2 size={16} /> Remove from Fleet
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Add manual device dialog ─────────────────────────────────────────────────
function AddManualDeviceDialog({ open, onOpenChange, onAdded }: { open: boolean; onOpenChange: (open: boolean) => void; onAdded: () => void }) {
  const [displayName, setDisplayName] = useState("");
  const [ip, setIp] = useState("");
  const [mac, setMac] = useState("");
  const [manufacturer, setManufacturer] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      setDisplayName(""); setIp(""); setMac(""); setManufacturer("");
    }
  }, [open]);

  const canSubmit = ip.trim().length > 0 || mac.trim().length > 0;

  const handleSubmit = async () => {
    if (!canSubmit || saving) return;
    setSaving(true);
    try {
      await managedDeviceService.addManual({
        display_name: displayName.trim() || undefined,
        ip: ip.trim() || undefined,
        mac: mac.trim() || undefined,
        manufacturer: manufacturer.trim() || undefined,
      });
      toast.success("Device added to fleet");
      onOpenChange(false);
      onAdded();
    } catch (error: any) {
      toast.error(error.message || "Failed to add device");
    } finally {
      setSaving(false);
    }
  };

  const fieldStyle = { height: "40px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", padding: "0 12px", width: "100%", outline: "none" } as const;

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
        <Dialog.Content className="fixed z-[70] rounded-xl border border-border p-6 flex flex-col gap-4" style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "400px" }}>
          <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Add Device to Fleet</Dialog.Title>
          <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            Requires an IP or MAC address.
          </Dialog.Description>
          <div className="flex flex-col gap-3">
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Display name" style={fieldStyle} />
            <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP address" style={fieldStyle} />
            <input value={mac} onChange={(e) => setMac(e.target.value)} placeholder="MAC address" style={fieldStyle} />
            <input value={manufacturer} onChange={(e) => setManufacturer(e.target.value)} placeholder="Manufacturer" style={fieldStyle} />
          </div>
          <div className="flex gap-3">
            <Dialog.Close asChild>
              <button style={{ flex: 1, height: "44px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>Cancel</button>
            </Dialog.Close>
            <button
              onClick={handleSubmit}
              disabled={!canSubmit || saving}
              style={{ flex: 1, height: "44px", backgroundColor: "var(--primary)", border: "none", borderRadius: "var(--radius)", cursor: canSubmit && !saving ? "pointer" : "default", opacity: canSubmit ? 1 : 0.5, fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary-foreground)", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px" }}
            >
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Add
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Reject device dialog ─────────────────────────────────────────────────────
function RejectDeviceDialog({ device, onOpenChange, onRejected }: { device: ManagedDevice | null; onOpenChange: (open: boolean) => void; onRejected: () => void }) {
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => { setReason(""); }, [device?.device_id]);

  const handleReject = async () => {
    if (!device || saving) return;
    setSaving(true);
    try {
      await managedDeviceService.reject(device.device_id, reason.trim() ? { reason: reason.trim() } : undefined);
      toast.success("Device rejected and blocked");
      onOpenChange(false);
      onRejected();
    } catch (error: any) {
      toast.error(error.message || "Failed to reject device");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog.Root open={!!device} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
        <Dialog.Content className="fixed z-[70] rounded-xl border border-border p-6 flex flex-col gap-4" style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "380px" }}>
          <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Reject Device?</Dialog.Title>
          <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
            This blocks {device ? fleetDeviceLabel(device) : "this device"} on the firewall and removes it from the whitelist.
          </Dialog.Description>
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (optional)" rows={3} className="outline-none" style={{ backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", padding: "8px 12px", resize: "none" }} />
          <div className="flex gap-3">
            <Dialog.Close asChild>
              <button style={{ flex: 1, height: "44px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>Cancel</button>
            </Dialog.Close>
            <button onClick={handleReject} disabled={saving} style={{ flex: 1, height: "44px", backgroundColor: "var(--destructive)", border: "none", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "white", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px" }}>
              {saving ? <Loader2 size={14} className="animate-spin" /> : <UserX size={14} />} Reject
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Main component ───────────────────────────────────────────────────────────
export function DV01DevicesList() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("paired");
  const [search, setSearch] = useState("");

  const [devices, setDevices] = useState<PairedDevice[]>([]);
  const [loading, setLoading] = useState(true);

  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [unpairId, setUnpairId] = useState<string | null>(null);
  const [unpairLoading, setUnpairLoading] = useState(false);

  // Fleet security state
  const [fleetDevices, setFleetDevices] = useState<ManagedDevice[]>([]);
  const [fleetSummary, setFleetSummary] = useState<ManagedDevicesSummary | null>(null);
  const [fleetLoading, setFleetLoading] = useState(true);
  const [selectedFleetId, setSelectedFleetId] = useState<string | null>(null);
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [rejectTarget, setRejectTarget] = useState<ManagedDevice | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ManagedDevice | null>(null);
  const [deleting, setDeleting] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await deviceService.listDevices();
      setDevices(Array.isArray(data) ? data : []);
    } catch (e: any) {
      console.warn("Failed to load devices", e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadFleet = useCallback(async () => {
    setFleetLoading(true);
    try {
      const [list, summary] = await Promise.all([
        managedDeviceService.list(),
        managedDeviceService.summary().catch(() => null),
      ]);
      setFleetDevices(Array.isArray(list) ? list : []);
      setFleetSummary(summary);
    } catch (e: any) {
      toast.error(e.message || "Failed to load fleet devices");
    } finally {
      setFleetLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (tab === "fleet" && fleetDevices.length === 0 && fleetLoading) {
      loadFleet();
    }
  }, [tab, fleetDevices.length, fleetLoading, loadFleet]);

  // Tab change resets selection
  useEffect(() => {
    setSelectedDeviceId(null);
    setSelectedFleetId(null);
  }, [tab]);

  const handleUnpair = async () => {
    if (!unpairId) return;
    setUnpairLoading(true);
    try {
      await deviceService.unpairDevice(unpairId);
      toast.success("Device unpaired");
      setUnpairId(null);
      if (selectedDeviceId === unpairId) setSelectedDeviceId(null);
      loadData();
    } catch (e: any) {
      toast.error(e.message || "Failed to unpair device");
    } finally {
      setUnpairLoading(false);
    }
  };

  const handleDeleteFleet = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await managedDeviceService.remove(deleteTarget.device_id);
      toast.success("Device removed from fleet");
      setDeleteTarget(null);
      if (selectedFleetId === deleteTarget.device_id) setSelectedFleetId(null);
      loadFleet();
    } catch (e: any) {
      toast.error(e.message || "Failed to remove device");
    } finally {
      setDeleting(false);
    }
  };

  const pairedDevices = devices.filter(d => d.status !== 'unpaired');
  const unpairedDevices = devices.filter(d => d.status === 'unpaired');

  const filteredPaired = pairedDevices.filter(d => !search || d.serial.toLowerCase().includes(search.toLowerCase()) || d.nodeId.toLowerCase().includes(search.toLowerCase()));
  const filteredUnpaired = unpairedDevices.filter(d => !search || d.serial.toLowerCase().includes(search.toLowerCase()) || d.nodeId.toLowerCase().includes(search.toLowerCase()));
  const filteredFleet = fleetDevices.filter((d) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return [d.display_name, d.hostname, d.ip, d.mac, d.device_id].some((v) => v?.toLowerCase().includes(q));
  });

  const selectedFleetDevice = fleetDevices.find((d) => d.device_id === selectedFleetId) ?? null;

  const Header = (
    <div className="flex flex-col justify-center flex-shrink-0 px-5 h-20 border-b border-border bg-card relative overflow-hidden">
      <div className="absolute inset-0 opacity-10" style={{ background: "linear-gradient(90deg, var(--primary) 0%, transparent 100%)" }} />
      <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.2, position: "relative" }}>
        Devices
      </h2>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.3, position: "relative" }}>
        Manage your connected Guardians
      </p>
    </div>
  );

  const StatCards = tab === "fleet" ? (
    <div className="flex gap-4 px-5 py-5 border-b border-border bg-background flex-wrap">
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)", minWidth: "130px" }}>
        <div className="flex items-center gap-2 mb-2">
          <Cpu size={16} style={{ color: "var(--primary)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Total</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{fleetSummary?.total ?? fleetDevices.length}</p>
      </div>
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)", minWidth: "130px" }}>
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert size={16} style={{ color: "var(--destructive)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>At Risk</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{(fleetSummary?.critical_devices ?? 0) + (fleetSummary?.high_risk_devices ?? 0)}</p>
      </div>
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)", minWidth: "130px" }}>
        <div className="flex items-center gap-2 mb-2">
          <Ban size={16} style={{ color: "var(--chart-5)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Blocked</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{fleetSummary?.blocked ?? 0}</p>
      </div>
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)", minWidth: "130px" }}>
        <div className="flex items-center gap-2 mb-2">
          <ShieldCheck size={16} style={{ color: "var(--chart-2)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Monitored</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{fleetSummary?.monitoring_enabled ?? 0}</p>
      </div>
    </div>
  ) : (
    <div className="flex gap-4 px-5 py-5 border-b border-border bg-background">
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Cpu size={16} style={{ color: "var(--primary)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Total Devices</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{devices.length}</p>
      </div>
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Shield size={16} style={{ color: "var(--chart-2)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Paired</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{pairedDevices.length}</p>
      </div>
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-2">
          <LayoutList size={16} style={{ color: "var(--muted-foreground)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Unpaired</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{unpairedDevices.length}</p>
      </div>
    </div>
  );

  const Controls = (
    <div className="flex flex-col gap-4 px-5 py-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-1 p-1 rounded-lg" style={{ backgroundColor: "var(--secondary)", border: "1px solid var(--border)" }}>
          <button
            onClick={() => setTab("paired")}
            style={{ padding: "6px 16px", borderRadius: "var(--radius)", backgroundColor: tab === "paired" ? "var(--background)" : "transparent", color: tab === "paired" ? "var(--foreground)" : "var(--muted-foreground)", boxShadow: tab === "paired" ? "0 1px 3px rgba(0,0,0,0.1)" : "none", border: "none", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer", transition: "all 0.2s" }}
          >
            Paired
          </button>
          <button
            onClick={() => setTab("unpaired")}
            style={{ padding: "6px 16px", borderRadius: "var(--radius)", backgroundColor: tab === "unpaired" ? "var(--background)" : "transparent", color: tab === "unpaired" ? "var(--foreground)" : "var(--muted-foreground)", boxShadow: tab === "unpaired" ? "0 1px 3px rgba(0,0,0,0.1)" : "none", border: "none", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer", transition: "all 0.2s" }}
          >
            Unpaired
          </button>
          <button
            onClick={() => setTab("fleet")}
            style={{ padding: "6px 16px", borderRadius: "var(--radius)", backgroundColor: tab === "fleet" ? "var(--background)" : "transparent", color: tab === "fleet" ? "var(--foreground)" : "var(--muted-foreground)", boxShadow: tab === "fleet" ? "0 1px 3px rgba(0,0,0,0.1)" : "none", border: "none", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer", transition: "all 0.2s", display: "flex", alignItems: "center", gap: "6px" }}
          >
            <ShieldAlert size={14} /> Fleet Security
          </button>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative" style={{ width: "240px" }}>
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "var(--muted-foreground)" }} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={tab === "fleet" ? "Search IP, MAC, hostname..." : "Search serial or node ID..."}
              className="w-full pl-9 pr-3 outline-none"
              style={{ height: "36px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", transition: "border-color 0.2s" }}
            />
          </div>
          {tab === "fleet" ? (
            <>
              <button onClick={loadFleet} aria-label="Refresh fleet" className="flex items-center justify-center rounded-md" style={{ width: "36px", height: "36px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", cursor: "pointer" }}>
                <RefreshCw size={15} style={{ color: "var(--secondary-foreground)" }} className={fleetLoading ? "animate-spin" : ""} />
              </button>
              <button onClick={() => setAddDialogOpen(true)} className="flex items-center justify-center gap-2 px-4 shadow-sm" style={{ height: "36px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", transition: "opacity 0.2s" }}>
                <Plus size={16} /> Add Device
              </button>
            </>
          ) : (
            <button onClick={() => navigate("/settings/device-pairing")} className="flex items-center justify-center gap-2 px-4 shadow-sm" style={{ height: "36px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", transition: "opacity 0.2s" }}>
              <Plus size={16} /> Pair New Guardian
            </button>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex flex-col h-[100dvh] md:flex-row overflow-hidden bg-background">
      <div className="flex flex-col flex-1 border-r border-border min-w-0">
        {Header}
        {StatCards}
        {Controls}

        {/* List area */}
        <div className="flex-1 overflow-y-auto px-5 pb-6">
          {tab === "fleet" ? (
            fleetLoading ? (
              <div className="flex flex-col items-center justify-center py-12">
                <Loader2 size={24} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
                <span className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Loading fleet...</span>
              </div>
            ) : filteredFleet.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center border border-dashed border-border rounded-xl" style={{ backgroundColor: "var(--card)" }}>
                <div className="rounded-full flex items-center justify-center mb-4" style={{ width: "64px", height: "64px", backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)" }}>
                  <ShieldAlert size={32} style={{ color: "var(--primary)" }} />
                </div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>No managed devices found</p>
                <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Run a discovery scan or add a device manually</p>
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {filteredFleet.map((device) => (
                  <button
                    key={device.device_id}
                    onClick={() => setSelectedFleetId(device.device_id)}
                    className="w-full text-left flex items-center justify-between p-4 rounded-xl border transition-all shadow-sm"
                    style={{
                      backgroundColor: selectedFleetId === device.device_id ? "color-mix(in srgb, var(--primary) 6%, var(--card))" : "var(--card)",
                      borderColor: selectedFleetId === device.device_id ? "var(--primary)" : "var(--border)",
                      cursor: "pointer"
                    }}
                  >
                    <div className="flex items-center gap-4 min-w-0">
                      <div className="rounded-lg flex items-center justify-center flex-shrink-0 shadow-sm" style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)" }}>
                        <Cpu size={20} style={{ color: "var(--primary)" }} />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <p className="truncate" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", maxWidth: "220px" }}>{fleetDeviceLabel(device)}</p>
                          <StatusBadge status={device.risk_level.toUpperCase()} variant={riskVariant(device.risk_level)} />
                          {device.blocked && <StatusBadge status="BLOCKED" variant="danger" />}
                        </div>
                        <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{device.ip || device.mac || device.device_id}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 flex-shrink-0">
                      <div className="text-right hidden sm:block">
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>SEC</p>
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: scoreColor(device.security_score) }}>{device.security_score ?? "—"}</p>
                      </div>
                      <ChevronRight size={18} style={{ color: "var(--muted-foreground)" }} />
                    </div>
                  </button>
                ))}
              </div>
            )
          ) : loading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <Loader2 size={24} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
              <span className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Loading...</span>
            </div>
          ) : tab === "paired" ? (
            filteredPaired.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center border border-dashed border-border rounded-xl" style={{ backgroundColor: "var(--card)" }}>
                <div className="rounded-full flex items-center justify-center mb-4" style={{ width: "64px", height: "64px", backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)" }}>
                  <Shield size={32} style={{ color: "var(--primary)" }} />
                </div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>No paired Guardians found</p>
                <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Click 'Pair New Guardian' to get started</p>
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {filteredPaired.map((device) => (
                  <button
                    key={device.deviceId}
                    onClick={() => setSelectedDeviceId(device.deviceId)}
                    className="w-full text-left flex items-center justify-between p-4 rounded-xl border transition-all shadow-sm"
                    style={{
                      backgroundColor: selectedDeviceId === device.deviceId ? "color-mix(in srgb, var(--primary) 6%, var(--card))" : "var(--card)",
                      borderColor: selectedDeviceId === device.deviceId ? "var(--primary)" : "var(--border)",
                      cursor: "pointer"
                    }}
                  >
                    <div className="flex items-center gap-4">
                      <div className="rounded-lg flex items-center justify-center flex-shrink-0 shadow-sm" style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)" }}>
                        <Shield size={20} style={{ color: "var(--primary)" }} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <StatusDot status={device.status} />
                          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{device.serial}</p>
                        </div>
                        <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{device.nodeId}</p>
                      </div>
                    </div>
                    <ChevronRight size={18} style={{ color: "var(--muted-foreground)" }} />
                  </button>
                ))}
              </div>
            )
          ) : (
            filteredUnpaired.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center border border-dashed border-border rounded-xl" style={{ backgroundColor: "var(--card)" }}>
                <div className="rounded-full flex items-center justify-center mb-4" style={{ width: "64px", height: "64px", backgroundColor: "var(--muted)" }}>
                  <LayoutList size={32} style={{ color: "var(--muted-foreground)" }} />
                </div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>No unpaired Guardians found</p>
                <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Unpaired devices will appear here</p>
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {filteredUnpaired.map((device) => (
                  <button
                    key={device.deviceId}
                    onClick={() => setSelectedDeviceId(device.deviceId)}
                    className="w-full text-left flex items-center justify-between p-4 rounded-xl border transition-all shadow-sm"
                    style={{
                      backgroundColor: selectedDeviceId === device.deviceId ? "color-mix(in srgb, var(--primary) 6%, var(--card))" : "var(--card)",
                      borderColor: selectedDeviceId === device.deviceId ? "var(--primary)" : "var(--border)",
                      cursor: "pointer"
                    }}
                  >
                    <div className="flex items-center gap-4">
                      <div className="rounded-lg flex items-center justify-center flex-shrink-0 shadow-sm" style={{ width: "40px", height: "40px", backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
                        <LayoutList size={20} style={{ color: "var(--muted-foreground)" }} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{device.serial}</p>
                        </div>
                        <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{device.nodeId} · Unpaired</p>
                      </div>
                    </div>
                    <ChevronRight size={18} style={{ color: "var(--muted-foreground)" }} />
                  </button>
                ))}
              </div>
            )
          )}
        </div>
      </div>

      {/* Side panel */}
      <div className="hidden md:flex flex-col" style={{ width: "380px", backgroundColor: "var(--card)", borderLeft: "1px solid var(--border)", boxShadow: "-4px 0 15px rgba(0,0,0,0.02)" }}>
        {tab === "fleet" ? (
          selectedFleetDevice ? (
            <FleetDetailPanel
              device={selectedFleetDevice}
              onClose={() => setSelectedFleetId(null)}
              onReject={setRejectTarget}
              onDelete={setDeleteTarget}
              onChanged={loadFleet}
            />
          ) : (
            <div className="flex flex-col items-center justify-center h-full p-8 text-center">
              <ShieldAlert size={48} style={{ color: "var(--muted-foreground)", opacity: 0.2, marginBottom: "16px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>Select a device</p>
              <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>Click a device to view scores, run a scan, or manage blocking</p>
            </div>
          )
        ) : selectedDeviceId ? (
          <DeviceDetailPanel deviceId={selectedDeviceId} onClose={() => setSelectedDeviceId(null)} onUnpair={setUnpairId} />
        ) : (
          <div className="flex flex-col items-center justify-center h-full p-8 text-center">
            <Cpu size={48} style={{ color: "var(--muted-foreground)", opacity: 0.2, marginBottom: "16px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>Select a Guardian</p>
            <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>Click a device from the list to view its connection details and status</p>
          </div>
        )}
      </div>

      {/* Mobile side panel overlay */}
      {tab === "fleet" && selectedFleetId && selectedFleetDevice && (
        <div className="md:hidden fixed inset-0 z-50 flex justify-end" style={{ backgroundColor: "rgba(0,0,0,0.5)" }} onClick={() => setSelectedFleetId(null)}>
          <div className="w-[85vw] max-w-[360px] h-full shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <FleetDetailPanel device={selectedFleetDevice} onClose={() => setSelectedFleetId(null)} onReject={setRejectTarget} onDelete={setDeleteTarget} onChanged={loadFleet} />
          </div>
        </div>
      )}
      {tab !== "fleet" && selectedDeviceId && (
        <div className="md:hidden fixed inset-0 z-50 flex justify-end" style={{ backgroundColor: "rgba(0,0,0,0.5)" }} onClick={() => setSelectedDeviceId(null)}>
          <div className="w-[85vw] max-w-[360px] h-full shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <DeviceDetailPanel deviceId={selectedDeviceId} onClose={() => setSelectedDeviceId(null)} onUnpair={setUnpairId} />
          </div>
        </div>
      )}

      {/* Unpair Confirm Dialog */}
      <Dialog.Root open={!!unpairId} onOpenChange={(open) => !open && setUnpairId(null)}>
        <Dialog.Portal>
          <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.6)", zIndex: 99 }} />
          <Dialog.Content
            style={{
              position: "fixed", top: "50%", left: "50%", transform: "translate(-50%,-50%)", zIndex: 100,
              backgroundColor: "var(--card)", border: "1px solid var(--border)", borderRadius: "var(--radius-card)",
              padding: "24px", width: "320px", maxWidth: "90vw"
            }}
          >
            <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "8px" }}>
              Unpair Guardian
            </Dialog.Title>
            <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", marginBottom: "20px", lineHeight: 1.6 }}>
              Are you sure you want to unpair this device? This will remove its binding to your account.
            </Dialog.Description>
            <div style={{ display: "flex", gap: "8px" }}>
              <Dialog.Close asChild>
                <button style={{ flex: 1, height: "40px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>
                  Cancel
                </button>
              </Dialog.Close>
              <button
                onClick={handleUnpair}
                disabled={unpairLoading}
                style={{ flex: 1, height: "40px", backgroundColor: "var(--destructive)", border: "none", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "white", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px" }}
              >
                {unpairLoading ? <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} /> : <Trash2 size={14} />}
                Unpair
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Fleet: delete confirm */}
      <Dialog.Root open={!!deleteTarget} onOpenChange={(open) => !open && !deleting && setDeleteTarget(null)}>
        <Dialog.Portal>
          <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.6)", zIndex: 99 }} />
          <Dialog.Content
            style={{
              position: "fixed", top: "50%", left: "50%", transform: "translate(-50%,-50%)", zIndex: 100,
              backgroundColor: "var(--card)", border: "1px solid var(--border)", borderRadius: "var(--radius-card)",
              padding: "24px", width: "320px", maxWidth: "90vw"
            }}
          >
            <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "8px" }}>
              Remove Device
            </Dialog.Title>
            <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", marginBottom: "20px", lineHeight: 1.6 }}>
              Removes {deleteTarget ? fleetDeviceLabel(deleteTarget) : "this device"} from the fleet registry. This does not unblock it if already blocked.
            </Dialog.Description>
            <div style={{ display: "flex", gap: "8px" }}>
              <Dialog.Close asChild>
                <button style={{ flex: 1, height: "40px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>
                  Cancel
                </button>
              </Dialog.Close>
              <button
                onClick={handleDeleteFleet}
                disabled={deleting}
                style={{ flex: 1, height: "40px", backgroundColor: "var(--destructive)", border: "none", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "white", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px" }}
              >
                {deleting ? <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} /> : <Trash2 size={14} />}
                Remove
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <AddManualDeviceDialog open={addDialogOpen} onOpenChange={setAddDialogOpen} onAdded={loadFleet} />
      <RejectDeviceDialog device={rejectTarget} onOpenChange={(open) => !open && setRejectTarget(null)} onRejected={loadFleet} />

      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  );
}
