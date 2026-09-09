import { useState, useEffect, useCallback, useRef, type ReactNode } from "react";
import { useNavigate } from "react-router";
import {
  Plus, Search, Cpu, Shield, ShieldAlert, Trash2, Loader2, Info, LayoutList, ChevronRight,
  Ban, ShieldCheck, ScanSearch, Pencil, Check, X as XIcon2, UserX, RefreshCw, Copy, Home,
} from "lucide-react";
import { toast } from "sonner";
import { deviceService, type PairedDevice, type DeviceDetail, type PairedGuardianStatus, type PairingCodeResponse } from "../../services/deviceService";
import {
  managedDeviceService,
  type ManagedDevice,
  type ManagedDevicesSummary,
  type DeviceScanRun,
} from "../../services/managedDeviceService";
import { StatusBadge } from "../../components/SeverityBadge";
import { guardianDisplayText } from "../../utils/displayText";
import * as Dialog from "@radix-ui/react-dialog";
import * as Switch from "@radix-ui/react-switch";

type Tab = "paired" | "unpaired" | "fleet";

function InfoTooltip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <span className="relative inline-flex items-center group" onClick={(e) => e.stopPropagation()}>
      <span
        role="img"
        aria-label={label}
        tabIndex={0}
        className="inline-flex items-center justify-center rounded-full border border-border bg-background text-muted-foreground transition-colors hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
        style={{ width: "18px", height: "18px" }}
      >
        <Info size={12} />
      </span>
      <span
        role="tooltip"
        className="pointer-events-none absolute left-0 top-7 z-50 hidden w-72 rounded-md border border-border bg-popover p-3 text-left shadow-xl group-hover:block group-focus-within:block"
      >
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--popover-foreground)", lineHeight: 1.5 }}>
          {children}
        </span>
      </span>
    </span>
  );
}

function safeTrim(value: unknown): string {
  return String(value ?? "").trim();
}

/** Paired Guardian records from GET /devices/paired — not scan or fleet inventory. */
function isValidPairedDevice(device: PairedDevice | null | undefined): device is PairedDevice {
  if (!device || typeof device !== "object") return false;
  return safeTrim(device.deviceId).length > 0;
}

/** Managed/scanned devices for Fleet Security only — never shown in Paired tab. */
function isValidFleetDevice(device: ManagedDevice | null | undefined): device is ManagedDevice {
  if (!device || typeof device !== "object") return false;
  return safeTrim(device.device_id).length > 0;
}

// ── Status dot for paired guardian ──────────────────────────────────────────
function StatusDot({ status }: { status: string }) {
  const isPending = status === "pending_bootstrap";
  const isUnpaired = status === "unpaired";
  return (
    <span
      style={{
        display: "inline-block",
        width: "8px",
        height: "8px",
        borderRadius: "50%",
        flexShrink: 0,
        backgroundColor: isUnpaired ? "var(--muted-foreground)" : isPending ? "var(--chart-5)" : "var(--chart-2)",
        animation: isPending ? "pulse 2s ease-in-out infinite" : undefined,
      }}
    />
  );
}

function GuardianStatusSection({ title, rows }: { title: string; rows: Array<{ label: string; value: string | number | undefined; mono?: boolean }> }) {
  return (
    <div>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>{title}</p>
      <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--background)" }}>
        {rows.map(({ label, value, mono }, index) => (
          <div key={label} className="flex items-center justify-between gap-3 px-4 py-3" style={{ borderBottom: index < rows.length - 1 ? "1px solid var(--border)" : undefined }}>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
            <span style={{ fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-all", maxWidth: "58%", textAlign: "right" }}>{value === undefined || value === "" ? "Unavailable" : guardianDisplayText(value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── DeviceDetailPanel ────────────────────────────────────────────────────────
function DeviceDetailPanel({
  deviceId,
  fallbackDevice,
  onClose,
  onUnpair,
  onRepair,
}: {
  deviceId: string;
  fallbackDevice?: PairedDevice | null;
  onClose: () => void;
  onUnpair: (id: string) => void;
  onRepair?: (device: PairedDevice) => void;
}) {
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [guardianStatus, setGuardianStatus] = useState<PairedGuardianStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setDetail(null);
    setGuardianStatus(null);
    setLoading(true);
    deviceService.getDevice(deviceId)
      .then((data) => {
        if (active) setDetail(data);
      })
      .catch((e: any) => {
        if (active && !fallbackDevice) toast.error(guardianDisplayText(e.message) || "Failed to load device details");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    deviceService.getGuardianStatus(deviceId)
      .then((data) => {
        if (active) setGuardianStatus(data);
      })
      .catch(() => {
        // The base detail stays usable when optional remote status is unavailable.
      });
    return () => { active = false; };
  }, [deviceId, fallbackDevice?.deviceId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 size={32} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
      </div>
    );
  }

  const displayDevice = detail ?? (fallbackDevice ? {
    deviceId: fallbackDevice.deviceId,
    serial: fallbackDevice.serial,
    did: fallbackDevice.did,
    nodeId: fallbackDevice.nodeId,
    status: fallbackDevice.status,
    bootstrapStatus: "N/A",
  } : null);
  const isUnpaired = safeTrim(displayDevice?.status).toLowerCase() === "unpaired";

  if (!displayDevice) {
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
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{displayDevice.serial}</p>
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
            <StatusDot status={displayDevice.status} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", textTransform: "capitalize" }}>{isUnpaired ? "Unpaired" : displayDevice.status}</span>
          </div>
        </div>

        {/* Info list */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>DEVICE INFO</p>
          <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--background)" }}>
            {[
              { label: "Node ID", value: displayDevice.nodeId || "N/A", mono: true },
              { label: "DID", value: displayDevice.did || "N/A", mono: true },
              { label: "Overlay IP", value: detail?.overlayIp || "N/A", mono: true },
              { label: "Bootstrap Status", value: detail?.bootstrapStatus || "N/A" },
            ].map(({ label, value, mono }, i, arr) => (
              <div key={label} className="flex items-center justify-between px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
                <span style={{ fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-all", maxWidth: "200px", textAlign: "right" }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        {guardianStatus ? (
          <>
            <GuardianStatusSection title="IDENTITY" rows={[
              { label: "Node Name", value: guardianStatus.identity.nodeName },
              { label: "DID", value: guardianStatus.identity.did, mono: true },
              { label: "Device Fingerprint", value: guardianStatus.identity.deviceFingerprint, mono: true },
              { label: "DID Status", value: guardianStatus.identity.didStatus },
              { label: "DKP Version", value: guardianStatus.identity.dkpVersion },
            ]} />
            <GuardianStatusSection title="RUNTIME" rows={[
              { label: "Connectivity", value: guardianStatus.runtime.status },
              { label: "Daemon", value: guardianStatus.runtime.daemonStatus },
              { label: "Last Seen", value: guardianStatus.runtime.lastSeen },
              { label: "Uptime (seconds)", value: guardianStatus.runtime.uptimeSeconds },
            ]} />
            <GuardianStatusSection title="NETWORK" rows={[
              { label: "Physical IP", value: guardianStatus.network.physicalIp, mono: true },
              { label: "Interface", value: guardianStatus.network.interfaceName },
              { label: "Transport", value: guardianStatus.network.transport },
            ]} />
            <GuardianStatusSection title="GUARDIAN MESH" rows={[
              { label: "Status", value: guardianStatus.nebula.status },
              { label: "Overlay IP", value: guardianStatus.nebula.overlayIp, mono: true },
              { label: "Role", value: guardianStatus.nebula.role },
              { label: "Trusted Peers", value: guardianStatus.nebula.trustedPeerCount },
            ]} />
            <GuardianStatusSection title="HARDWARE SECURITY" rows={[
              { label: "SE050", value: guardianStatus.hardware.se050Status },
              { label: "DKP Version", value: guardianStatus.hardware.dkpVersion },
            ]} />
            <GuardianStatusSection title="ATTESTATION / INTEGRITY" rows={[
              { label: "Attestation", value: guardianStatus.security.attestationStatus },
              { label: "Attestation Endpoint", value: guardianStatus.security.attestationEndpoint, mono: true },
              { label: "PCR", value: guardianStatus.security.pcrStatus },
              { label: "Integrity", value: guardianStatus.security.integrityStatus },
              { label: "Secure Boot / HAB", value: guardianStatus.security.secureBootStatus },
            ]} />
            <GuardianStatusSection title="POLICY / TRUST" rows={[
              { label: "Policy", value: guardianStatus.security.policyStatus },
              { label: "Policy Digest", value: guardianStatus.security.policyDigest, mono: true },
              { label: "Trust", value: guardianStatus.security.trustState },
            ]} />
            <GuardianStatusSection title="PAIRING" rows={[
              { label: "Paired At", value: guardianStatus.pairing.pairedAt },
              { label: "Method", value: guardianStatus.pairing.method },
              { label: "State", value: guardianStatus.pairing.status },
              { label: "Reactivated At", value: guardianStatus.pairing.reactivatedAt },
            ]} />
          </>
        ) : (
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Runtime status is currently unavailable for this Guardian.</p>
        )}

        {/* Actions */}
        {isUnpaired ? (
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>ACTIONS</p>
            <button
              onClick={() => fallbackDevice && onRepair?.(fallbackDevice)}
              disabled={!fallbackDevice || !onRepair}
              className="w-full flex items-center justify-center gap-2 rounded-lg"
              style={{ height: "44px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 35%, transparent)", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: fallbackDevice && onRepair ? "pointer" : "default", opacity: fallbackDevice && onRepair ? 1 : 0.5 }}
            >
              <RefreshCw size={16} /> Re-Pair Guardian
            </button>
          </div>
        ) : (
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>ACTIONS</p>
            <button
              onClick={() => { onClose(); onUnpair(displayDevice.deviceId); }}
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
  return guardianDisplayText(safeTrim(device.display_name) || safeTrim(device.hostname) || safeTrim(device.ip) || safeTrim(device.mac) || safeTrim(device.device_id));
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
  const [nameDraft, setNameDraft] = useState(guardianDisplayText(device.display_name ?? ""));
  const [savingName, setSavingName] = useState(false);
  const [togglingMonitor, setTogglingMonitor] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [approving, setApproving] = useState(false);
  const [scanRun, setScanRun] = useState<DeviceScanRun | null>(null);
  const [scanning, setScanning] = useState(false);
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    setEditingName(false);
    setNameDraft(guardianDisplayText(device.display_name ?? ""));
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
      toast.error(guardianDisplayText(error.message) || "Failed to start scan");
    } finally {
      setScanning(false);
    }
  };

  const handleSaveName = async () => {
    setSavingName(true);
    try {
      await managedDeviceService.edit(device.device_id, { display_name: safeTrim(nameDraft) || null });
      toast.success("Device name updated");
      setEditingName(false);
      onChanged();
    } catch (error: any) {
      toast.error(guardianDisplayText(error.message) || "Failed to update device name");
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
      toast.error(guardianDisplayText(error.message) || "Failed to update monitoring");
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
      toast.error(guardianDisplayText(error.message) || "Block/unblock failed");
    } finally {
      setBlocking(false);
    }
  };

  const handleApprove = async () => {
    setApproving(true);
    try {
      await managedDeviceService.approve(device.device_id);
      toast.success("Device approved and unblocked");
      onChanged();
    } catch (error: any) {
      toast.error(guardianDisplayText(error.message) || "Failed to approve device");
    } finally {
      setApproving(false);
    }
  };

  const hasIp = !!device.ip;
  const scanActive = scanning || scanRun?.state === "running";
  const riskLevel = safeTrim(device.risk_level) || "unknown";
  const securityReasons = Array.isArray(device.security_reasons) ? device.security_reasons : [];
  const privacyReasons = Array.isArray(device.privacy_reasons) ? device.privacy_reasons : [];
  const openPorts = Array.isArray(device.open_ports) ? device.open_ports : [];
  const scanFindings = Array.isArray(scanRun?.findings) ? scanRun.findings : [];
  const scanRecommendations = Array.isArray(scanRun?.recommendations) ? scanRun.recommendations : [];

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
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{guardianDisplayText(device.ip || device.mac || device.device_id)}</p>
          </div>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)", flexShrink: 0 }}>
          <XIcon />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-6">
        {/* Status badges */}
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={riskLevel.toUpperCase()} variant={riskVariant(riskLevel)} />
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
          {(securityReasons.length > 0 || privacyReasons.length > 0) && (
            <div className="mt-3 flex flex-col gap-1">
              {[...securityReasons, ...privacyReasons].slice(0, 6).map((reason, i) => (
                <p key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>• {guardianDisplayText(reason)}</p>
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
              { label: "Open Ports", value: String(openPorts.length) },
              { label: "Last Seen", value: device.last_seen ? new Date(device.last_seen).toLocaleString() : "N/A" },
            ].map(({ label, value, mono }, i, arr) => (
              <div key={label} className="flex items-center justify-between px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
                <span style={{ fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-all", maxWidth: "200px", textAlign: "right" }}>{guardianDisplayText(value)}</span>
              </div>
            ))}
          </div>
        </div>

        {openPorts.length > 0 && (
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>OPEN PORTS</p>
            <div className="flex flex-wrap gap-1.5">
              {openPorts.slice(0, 12).map((port) => (
                <span key={`${port.port}-${port.protocol}`} className="rounded-md px-2 py-0.5" style={{ backgroundColor: "var(--secondary)", border: "1px solid var(--border)", fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)" }}>
                  {guardianDisplayText(`${port.port}/${port.protocol}${port.service ? ` ${port.service}` : ""}`)}
                </span>
              ))}
              {openPorts.length > 12 && (
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", color: "var(--muted-foreground)" }}>+{openPorts.length - 12} more</span>
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
              {scanFindings.slice(0, 5).map((finding, i) => (
                <p key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>• {guardianDisplayText(finding)}</p>
              ))}
              {scanRecommendations.slice(0, 3).map((rec, i) => (
                <p key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-5)", lineHeight: 1.5 }}>→ {guardianDisplayText(rec)}</p>
              ))}
            </div>
          )}
        </div>

        {/* Actions */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>ACTIONS</p>
          <div className="flex flex-col gap-2">
            {device.rejected ? (
              <button
                onClick={handleApprove}
                disabled={approving}
                className="w-full flex items-center justify-center gap-2 rounded-lg"
                style={{ height: "44px", backgroundColor: "color-mix(in srgb, var(--chart-2) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--chart-2) 25%, transparent)", color: "var(--chart-2)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: approving ? "wait" : "pointer" }}
              >
                {approving ? <Loader2 size={16} className="animate-spin" /> : <ShieldCheck size={16} />} Approve Device
              </button>
            ) : (
              <>
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
              <button
                onClick={() => onReject(device)}
                className="w-full flex items-center justify-center gap-2 rounded-lg"
                style={{ height: "44px", backgroundColor: "color-mix(in srgb, var(--chart-5) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--chart-5) 25%, transparent)", color: "var(--chart-5)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer" }}
              >
                <UserX size={16} /> Reject & Block
              </button>
              </>
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

  const canSubmit = safeTrim(ip).length > 0 || safeTrim(mac).length > 0;

  const handleSubmit = async () => {
    if (!canSubmit || saving) return;
    setSaving(true);
    try {
      await managedDeviceService.addManual({
        display_name: safeTrim(displayName) || undefined,
        ip: safeTrim(ip) || undefined,
        mac: safeTrim(mac) || undefined,
        manufacturer: safeTrim(manufacturer) || undefined,
      });
      toast.success("Device added to fleet");
      onOpenChange(false);
      onAdded();
    } catch (error: any) {
      toast.error(guardianDisplayText(error.message) || "Failed to add device");
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
      await managedDeviceService.reject(device.device_id, safeTrim(reason) ? { reason: safeTrim(reason) } : undefined);
      toast.success("Device rejected and blocked");
      onOpenChange(false);
      onRejected();
    } catch (error: any) {
      toast.error(guardianDisplayText(error.message) || "Failed to reject device");
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

  const [pairedDevices, setPairedDevices] = useState<PairedDevice[]>([]);
  const [unpairedDevices, setUnpairedDevices] = useState<PairedDevice[]>([]);
  const [allDevices, setAllDevices] = useState<PairedDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [pairedLoaded, setPairedLoaded] = useState(false);

  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [unpairId, setUnpairId] = useState<string | null>(null);
  const [unpairLoading, setUnpairLoading] = useState(false);
  const [repairTarget, setRepairTarget] = useState<PairedDevice | null>(null);
  const [repairPairingData, setRepairPairingData] = useState<PairingCodeResponse | null>(null);
  const [repairProof, setRepairProof] = useState("");
  const [repairLoading, setRepairLoading] = useState(false);
  const [repairCodeCopied, setRepairCodeCopied] = useState(false);

  // Fleet security state
  const [fleetDevices, setFleetDevices] = useState<ManagedDevice[]>([]);
  const [fleetSummary, setFleetSummary] = useState<ManagedDevicesSummary | null>(null);
  const [fleetLoading, setFleetLoading] = useState(true);
  const [selectedFleetId, setSelectedFleetId] = useState<string | null>(null);
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [rejectTarget, setRejectTarget] = useState<ManagedDevice | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ManagedDevice | null>(null);
  const [deleting, setDeleting] = useState(false);

  const loadPairedDevices = useCallback(async () => {
    setLoading(true);
    try {
      const data = await deviceService.listPairedDevices();
      setPairedDevices(data.filter(isValidPairedDevice));
      setPairedLoaded(true);
    } catch (e: any) {
      console.warn("Failed to load paired devices", e.message);
      setPairedLoaded(false);
      toast.error(guardianDisplayText(e.message) || "Failed to load paired devices");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadUnpairedDevices = useCallback(async () => {
    try {
      const data = await deviceService.listUnpairedDevices();
      setUnpairedDevices(data.filter(isValidPairedDevice));
    } catch (e: any) {
      console.warn("Failed to load unpaired devices", e.message);
      toast.error(guardianDisplayText(e.message) || "Failed to load unpaired devices");
    }
  }, []);

  const loadAllDevices = useCallback(async () => {
    try {
      const data = await deviceService.listAllDevices();
      setAllDevices(data);
    } catch (e: any) {
      console.warn("Failed to load device stats", e.message);
      toast.error(guardianDisplayText(e.message) || "Failed to load device stats");
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
      toast.error(guardianDisplayText(e.message) || "Failed to load fleet devices");
    } finally {
      setFleetLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPairedDevices();
    loadUnpairedDevices();
    loadAllDevices();
  }, [loadPairedDevices, loadUnpairedDevices, loadAllDevices]);

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
      setPairedDevices((prev) => prev.filter((device) => device.deviceId !== unpairId));
      await Promise.all([loadPairedDevices(), loadUnpairedDevices(), loadAllDevices()]);
    } catch (e: any) {
      toast.error(guardianDisplayText(e.message) || "Failed to unpair device");
    } finally {
      setUnpairLoading(false);
    }
  };

  const resetRepair = () => {
    setRepairTarget(null);
    setRepairPairingData(null);
    setRepairProof("");
    setRepairLoading(false);
    setRepairCodeCopied(false);
  };

  const handleOpenRepair = async (device: PairedDevice) => {
    const serial = safeTrim(device.serial);
    if (!serial) {
      toast.error("Device serial is required to generate a pairing code");
      return;
    }

    setRepairTarget(device);
    setRepairPairingData(null);
    setRepairProof("");
    setRepairCodeCopied(false);
    setRepairLoading(true);
    try {
      const data = await deviceService.getPairingCode(serial);
      setRepairPairingData(data);
      toast.success("Pairing code generated");
    } catch (e: any) {
      toast.error(guardianDisplayText(e.message) || "Failed to generate pairing code");
      resetRepair();
    } finally {
      setRepairLoading(false);
    }
  };

  const handleRepair = async () => {
    if (!repairPairingData || !safeTrim(repairProof) || repairLoading) return;
    setRepairLoading(true);
    try {
      await deviceService.pairDevice(repairPairingData.serial, safeTrim(repairProof));
      toast.success("Guardian re-paired successfully");
      resetRepair();
      await Promise.all([loadPairedDevices(), loadUnpairedDevices(), loadAllDevices()]);
    } catch (e: any) {
      toast.error(guardianDisplayText(e.message) || "Re-pair failed. Check the proof and try again.");
    } finally {
      setRepairLoading(false);
    }
  };

  const handleCopyRepairCode = async () => {
    if (!repairPairingData?.pairingCode) return;
    try {
      await navigator.clipboard.writeText(repairPairingData.pairingCode);
      setRepairCodeCopied(true);
      toast.success("Pairing code copied");
      window.setTimeout(() => setRepairCodeCopied(false), 1500);
    } catch {
      toast.error("Copy failed");
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
      toast.error(guardianDisplayText(e.message) || "Failed to remove device");
    } finally {
      setDeleting(false);
    }
  };

  // Paired tab: GET /devices/paired only — never scan, discovery, or fleet inventory.
  // Unpaired tab: separate guardian pairing source (no managed-device fallback).
  // Stats cards: GET /devices/all only — never used as a list source.
  // Fleet Security: only managed-device API state — never paired-device fallback.
  const validFleetDevices = fleetDevices.filter(isValidFleetDevice);
  const pairedDeviceCount = allDevices.filter((device) => safeTrim(device.status).toLowerCase() === "active").length;
  const unpairedDeviceCount = allDevices.filter((device) => safeTrim(device.status).toLowerCase() === "unpaired").length;

  const searchQuery = safeTrim(search).toLowerCase();
  const filteredPaired = pairedDevices.filter((d) => {
    if (!searchQuery) return true;
    return (
      safeTrim(d.serial).toLowerCase().includes(searchQuery) ||
      safeTrim(d.nodeId).toLowerCase().includes(searchQuery)
    );
  });
  const filteredUnpaired = unpairedDevices.filter((d) => {
    if (!searchQuery) return true;
    return (
      safeTrim(d.serial).toLowerCase().includes(searchQuery) ||
      safeTrim(d.nodeId).toLowerCase().includes(searchQuery)
    );
  });
  const filteredFleet = validFleetDevices.filter((d) => {
    if (!searchQuery) return true;
    return [d.display_name, d.hostname, d.ip, d.mac, d.device_id].some((v) =>
      safeTrim(v).toLowerCase().includes(searchQuery)
    );
  });

  const selectedFleetDevice = validFleetDevices.find((d) => d.device_id === selectedFleetId) ?? null;
  const selectedGuardianDevice =
    (tab === "unpaired" ? unpairedDevices : pairedDevices).find((device) => device.deviceId === selectedDeviceId) ?? null;

  const Header = (
    <div className="flex flex-col justify-center flex-shrink-0 px-5 h-16 border-b border-border bg-card relative overflow-hidden">
      <div className="absolute inset-0 opacity-10" style={{ background: "linear-gradient(90deg, var(--primary) 0%, transparent 100%)" }} />
      <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.2, position: "relative" }}>
        Devices
      </h2>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.3, position: "relative" }}>
        Manage your connected Guardians
      </p>
    </div>
  );

  const GuardianStatCards = (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 px-5 py-3 border-b border-border bg-background">
      <div className="rounded-xl p-3 border border-border shadow-sm flex flex-col justify-between min-w-0" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-1.5">
          <Cpu size={16} style={{ color: "var(--primary)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Total Devices</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "24px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)", lineHeight: 1.1 }}>{allDevices.length}</p>
      </div>
      <div className="rounded-xl p-3 border border-border shadow-sm flex flex-col justify-between min-w-0" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-1.5">
          <Shield size={16} style={{ color: "var(--chart-2)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Paired Devices</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "24px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)", lineHeight: 1.1 }}>{pairedDeviceCount}</p>
      </div>
      <div className="rounded-xl p-3 border border-border shadow-sm flex flex-col justify-between min-w-0" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-1.5">
          <LayoutList size={16} style={{ color: "var(--muted-foreground)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Unpaired Devices</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "24px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)", lineHeight: 1.1 }}>{unpairedDeviceCount}</p>
      </div>
    </div>
  );

  const FleetStatCards = (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 px-5 py-3 border-b border-border bg-background">
      <div className="rounded-xl p-3 border border-border shadow-sm flex flex-col justify-between min-w-0" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-1.5">
          <Cpu size={16} style={{ color: "var(--primary)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Total</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "24px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)", lineHeight: 1.1 }}>{fleetSummary?.total ?? validFleetDevices.length}</p>
      </div>
      <div className="rounded-xl p-3 border border-border shadow-sm flex flex-col justify-between min-w-0" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-1.5">
          <ShieldAlert size={16} style={{ color: "var(--destructive)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>At Risk</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "24px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)", lineHeight: 1.1 }}>{(fleetSummary?.critical_devices ?? 0) + (fleetSummary?.high_risk_devices ?? 0)}</p>
      </div>
      <div className="rounded-xl p-3 border border-border shadow-sm flex flex-col justify-between min-w-0" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-1.5">
          <Ban size={16} style={{ color: "var(--chart-5)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Blocked</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "24px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)", lineHeight: 1.1 }}>{fleetSummary?.blocked ?? 0}</p>
      </div>
      <div className="rounded-xl p-3 border border-border shadow-sm flex flex-col justify-between min-w-0" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-1.5">
          <ShieldCheck size={16} style={{ color: "var(--chart-2)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Monitored</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "24px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)", lineHeight: 1.1 }}>{fleetSummary?.monitoring_enabled ?? 0}</p>
      </div>
    </div>
  );

  const StatCards = tab === "fleet" ? FleetStatCards : GuardianStatCards;

  const Controls = (
    <div className="flex flex-col gap-3 px-5 py-3 flex-shrink-0">
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
            <ShieldAlert size={14} /> Fleet Discovery
            <InfoTooltip label="Fleet Discovery help">
              Fleet Discovery scans your network for devices Guardian can monitor. It helps you spot new devices, risky devices, and devices that should be blocked or reviewed.
            </InfoTooltip>
          </button>
          <button
            onClick={() => navigate("/devices/smart-home")}
            style={{ padding: "6px 16px", borderRadius: "var(--radius)", backgroundColor: "transparent", color: "var(--muted-foreground)", border: "none", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer", transition: "all 0.2s", display: "flex", alignItems: "center", gap: "6px" }}
          >
            <Home size={14} /> Smart Home
            <InfoTooltip label="Smart Home help">
              Smart Home connects supported household devices, like cameras, thermostats, plugs, and switches, so Guardian can show their status and help automate simple actions.
            </InfoTooltip>
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
      <div className="flex flex-col flex-1 border-r border-border min-w-0 min-h-0">
        {Header}
        {StatCards}
        {Controls}

        {/* List area */}
        <div className="flex-1 min-h-0 overflow-y-auto px-5 pb-6">
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
                {filteredFleet.map((device) => {
                  const riskLevel = safeTrim(device.risk_level) || "unknown";
                  return (
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
                          <StatusBadge status={riskLevel.toUpperCase()} variant={riskVariant(riskLevel)} />
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
                  );
                })}
              </div>
            )
          ) : loading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <Loader2 size={24} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
              <span className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Loading...</span>
            </div>
          ) : tab === "paired" ? (
            pairedLoaded && filteredPaired.length === 0 ? (
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
                            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{safeTrim(device.serial) || safeTrim(device.nodeId)}</p>
                          </div>
                          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{safeTrim(device.nodeId)}</p>
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
                  <div
                    key={device.deviceId}
                    role="button"
                    tabIndex={0}
                    onClick={() => setSelectedDeviceId(device.deviceId)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedDeviceId(device.deviceId);
                      }
                    }}
                    className="w-full text-left flex items-center justify-between p-4 rounded-xl border transition-all shadow-sm"
                    style={{
                      backgroundColor: selectedDeviceId === device.deviceId ? "color-mix(in srgb, var(--primary) 6%, var(--card))" : "var(--card)",
                      borderColor: selectedDeviceId === device.deviceId ? "var(--primary)" : "var(--border)",
                      cursor: "pointer"
                    }}
                  >
                    <div className="flex items-center gap-4 min-w-0">
                      <div className="rounded-lg flex items-center justify-center flex-shrink-0 shadow-sm" style={{ width: "40px", height: "40px", backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
                        <LayoutList size={20} style={{ color: "var(--muted-foreground)" }} />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <p className="truncate" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{safeTrim(device.serial) || safeTrim(device.nodeId)}</p>
                        </div>
                        <p className="truncate" style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{safeTrim(device.nodeId)} · Unpaired</p>
                      </div>
                    </div>
                    <ChevronRight size={18} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
                  </div>
                ))}
              </div>
            )
          )}
        </div>
      </div>

      {/* Side panel */}
      {tab === "fleet" ? (
        selectedFleetDevice && (
          <div className="hidden md:flex flex-col flex-shrink-0" style={{ width: "380px", backgroundColor: "var(--card)", borderLeft: "1px solid var(--border)", boxShadow: "-4px 0 15px rgba(0,0,0,0.02)", animation: "slideInRight 220ms ease-out" }}>
            <FleetDetailPanel
              device={selectedFleetDevice}
              onClose={() => setSelectedFleetId(null)}
              onReject={setRejectTarget}
              onDelete={setDeleteTarget}
              onChanged={loadFleet}
            />
          </div>
        )
      ) : (
        selectedDeviceId && (
          <div className="hidden md:flex flex-col flex-shrink-0" style={{ width: "380px", backgroundColor: "var(--card)", borderLeft: "1px solid var(--border)", boxShadow: "-4px 0 15px rgba(0,0,0,0.02)", animation: "slideInRight 220ms ease-out" }}>
            <DeviceDetailPanel
              deviceId={selectedDeviceId}
              fallbackDevice={selectedGuardianDevice}
              onClose={() => setSelectedDeviceId(null)}
              onUnpair={setUnpairId}
              onRepair={handleOpenRepair}
            />
          </div>
        )
      )}

      {/* Mobile side panel overlay */}
      {tab === "fleet" && selectedFleetId && selectedFleetDevice && (
        <div className="md:hidden fixed inset-0 z-50 flex justify-end" style={{ backgroundColor: "rgba(0,0,0,0.5)" }} onClick={() => setSelectedFleetId(null)}>
          <div className="w-[85vw] max-w-[360px] h-full shadow-2xl" style={{ animation: "slideInRight 220ms ease-out" }} onClick={(e) => e.stopPropagation()}>
            <FleetDetailPanel device={selectedFleetDevice} onClose={() => setSelectedFleetId(null)} onReject={setRejectTarget} onDelete={setDeleteTarget} onChanged={loadFleet} />
          </div>
        </div>
      )}
      {tab !== "fleet" && selectedDeviceId && (
        <div className="md:hidden fixed inset-0 z-50 flex justify-end" style={{ backgroundColor: "rgba(0,0,0,0.5)" }} onClick={() => setSelectedDeviceId(null)}>
          <div className="w-[85vw] max-w-[360px] h-full shadow-2xl" style={{ animation: "slideInRight 220ms ease-out" }} onClick={(e) => e.stopPropagation()}>
            <DeviceDetailPanel
              deviceId={selectedDeviceId}
              fallbackDevice={selectedGuardianDevice}
              onClose={() => setSelectedDeviceId(null)}
              onUnpair={setUnpairId}
              onRepair={handleOpenRepair}
            />
          </div>
        </div>
      )}

      {/* Re-pair Dialog */}
      <Dialog.Root open={!!repairTarget} onOpenChange={(open) => !open && !repairLoading && resetRepair()}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
          <Dialog.Content className="fixed z-[70] rounded-xl border border-border p-6 flex flex-col gap-4" style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "440px" }}>
            <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Re-Pair Guardian</Dialog.Title>
            <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
              Generate a fresh pairing code and paste the signed proof from the target device.
            </Dialog.Description>

            <div className="flex flex-col gap-3">
              <div className="rounded-lg border border-border p-3" style={{ backgroundColor: "var(--background)" }}>
                <div className="flex items-center justify-between gap-3 mb-2">
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>PAIRING CODE</span>
                  <div className="flex items-center gap-2">
                    {repairCodeCopied && (
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--chart-2)" }}>Copied</span>
                    )}
                    {repairLoading && !repairPairingData ? (
                      <Loader2 size={14} className="animate-spin" style={{ color: "var(--primary)" }} />
                    ) : (
                      <button
                        type="button"
                        onClick={handleCopyRepairCode}
                        disabled={!repairPairingData?.pairingCode}
                        aria-label="Copy pairing code"
                        title={repairCodeCopied ? "Copied" : "Copy pairing code"}
                        className="flex items-center justify-center rounded-md transition-opacity active:opacity-80"
                        style={{
                          width: "30px",
                          height: "30px",
                          backgroundColor: repairCodeCopied ? "color-mix(in srgb, var(--chart-2) 14%, transparent)" : "var(--secondary)",
                          color: repairCodeCopied ? "var(--chart-2)" : "var(--secondary-foreground)",
                          border: "1px solid var(--border)",
                          cursor: repairPairingData?.pairingCode ? "pointer" : "default",
                          opacity: repairPairingData?.pairingCode ? 1 : 0.5,
                          flexShrink: 0,
                        }}
                      >
                        {repairCodeCopied ? <Check size={13} /> : <Copy size={13} />}
                      </button>
                    )}
                  </div>
                </div>
                <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", wordBreak: "break-all", lineHeight: 1.8, minHeight: "22px", userSelect: "all" }}>
                  {repairPairingData?.pairingCode || "Generating..."}
                </p>
              </div>

              <div>
                <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>
                  Signed Proof
                </label>
                <textarea
                  autoFocus={!!repairPairingData}
                  value={repairProof}
                  onChange={(event) => setRepairProof(event.target.value)}
                  placeholder="Paste the proof string from the Guardian device..."
                  rows={5}
                  className="w-full px-4 py-3 outline-none"
                  disabled={!repairPairingData || repairLoading}
                  style={{
                    backgroundColor: "var(--input-background)",
                    border: "1.5px solid var(--border)",
                    borderRadius: "var(--radius)",
                    color: "var(--foreground)",
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: "11px",
                    resize: "none",
                    lineHeight: 1.7,
                    width: "100%",
                    boxSizing: "border-box",
                    opacity: repairPairingData ? 1 : 0.55,
                  }}
                />
              </div>
            </div>

            <div className="flex gap-3">
              <button
                onClick={resetRepair}
                disabled={repairLoading}
                style={{ flex: 1, height: "44px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: repairLoading ? "default" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", opacity: repairLoading ? 0.6 : 1 }}
              >
                Cancel
              </button>
              <button
                onClick={handleRepair}
                disabled={!repairPairingData || !safeTrim(repairProof) || repairLoading}
                style={{ flex: 1, height: "44px", backgroundColor: "var(--primary)", border: "none", borderRadius: "var(--radius)", cursor: repairPairingData && safeTrim(repairProof) && !repairLoading ? "pointer" : "default", opacity: repairPairingData && safeTrim(repairProof) && !repairLoading ? 1 : 0.5, fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary-foreground)", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px" }}
              >
                {repairLoading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                Re-Pair
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

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

      <style>{`
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes slideInRight { from{transform:translateX(100%); opacity:0.6} to{transform:translateX(0); opacity:1} }
      `}</style>
    </div>
  );
}
