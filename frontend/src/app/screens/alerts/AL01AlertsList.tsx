import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import {
  Clock, ChevronRight, ChevronDown, Trash2, Search, Shield, Archive,
  CheckSquare, Square, X, AlertTriangle, Brain, Loader2, Network,
} from "lucide-react";
import { mockAlerts } from "../../data/mockData";
import { useAlerts, useThreatStatus } from "../../hooks/useApiData";
import type { ThreatStatus } from "../../services/threatService";
import { ApiError } from "../../services/api";
import { advisoryService, type AdvisoryRules, type RemediationRecommendation } from "../../services/advisoryService";
import { managedDeviceService, type ManagedDevice } from "../../services/managedDeviceService";
import { guardianAlertHeading, type Alert } from "../../services/alertService";
import { ThreatProtectionPanel } from "./AL08ThreatProtection";
import { AL09LiveAttackTopology } from "./AL09LiveAttackTopology";
import { SeverityBadge, StatusBadge } from "../../components/SeverityBadge";
import { SkeletonBlock, SkeletonCard } from "../../components/SkeletonBlock";
import { EmptyState } from "../../components/EmptyState";
import { toast } from "sonner";

type Mode = "active" | "archived" | "bulk";
type SeverityFilter = "ALL" | "HIGH" | "MEDIUM" | "LOW";
type StatusFilter = "ALL" | "Active" | "Acknowledged" | "Blocked";
type AlertView = Alert & Partial<typeof mockAlerts[number]>;
type RecommendationState =
  | { status: "idle" | "loading" }
  | { status: "available" | "fallback"; recommendation: RemediationRecommendation; rules?: AdvisoryRules | null }
  | { status: "none"; rules?: AdvisoryRules | null }
  | { status: "error"; message: string; rules?: AdvisoryRules | null }
  | { status: "unauthorized"; message: string };

function confidencePercent(confidence: number | undefined): number {
  const raw = Number(confidence ?? 0);
  const percent = raw <= 1 ? raw * 100 : raw;
  return Math.max(0, Math.min(100, Math.round(percent)));
}

function formatDateTime(value?: string): string {
  if (!value) return "N/A";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function compactValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "N/A";
  return String(value);
}

function extractCves(lines: string[]): string[] {
  return Array.from(new Set(lines.flatMap((line) => line.match(/CVE-\d{4}-\d{4,7}/gi) ?? [])));
}

function extractCvss(lines: string[]): string[] {
  return Array.from(new Set(lines.flatMap((line) => line.match(/CVSS\s*[:=]?\s*\d+(?:\.\d+)?|\b\d+(?:\.\d+)?\s*CVSS/gi) ?? [])));
}

function findDeviceForAlert(alert: AlertView, devices: ManagedDevice[]): ManagedDevice | null {
  const ips = new Set([alert.srcIp, alert.dstIp, alert.deviceIp].filter(Boolean));
  return devices.find((device) => device.ip && ips.has(device.ip)) ?? null;
}

function isUnauthorizedError(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 401 || error.status === 403);
}

function isNotFoundError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

function advisoryErrorMessage(error: unknown): string {
  if (isUnauthorizedError(error)) return "Session expired or unauthorized. Please sign in again.";
  if (error instanceof Error) return error.message;
  return "Recommendation request failed";
}

function RecommendationSkeleton() {
  return (
    <div className="rounded-lg border p-4" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}>
      <div className="flex items-center gap-2 mb-4">
        <SkeletonBlock height={18} width={18} rounded="sm" />
        <SkeletonBlock height={12} width="48%" />
      </div>
      <SkeletonCard lines={4} />
    </div>
  );
}

function RecommendationCard({ state }: { state: RecommendationState }) {
  const sectionLabel = { fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em" } as const;

  if (state.status === "loading") return <RecommendationSkeleton />;

  if (state.status === "unauthorized" || state.status === "error" || state.status === "none") {
    const title = state.status === "none" ? "No recommendation found" : state.status === "unauthorized" ? "Unauthorized" : "Recommendation unavailable";
    const message = state.status === "none"
      ? "No advisory has been generated for this alert yet. Alert details remain available for manual triage."
      : state.message;
    return (
      <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: state.status === "unauthorized" ? "color-mix(in srgb, var(--chart-5) 28%, var(--border))" : "var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Brain size={14} style={{ color: "var(--primary)" }} />
          <span style={sectionLabel}>AI-READY REMEDIATION ADVISORY</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{title}</p>
        <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>{message}</p>
      </div>
    );
  }

  if (state.status !== "available" && state.status !== "fallback") return null;

  const rec = state.recommendation;
  const advisoryConfidence = confidencePercent(rec.advisory_confidence ?? rec.confidence);
  const modelConfidence = rec.anomaly?.confidence != null ? confidencePercent(rec.anomaly.confidence) : null;
  const isFallback = state.status === "fallback" || rec.source === "fallback";

  return (
    <div className="rounded-lg border p-4" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 22%, transparent)" }}>
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <Brain size={14} style={{ color: "var(--primary)" }} />
          <span style={sectionLabel}>AI REMEDIATION RECOMMENDATION</span>
        </div>
        <span className="rounded-full px-2 py-0.5" style={{ backgroundColor: isFallback ? "color-mix(in srgb, var(--chart-5) 13%, transparent)" : "color-mix(in srgb, var(--primary) 13%, transparent)", border: `1px solid ${isFallback ? "color-mix(in srgb, var(--chart-5) 25%, transparent)" : "color-mix(in srgb, var(--primary) 25%, transparent)"}`, color: isFallback ? "var(--chart-5)" : "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-semibold)" }}>
          {rec.source || "fallback"}
        </span>
      </div>

      <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.35 }}>{rec.title}</h3>
      <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.65 }}>{rec.summary}</p>

      <div className="mt-4">
        <div className="flex items-center justify-between mb-1.5">
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Recommendation Confidence</span>
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-2)", fontWeight: "var(--font-weight-semibold)" }}>{advisoryConfidence}%</span>
        </div>
        <div style={{ height: "7px", borderRadius: "999px", backgroundColor: "var(--muted)", overflow: "hidden" }}>
          <div style={{ width: `${advisoryConfidence}%`, height: "100%", backgroundColor: "var(--chart-2)", borderRadius: "999px" }} />
        </div>
      </div>

      {(modelConfidence !== null || rec.advisory_basis) && (
        <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
          {modelConfidence !== null && (
            <div className="rounded-md p-2.5" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textTransform: "uppercase", letterSpacing: "0.04em" }}>Model Confidence</p>
              <p className="mt-1" style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{modelConfidence}%</p>
            </div>
          )}
          {rec.advisory_basis && (
            <div className="rounded-md p-2.5 md:col-span-1" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textTransform: "uppercase", letterSpacing: "0.04em" }}>Confidence Basis</p>
              <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", lineHeight: 1.5 }}>{rec.advisory_basis}</p>
            </div>
          )}
        </div>
      )}

      <div className="mt-3 flex items-center gap-2 flex-wrap">
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Generated {formatDateTime(rec.generated_at)}</span>
        {isFallback && <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-5)" }}>Fallback recommendation</span>}
      </div>

      {rec.steps.length > 0 && (
        <div className="mt-4">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>REMEDIATION STEPS</p>
          <ol className="flex flex-col gap-3">
            {[...rec.steps].sort((a, b) => a.order - b.order).map((step, index) => (
              <li key={`${step.order}-${index}`} className="flex gap-3">
                <span className="rounded-md flex items-center justify-center flex-shrink-0" style={{ width: "24px", height: "24px", backgroundColor: "color-mix(in srgb, var(--primary) 16%, transparent)", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)" }}>{step.order || index + 1}</span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.5 }}>{step.action}</p>
                    <span className="rounded-full px-2 py-0.5" style={{ backgroundColor: step.automatable ? "color-mix(in srgb, var(--chart-2) 13%, transparent)" : "color-mix(in srgb, var(--chart-5) 13%, transparent)", border: `1px solid ${step.automatable ? "color-mix(in srgb, var(--chart-2) 25%, transparent)" : "color-mix(in srgb, var(--chart-5) 25%, transparent)"}`, color: step.automatable ? "var(--chart-2)" : "var(--chart-5)", fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-semibold)" }}>
                      {step.automatable ? "Automatable" : "Manual"}
                    </span>
                  </div>
                  <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.55 }}>{step.rationale}</p>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}

      {rec.context.length > 0 && (
        <div className="mt-4">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>CONTEXT / EVIDENCE</p>
          <div className="flex flex-col gap-1.5">
            {rec.context.map((line, index) => (
              <p key={index} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>• {line}</p>
            ))}
          </div>
        </div>
      )}

      {rec.references.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-1.5">
          {rec.references.map((ref) => (
            <span key={ref} className="rounded-md px-2 py-1" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)", color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace", fontSize: "10px" }}>{ref}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function DeviceContextCard({ alert, recommendation, devices }: { alert: AlertView; recommendation: RemediationRecommendation | null; devices: ManagedDevice[] }) {
  const context = recommendation?.context ?? [];
  const device = findDeviceForAlert(alert, devices);
  const cves = extractCves([...(recommendation?.references ?? []), ...context]);
  const cvss = extractCvss(context);
  const openPorts = device?.open_ports ?? [];
  const riskReasons = [...(device?.security_reasons ?? []), ...(device?.privacy_reasons ?? []), ...context.filter((line) => /risk|cve|cvss|vulnerab/i.test(line))];
  const rows = [
    { label: "Device IP", value: device?.ip || alert.dstIp || alert.srcIp || alert.deviceIp, mono: true },
    { label: "Device ID", value: device?.device_id, mono: true },
    { label: "Vendor", value: device?.vendor || device?.display_name },
    { label: "Authorization", value: device ? (device.rejected ? "Rejected" : device.blocked ? "Blocked" : "Authorized / monitored") : alert.blocked ? "Blocked by threat enforcement" : "Unknown" },
    { label: "OS Fingerprint", value: device?.os_fingerprint || alert.os },
  ];

  return (
    <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>DEVICE CONTEXT</p>
      <div className="grid grid-cols-2 gap-2">
        {rows.map((row) => (
          <div key={row.label} className="rounded-md p-2.5" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{row.label}</p>
            <p className="mt-1" style={{ fontFamily: row.mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-word" }}>{compactValue(row.value)}</p>
          </div>
        ))}
      </div>
      {openPorts.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {openPorts.slice(0, 10).map((port) => (
            <span key={`${port.protocol}-${port.port}`} className="rounded-md px-2 py-1" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)", color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace", fontSize: "10px" }}>
              {port.port}/{port.protocol}{port.service ? ` ${port.service}` : ""}
            </span>
          ))}
        </div>
      )}
      {riskReasons.length > 0 && (
        <div className="mt-3">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontWeight: "var(--font-weight-semibold)", marginBottom: "6px" }}>Risk details</p>
          {riskReasons.slice(0, 5).map((reason, index) => (
            <p key={index} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>• {reason}</p>
          ))}
        </div>
      )}
      {(cves.length > 0 || cvss.length > 0) && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {[...cves, ...cvss].map((item) => (
            <span key={item} className="rounded-md px-2 py-1" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 22%, transparent)", color: "var(--destructive)", fontFamily: "JetBrains Mono, monospace", fontSize: "10px" }}>{item}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Alert Detail Panel (inline for tablet/desktop) ────────────────────────────
function AlertDetailPanel({ alert, onClose }: { alert: AlertView; onClose: () => void }) {
  const navigate = useNavigate();
  const accentColor = alert.severity === "HIGH" ? "var(--destructive)" : alert.severity === "MEDIUM" ? "var(--chart-5)" : "var(--chart-2)";
  const statusVariant = alert.status === "Active" ? "danger" : alert.status === "Blocked" ? "warning" : "muted";
  const sectionLabel = { fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" } as const;
  const [recommendationState, setRecommendationState] = useState<RecommendationState>({ status: "idle" });
  const [devices, setDevices] = useState<ManagedDevice[]>([]);
  const activeRecommendation = recommendationState.status === "available" || recommendationState.status === "fallback"
    ? recommendationState.recommendation
    : null;

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setRecommendationState({ status: "loading" });
    setDevices([]);

    async function loadRecommendation() {
      const [primary, recent, rules, deviceList] = await Promise.allSettled([
        advisoryService.getRecommendation(alert.id, controller.signal),
        advisoryService.listRecommendations(500, controller.signal),
        advisoryService.getRules(controller.signal),
        managedDeviceService.list(),
      ]);

      if (!active || controller.signal.aborted) return;
      const rulesValue = rules.status === "fulfilled" ? rules.value : null;
      if (deviceList.status === "fulfilled") setDevices(deviceList.value);

      if (primary.status === "fulfilled") {
        setRecommendationState({
          status: primary.value.source === "fallback" ? "fallback" : "available",
          recommendation: primary.value,
          rules: rulesValue,
        });
        return;
      }

      const err = primary.reason;
      if (isUnauthorizedError(err)) {
        toast.error("Session expired or unauthorized");
        setRecommendationState({ status: "unauthorized", message: "Session expired or unauthorized. Please sign in again." });
        return;
      }

      const recentMatch = recent.status === "fulfilled"
        ? recent.value.find((rec) => rec.alert_id === alert.id) ?? null
        : null;
      if (recentMatch) {
        setRecommendationState({
          status: "fallback",
          recommendation: recentMatch,
          rules: rulesValue,
        });
        return;
      }

      if (isNotFoundError(err)) {
        setRecommendationState({ status: "none", rules: rulesValue });
        return;
      }

      setRecommendationState({ status: "error", message: advisoryErrorMessage(err), rules: rulesValue });
    }

    loadRecommendation();
    return () => {
      active = false;
      controller.abort();
    };
  }, [alert.id]);

  const details = [
    { label: "Signature ID", value: alert.signatureId, mono: true },
    { label: "Category", value: alert.category || alert.eventType },
    { label: "Source", value: `${compactValue(alert.srcIp || alert.deviceIp)}:${compactValue(alert.srcPort)}`, mono: true },
    { label: "Destination", value: `${compactValue(alert.dstIp)}:${compactValue(alert.dstPort)}`, mono: true },
    { label: "Protocol", value: alert.protocol || alert.os },
    { label: "Timestamp", value: formatDateTime(alert.rawTimestamp || `${alert.date} ${alert.timestamp}`) },
  ];

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Severity accent bar */}
      <div style={{ height: "3px", backgroundColor: accentColor, flexShrink: 0 }} />

      {/* Header (pinned) */}
      <div className="flex items-start justify-between gap-3 px-5 pt-4 pb-4 border-b border-border flex-shrink-0">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <SeverityBadge severity={alert.severity} size="md" />
            <StatusBadge status={alert.status} variant={statusVariant} />
          </div>
          <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.3 }}>
            {guardianAlertHeading(alert.title)}
          </h2>
          <div className="flex items-center gap-1.5 mt-1.5 flex-wrap" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            <Clock size={12} />
            <span>{alert.timestamp} · {alert.date}</span>
            <span>·</span>
            <span style={{ fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{alert.device}</span>
          </div>
        </div>
        <button onClick={onClose} title="Close" className="flex items-center justify-center rounded-md flex-shrink-0" style={{ width: "28px", height: "28px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer" }}>
          <X size={14} />
        </button>
      </div>

      {/* Body (scrolls between pinned header and footer) */}
      <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-4">
        {/* HIGH severity warning — subtle inline banner */}
        {alert.severity === "HIGH" && (
          <div className="flex items-center gap-2 rounded-lg px-3 py-2.5" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 22%, transparent)" }}>
            <AlertTriangle size={14} style={{ color: "var(--destructive)", flexShrink: 0 }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)", fontWeight: "var(--font-weight-semibold)" }}>
              Active threat — review advisory and evidence
            </span>
          </div>
        )}

        {/* Details grid */}
        <div>
          <p style={sectionLabel}>Alert Details</p>
          <div className="grid grid-cols-2 rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
            {details.map((row, i) => (
              <div key={row.label} className="px-4 py-3 min-w-0" style={{ borderRight: i % 2 === 0 ? "1px solid var(--border)" : undefined, borderBottom: i < details.length - 2 ? "1px solid var(--border)" : undefined }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", fontWeight: "var(--font-weight-medium)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{row.label}</p>
                <p style={{ fontFamily: row.mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", fontWeight: "var(--font-weight-medium)", marginTop: "2px", wordBreak: "break-word" }}>{compactValue(row.value)}</p>
              </div>
            ))}
          </div>
        </div>

        <div>
          <p style={sectionLabel}>Original Alert Evidence</p>
          <div className="rounded-lg border border-border p-3" style={{ backgroundColor: "var(--card)" }}>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
              {alert.originalEvidence || alert.description || alert.aiSummary}
            </p>
          </div>
        </div>

        <RecommendationCard state={recommendationState} />
        <DeviceContextCard alert={alert} recommendation={activeRecommendation} devices={devices} />
      </div>

      {/* Footer CTA (pinned) */}
      <div className="px-5 py-4 border-t border-border flex-shrink-0">
        <button
          onClick={() => navigate(`/alerts/${alert.id}`)}
          className="w-full flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
          style={{ height: "44px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", borderRadius: "var(--radius)", border: "none", cursor: "pointer" }}
        >
          View Full Details
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}

// ── Alert List Panel ──────────────────────────────────────────────────────────
function AlertListPanel({
  mode, setMode, filtered, expandedId, setExpandedId, selectedIds, setSelectedIds,
  toggleSelect, search, setSearch, severityFilter, setSeverityFilter,
  statusFilter, setStatusFilter, activeFilters, onSelectAlert, selectedAlertId, isPanel, alerts,
  threatStatus,
}: {
  mode: Mode;
  setMode: (m: Mode) => void;
  filtered: AlertView[];
  expandedId: string | null;
  setExpandedId: (id: string | null) => void;
  selectedIds: Set<string>;
  setSelectedIds: (s: Set<string>) => void;
  toggleSelect: (id: string) => void;
  search: string;
  setSearch: (s: string) => void;
  severityFilter: SeverityFilter;
  setSeverityFilter: (f: SeverityFilter) => void;
  statusFilter: StatusFilter;
  setStatusFilter: (f: StatusFilter) => void;
  activeFilters: string[];
  onSelectAlert?: (id: string) => void;
  selectedAlertId?: string | null;
  isPanel?: boolean;
  alerts: AlertView[];
  threatStatus?: ThreatStatus | null;
}) {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className={`flex items-center justify-between border-b border-border flex-shrink-0 md:h-[72px] md:py-0 ${isPanel ? "px-5 pt-5 pb-3" : "px-4 pt-5 pb-3"}`}>
        <div>
          <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Alerts</h2>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            {alerts.filter((a: any) => !a.archived).length} active events
          </p>
        </div>
      </div>

      {/* Scrollable content — everything below the pinned header scrolls
          together, so the alert list keeps full height on short viewports. */}
      <div className="flex-1 overflow-y-auto flex flex-col">

      {/* AI Threat Intelligence */}
      <div className={`border-b border-border flex-shrink-0 ${isPanel ? "px-5 py-4" : "px-4 py-4"}`} style={{ backgroundColor: "var(--card)" }}>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
          AI Threat Intelligence
        </p>
        <div className="grid grid-cols-2 gap-2">
          {[
            { label: "Threat Score", value: "34", color: "var(--destructive)", note: "Critical" },
            { label: "IDS Alerts", value: threatStatus ? String(threatStatus.alert_count) : "12", color: "var(--destructive)", note: threatStatus ? "Guardian" : "+4 from yesterday" },
            { label: "Blocked", value: threatStatus ? String(threatStatus.block_count) : "47", color: "var(--chart-2)", note: threatStatus ? "Active blocks" : "Auto-blocked" },
            { label: "Quarantined", value: "3", color: "var(--chart-4)", note: "Pending review" },
          ].map(({ label, value, color, note }) => (
            <div key={label} className="rounded-lg p-3" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "22px", fontWeight: 700, color, lineHeight: 1, display: "block", marginBottom: "2px" }}>{value}</span>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", fontWeight: "var(--font-weight-medium)", display: "block" }}>{label}</span>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", display: "block" }}>{note}</span>
            </div>
          ))}
        </div>
      </div>


      {/* Controls row */}
      <div className={`flex items-center justify-between pt-3 pb-2 flex-shrink-0 ${isPanel ? "px-5" : "px-4"}`}>
        <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
          {mode === "archived" ? "Archived" : "Recent Events"}{" "}
          <span style={{ color: "var(--muted-foreground)", fontWeight: "var(--font-weight-normal)" }}>({filtered.length})</span>
        </h2>
        <div className="flex items-center gap-2">
          {mode !== "bulk" ? (
            <>
              <button onClick={() => setMode(mode === "archived" ? "active" : "archived")}
                className="flex items-center gap-1 px-2 py-1 rounded"
                style={{ border: "1px solid var(--border)", backgroundColor: "var(--muted)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", cursor: "pointer", borderRadius: "var(--radius-sm)" }}>
                <Archive size={12} />{mode === "archived" ? "Active" : "Archived"}
              </button>
              <button onClick={() => setMode("bulk")}
                className="flex items-center gap-1 px-2 py-1 rounded"
                style={{ border: "1px solid var(--border)", backgroundColor: "var(--muted)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", cursor: "pointer", borderRadius: "var(--radius-sm)" }}>
                <CheckSquare size={12} />Select
              </button>
            </>
          ) : (
            <button onClick={() => { setMode("active"); setSelectedIds(new Set()); }}
              style={{ background: "none", border: "none", cursor: "pointer", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}>
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Search */}
      <div className={`pb-2 flex-shrink-0 ${isPanel ? "px-5" : "px-4"}`}>
        <div className="relative">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "var(--muted-foreground)" }} />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search alerts..."
            className="w-full pl-9 pr-4 outline-none"
            style={{ height: "40px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" }}
          />
        </div>
      </div>

      {/* Filters */}
      <div className={`pb-3 flex items-center gap-2 flex-shrink-0 ${isPanel ? "px-5" : "px-4"}`}>
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
          className="outline-none flex-1"
          style={{ height: "34px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", padding: "0 8px", cursor: "pointer" }}>
          <option value="ALL">All Severities</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
          className="outline-none flex-1"
          style={{ height: "34px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", padding: "0 8px", cursor: "pointer" }}>
          <option value="ALL">All Statuses</option>
          <option value="Active">Active</option>
          <option value="Acknowledged">Acknowledged</option>
          <option value="Blocked">Blocked</option>
        </select>
      </div>

      {/* Filter chips */}
      {activeFilters.length > 0 && (
        <div className={`pb-3 flex items-center gap-2 flex-wrap flex-shrink-0 ${isPanel ? "px-5" : "px-4"}`}>
          {activeFilters.map((f) => (
            <span key={f} className="flex items-center gap-1 px-2 py-1 rounded-full"
              style={{ backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}>
              {f}
              <button onClick={() => { if (f === severityFilter) setSeverityFilter("ALL"); else setStatusFilter("ALL"); }} style={{ background: "none", border: "none", cursor: "pointer", padding: 0, lineHeight: 0 }}>
                <X size={11} style={{ color: "var(--primary)" }} />
              </button>
            </span>
          ))}
          <button onClick={() => { setSeverityFilter("ALL"); setStatusFilter("ALL"); }} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", background: "none", border: "none", cursor: "pointer", textDecoration: "underline" }}>
            Clear all
          </button>
        </div>
      )}

      {/* Bulk select all */}
      {mode === "bulk" && (
        <button className={`flex items-center gap-3 py-3 border-b border-border w-full transition-opacity active:opacity-70 flex-shrink-0 ${isPanel ? "px-5" : "px-4"}`}
          style={{ backgroundColor: "var(--muted)", border: "none", cursor: "pointer" }}
          onClick={() => { if (selectedIds.size === filtered.length) setSelectedIds(new Set()); else setSelectedIds(new Set(filtered.map((a) => a.id))); }}>
          {selectedIds.size === filtered.length ? <CheckSquare size={18} style={{ color: "var(--primary)" }} /> : <Square size={18} style={{ color: "var(--muted-foreground)" }} />}
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>Select All ({filtered.length})</span>
        </button>
      )}

      {/* Alert list */}
      <div className="flex-1">
        {filtered.length === 0 ? (
          mode === "archived"
            ? <EmptyState icon={Shield} heading="No archived alerts" subtext="Archived alerts will appear here." />
            : <EmptyState icon={Shield} heading="Your network looks clean" subtext="No active security events detected." />
        ) : (
          <div className="pb-4">
            {filtered.map((alert) => {
              const isExpanded = expandedId === alert.id;
              const isSelected = selectedIds.has(alert.id);
              const isHighlighted = selectedAlertId === alert.id;
              return (
                <div key={alert.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <div
                    className="flex items-start gap-3 py-3.5 transition-colors"
                    style={{
                      padding: isPanel ? "14px 20px" : "14px 16px",
                      cursor: "pointer",
                      backgroundColor: isHighlighted ? "color-mix(in srgb, var(--primary) 8%, transparent)" : undefined,
                      borderLeft: isHighlighted ? "3px solid var(--primary)" : "3px solid transparent",
                    }}
                    onClick={() => {
                      if (mode === "bulk") toggleSelect(alert.id);
                      else if (onSelectAlert) onSelectAlert(alert.id);
                      else setExpandedId(isExpanded ? null : alert.id);
                    }}
                  >
                    {mode === "bulk" && (
                      <div className="flex-shrink-0 mt-0.5">
                        {isSelected ? <CheckSquare size={18} style={{ color: "var(--primary)" }} /> : <Square size={18} style={{ color: "var(--muted-foreground)" }} />}
                      </div>
                    )}
                    <Clock size={14} style={{ color: "var(--muted-foreground)", marginTop: "3px", flexShrink: 0 }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-2">
                        <span className={`flex-1 ${isPanel ? "" : "truncate"}`} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                          {guardianAlertHeading(alert.title)}
                        </span>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <SeverityBadge severity={alert.severity} />
                          {!onSelectAlert && (!isExpanded ? <ChevronRight size={14} style={{ color: "var(--muted-foreground)" }} /> : <ChevronDown size={14} style={{ color: "var(--muted-foreground)" }} />)}
                          {onSelectAlert && <ChevronRight size={14} style={{ color: "var(--muted-foreground)" }} />}
                        </div>
                      </div>
                      <p className="line-clamp-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {alert.description}
                      </p>
                      <div className="flex items-center gap-2 mt-1.5">
                        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>{alert.timestamp}</span>
                      </div>
                    </div>
                    {mode !== "bulk" && (
                      <button onClick={(e) => { e.stopPropagation(); toast.success("Alert archived"); }} style={{ background: "none", border: "none", cursor: "pointer", padding: "4px", flexShrink: 0 }}>
                        <Trash2 size={15} style={{ color: "var(--muted-foreground)" }} />
                      </button>
                    )}
                  </div>

                  {/* Mobile inline expand */}
                  {isExpanded && mode !== "bulk" && !onSelectAlert && (
                    <div className="px-4 pb-4 pt-1" style={{ borderTop: "1px solid var(--border)", backgroundColor: "color-mix(in srgb, var(--primary) 4%, var(--background))" }}>
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-2">
                            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Event Type</span>
                            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{alert.eventType}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Status</span>
                            <StatusBadge status={alert.status} variant={alert.status === "Active" ? "danger" : alert.status === "Blocked" ? "warning" : "muted"} />
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button onClick={() => navigate(`/alerts/${alert.id}`)} className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80"
                          style={{ height: "38px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", borderRadius: "var(--radius)", border: "none", cursor: "pointer" }}>
                          View Full Details
                        </button>
                        <button className="px-3 rounded-md transition-opacity active:opacity-80"
                          style={{ height: "38px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)" }}>
                          Archive
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
      </div>
      {/* end scrollable content */}

      {/* Bulk action bar */}
      {mode === "bulk" && (
        <div className="border-t border-border flex items-center gap-3 px-4 py-4 flex-shrink-0" style={{ backgroundColor: "var(--card)" }}>
          <button className="flex-1 flex items-center justify-center gap-2 rounded-md"
            style={{ height: "44px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)" }}
            onClick={() => { if (selectedIds.size === 0) return; toast.success(`${selectedIds.size} alert${selectedIds.size > 1 ? "s" : ""} archived`); setSelectedIds(new Set()); setMode("active"); }}>
            <Archive size={15} /> Archive ({selectedIds.size})
          </button>
          <button className="flex-1 flex items-center justify-center gap-2 rounded-md"
            style={{ height: "44px", backgroundColor: "color-mix(in srgb, var(--destructive) 15%, transparent)", color: "var(--destructive)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", border: "1px solid color-mix(in srgb, var(--destructive) 30%, transparent)", cursor: "pointer", borderRadius: "var(--radius)" }}
            onClick={() => { if (selectedIds.size === 0) return; toast.success(`${selectedIds.size} alert${selectedIds.size > 1 ? "s" : ""} deleted`); setSelectedIds(new Set()); setMode("active"); }}>
            <Trash2 size={15} /> Delete ({selectedIds.size})
          </button>
        </div>
      )}
    </div>
  );
}

// ── Main exported component ───────────────────────────────────────────────────
export function AL01AlertsList() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>("active");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("ALL");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  // Top-level view: alert list, live topology, and the Suricata Threat Protection panel.
  const [mainView, setMainView] = useState<"list" | "topology" | "threat">("list");

  // Fetch alerts from API with fallback to mock data
  const { data: alertsData, loading } = useAlerts();
  // Suricata IDS status feeds the intel card + the Threat Protection tab indicator.
  const { data: threatStatus } = useThreatStatus();
  const suricataActive = threatStatus?.suricata?.toLowerCase() === "active";

  const alerts = useMemo(() => {
    return (alertsData?.alerts ?? []) as AlertView[];
  }, [alertsData]);

  const baseAlerts = useMemo(() => {
    return mode === "archived" ? alerts.filter((a: any) => a.archived) : alerts.filter((a: any) => !a.archived);
  }, [mode, alerts]);

  const filtered = useMemo(() => {
    return baseAlerts.filter((a: any) => {
      const matchSearch = !search || a.title.toLowerCase().includes(search.toLowerCase()) || a.device.toLowerCase().includes(search.toLowerCase());
      const matchSeverity = severityFilter === "ALL" || a.severity === severityFilter;
      const matchStatus = statusFilter === "ALL" || a.status === statusFilter;
      return matchSearch && matchSeverity && matchStatus;
    });
  }, [baseAlerts, search, severityFilter, statusFilter]);

  const activeFilters = useMemo(() => [
    ...(severityFilter !== "ALL" ? [severityFilter] : []),
    ...(statusFilter !== "ALL" ? [statusFilter] : []),
  ], [severityFilter, statusFilter]);

  const toggleSelect = (id: string) => {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id); else next.add(id);
    setSelectedIds(next);
  };

  const selectedAlert = useMemo(() => {
    return selectedAlertId ? alerts.find((a: any) => a.id === selectedAlertId) : null;
  }, [selectedAlertId, alerts]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full p-8">
        <Loader2 className="w-8 h-8 animate-spin" style={{ color: "var(--primary)" }} />
      </div>
    );
  }

  const listProps = {
    mode, setMode, filtered, expandedId, setExpandedId, selectedIds, setSelectedIds,
    toggleSelect, search, setSearch, severityFilter, setSeverityFilter,
    statusFilter, setStatusFilter, activeFilters, alerts,
    threatStatus,
  };

  const MAIN_TABS: { key: "list" | "topology" | "threat"; label: string }[] = [
    { key: "list", label: "Alert List" },
    { key: "topology", label: "Live Attack Topology" },
    { key: "threat", label: "Threat Protection" },
  ];

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Alerts workspace tabs */}
      <div className="flex-shrink-0 border-b border-border px-4 md:px-5 py-2.5">
        <div className="inline-flex items-center gap-1 p-1 rounded-lg" style={{ backgroundColor: "var(--muted)" }}>
          {MAIN_TABS.map((t) => {
            const active = mainView === t.key;
            return (
              <button
                key={t.key}
                onClick={() => setMainView(t.key)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md"
                style={{
                  backgroundColor: active ? "var(--card)" : "transparent",
                  color: active ? "var(--foreground)" : "var(--muted-foreground)",
                  border: active ? "1px solid var(--border)" : "1px solid transparent",
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                {t.key === "topology" && (
                  <Network size={13} style={{ color: active ? "var(--primary)" : "var(--muted-foreground)" }} />
                )}
                {t.key === "threat" && (
                  <Shield size={13} style={{ color: active ? "var(--primary)" : "var(--muted-foreground)" }} />
                )}
                {t.label}
                {t.key === "threat" && threatStatus && (
                  <span title={`Guardian ${threatStatus.suricata}`} style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: suricataActive ? "var(--chart-2)" : "var(--muted-foreground)", display: "inline-block" }} />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Content */}
      {mainView === "threat" ? (
        <div className="flex-1 min-h-0">
          <ThreatProtectionPanel />
        </div>
      ) : mainView === "topology" ? (
        <div className="flex-1 min-h-0">
          <AL09LiveAttackTopology />
        </div>
      ) : (
      <div className="flex-1 min-h-0">
      {/* ── Mobile: single column, navigate to detail ── */}
      <div className="md:hidden flex flex-col h-full">
        <AlertListPanel {...listProps} onSelectAlert={(id) => navigate(`/alerts/${id}`)} />
      </div>

      {/* ── Tablet: 40/60 split ── */}
      <div className="hidden md:flex lg:hidden" style={{ height: "100%", overflow: "hidden" }}>
        {/* Left panel 40% */}
        <div style={{ width: "40%", borderRight: "1px solid var(--border)", overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <AlertListPanel {...listProps} isPanel onSelectAlert={(id) => setSelectedAlertId(id)} selectedAlertId={selectedAlertId} />
        </div>
        {/* Right panel 60% */}
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          {selectedAlert ? (
            <AlertDetailPanel alert={selectedAlert} onClose={() => setSelectedAlertId(null)} />
          ) : (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-8">
              <div className="rounded-full flex items-center justify-center" style={{ width: "64px", height: "64px", backgroundColor: "var(--muted)" }}>
                <AlertTriangle size={28} style={{ color: "var(--muted-foreground)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Select an alert to view details</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "260px", lineHeight: 1.6 }}>
                Click any alert from the list to see the full analysis and recommended actions here.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── Desktop: 35/65 split ── */}
      <div className="hidden lg:flex" style={{ height: "100%", overflow: "hidden" }}>
        {/* Left panel 35% */}
        <div style={{ width: "35%", borderRight: "1px solid var(--border)", overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <AlertListPanel {...listProps} isPanel onSelectAlert={(id) => setSelectedAlertId(id)} selectedAlertId={selectedAlertId} />
        </div>
        {/* Right panel 65% */}
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          {selectedAlert ? (
            <AlertDetailPanel alert={selectedAlert} onClose={() => setSelectedAlertId(null)} />
          ) : (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-12">
              <div className="rounded-full flex items-center justify-center" style={{ width: "72px", height: "72px", backgroundColor: "var(--muted)" }}>
                <AlertTriangle size={32} style={{ color: "var(--muted-foreground)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Select an alert to view details</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "300px", lineHeight: 1.6 }}>
                Click any alert from the list to see full AI analysis and take action inline — no navigation needed.
              </p>
            </div>
          )}
        </div>
      </div>
      </div>
      )}
    </div>
  );
}
