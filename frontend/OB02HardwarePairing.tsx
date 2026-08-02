import { useState, useMemo } from "react";
import { useNavigate } from "react-router";
import {
  Clock, ChevronRight, ChevronDown, Trash2, Search, Shield, Archive,
  CheckSquare, Square, X, AlertTriangle, Ban, Scan, Monitor, Brain, Loader2, Network,
} from "lucide-react";
import { mockAlerts } from "../../data/mockData";
import { useAlerts, useThreatStatus } from "../../hooks/useApiData";
import type { ThreatStatus } from "../../services/threatService";
import { ThreatProtectionPanel } from "./AL08ThreatProtection";
import { AL09LiveAttackTopology } from "./AL09LiveAttackTopology";
import { SeverityBadge, StatusBadge } from "../../components/SeverityBadge";
import { SkeletonCard } from "../../components/SkeletonBlock";
import { EmptyState } from "../../components/EmptyState";
import { toast } from "sonner";

type Mode = "active" | "archived" | "bulk";
type SeverityFilter = "ALL" | "HIGH" | "MEDIUM" | "LOW";
type StatusFilter = "ALL" | "Active" | "Acknowledged" | "Blocked";

// ── Alert Detail Panel (inline for tablet/desktop) ────────────────────────────
function AlertDetailPanel({ alert, onClose }: { alert: typeof mockAlerts[0]; onClose: () => void }) {
  const navigate = useNavigate();
  const accentColor = alert.severity === "HIGH" ? "var(--destructive)" : alert.severity === "MEDIUM" ? "var(--chart-5)" : "var(--chart-2)";

  const statusVariant = alert.status === "Active" ? "danger" : alert.status === "Blocked" ? "warning" : "muted";
  const sectionLabel = { fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" } as const;

  const details = [
    { label: "Device", value: alert.device },
    { label: "IP Address", value: alert.deviceIp, mono: true },
    { label: "Event Type", value: alert.eventType },
    { label: "OS", value: alert.os },
  ];

  const actions = [
    { icon: Ban, label: "Block Device", desc: "Revoke network access immediately", color: "var(--destructive)" },
    { icon: Scan, label: "Run Security Scan", desc: "Full scan on the affected device", color: "var(--primary)" },
    { icon: Monitor, label: "View Affected Device", desc: "Open the device's details", color: "var(--chart-2)" },
    { icon: Archive, label: "Archive Event", desc: "Mark as reviewed", color: "var(--muted-foreground)" },
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
            {alert.title}
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
              Active threat — immediate action recommended
            </span>
          </div>
        )}

        {/* Details grid */}
        <div>
          <p style={sectionLabel}>Details</p>
          <div className="grid grid-cols-2 rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
            {details.map((row, i) => (
              <div key={row.label} className="px-4 py-3 min-w-0" style={{ borderRight: i % 2 === 0 ? "1px solid var(--border)" : undefined, borderBottom: i < 2 ? "1px solid var(--border)" : undefined }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", fontWeight: "var(--font-weight-medium)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{row.label}</p>
                <p style={{ fontFamily: row.mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", fontWeight: "var(--font-weight-medium)", marginTop: "2px", wordBreak: "break-word" }}>{row.value}</p>
              </div>
            ))}
          </div>
        </div>

        {/* AI Summary */}
        <div className="rounded-lg border p-4" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}>
          <div className="flex items-center gap-2 mb-2">
            <Brain size={14} style={{ color: "var(--primary)" }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em" }}>
              AI Analysis
            </span>
          </div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.65 }}>
            {alert.aiSummary}
          </p>
        </div>

        {/* Recommended actions */}
        <div>
          <p style={sectionLabel}>Recommended Actions</p>
          <div className="flex flex-col gap-2">
            {actions.map(({ icon: Icon, label, desc, color }) => (
              <button
                key={label}
                onClick={() => toast.success(`${label} — action initiated`)}
                className="flex items-center gap-3 p-3 rounded-lg text-left transition-colors"
                style={{ backgroundColor: "var(--card)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)" }}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = `color-mix(in srgb, ${color} 45%, var(--border))`; }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
              >
                <div className="flex items-center justify-center rounded-md flex-shrink-0" style={{ width: "36px", height: "36px", backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)` }}>
                  <Icon size={16} style={{ color }} />
                </div>
                <div className="flex-1 min-w-0">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{label}</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{desc}</p>
                </div>
                <ChevronRight size={16} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
              </button>
            ))}
          </div>
        </div>
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
  filtered: typeof mockAlerts;
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
  alerts: typeof mockAlerts;
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
            { label: "IDS Alerts", value: threatStatus ? String(threatStatus.alert_count) : "12", color: "var(--destructive)", note: threatStatus ? "Suricata" : "+4 from yesterday" },
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
                          {alert.title}
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
    if (!alertsData) return mockAlerts;
    return alertsData.alerts || mockAlerts;
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
                  <span title={`Suricata ${threatStatus.suricata}`} style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: suricataActive ? "var(--chart-2)" : "var(--muted-foreground)", display: "inline-block" }} />
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