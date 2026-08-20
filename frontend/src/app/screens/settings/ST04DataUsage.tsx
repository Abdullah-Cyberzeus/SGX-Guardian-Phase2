import { useState, ReactNode } from "react";
import { toast } from "sonner";
import {
  Loader2, AlertTriangle, RotateCcw, Pencil, Check, X,
  BarChart2, Network, History, Gauge, CheckCircle2,
} from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { useDusageCurrent, useDusageHistory, useDusageQuota } from "../../hooks/useApiData";
import { dusageService } from "../../services/dusageService";
import { guardianDisplayText } from "../../utils/displayText";

function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / Math.pow(1024, i);
  return `${i === 0 ? value : value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

const bandColor: Record<string, string> = {
  red: "var(--destructive)",
  amber: "var(--chart-5)",
  green: "var(--chart-2)",
  none: "var(--chart-2)",
};

const bandLabel: Record<string, string> = {
  red: "High usage",
  amber: "Moderate usage",
  green: "Normal usage",
  none: "Monitoring only",
};

function formatDate(iso?: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
}

function formatDateTime(iso?: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

function SectionCard({ title, titleColor, icon: Icon, right, divider, children }: { title: string; titleColor?: string; icon?: typeof BarChart2; right?: ReactNode; divider?: boolean; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
      <div className="flex items-center justify-between" style={{ marginBottom: "12px" }}>
        <div className="flex items-center gap-1.5">
          {Icon && <Icon size={13} style={{ color: titleColor || "var(--muted-foreground)" }} />}
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: titleColor || "var(--muted-foreground)", letterSpacing: "0.08em" }}>{title}</p>
        </div>
        {right}
      </div>
      {divider && <div style={{ borderBottom: "1px solid var(--border)", margin: "-12px -16px 12px" }} />}
      {children}
    </div>
  );
}

function UsageRing({ pct, color, muted, size = 128, stroke = 12 }: { pct: number; color: string; muted?: boolean; size?: number; stroke?: number }) {
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  return (
    <div className="relative flex-shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--muted)" strokeWidth={stroke} />
        {!muted && (
          <circle
            cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke}
            strokeLinecap="round" strokeDasharray={`${(pct / 100) * circ} ${circ}`}
            style={{ transition: "stroke-dasharray 0.6s ease" }}
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: Math.round(size * 0.22), fontWeight: "var(--font-weight-semibold)", color: muted ? "var(--muted-foreground)" : "var(--foreground)", lineHeight: 1 }}>
          {muted ? "—" : `${Math.round(pct)}%`}
        </span>
      </div>
    </div>
  );
}

function Row({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div className="grid items-baseline gap-3" style={{ gridTemplateColumns: "1fr auto" }}>
      <span className="truncate" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{label}</span>
      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: valueColor || "var(--foreground)", textAlign: "right", whiteSpace: "nowrap" }}>{value}</span>
    </div>
  );
}

export function ST04DataUsage() {
  const { data: current, loading, error, refetch } = useDusageCurrent();
  const { data: history, refetch: refetchHistory } = useDusageHistory();
  const { data: quotaInfo, refetch: refetchQuotaInfo } = useDusageQuota();
  const [resetting, setResetting] = useState(false);
  const [lastReset, setLastReset] = useState<{ status: string; at: Date } | null>(null);
  const [editingQuota, setEditingQuota] = useState(false);
  const [quotaInput, setQuotaInput] = useState("");
  const [savingQuota, setSavingQuota] = useState(false);

  const handleReset = async () => {
    if (!window.confirm("Reset the current period's usage counters to zero?")) return;
    setResetting(true);
    try {
      const result = await dusageService.reset();
      setLastReset({ status: result.status, at: new Date() });
      toast.success("Usage counters reset");
      await Promise.all([refetch(), refetchHistory(), refetchQuotaInfo()]);
    } catch (cause) {
      toast.error("Reset failed", { description: cause instanceof Error ? cause.message : "Please try again." });
    } finally {
      setResetting(false);
    }
  };

  const startEditQuota = () => {
    setQuotaInput(current?.quota_bytes ? String(Math.round(current.quota_bytes / (1024 * 1024))) : "");
    setEditingQuota(true);
  };

  const saveQuota = async () => {
    const mb = Number(quotaInput);
    if (!Number.isFinite(mb) || mb < 0) {
      toast.error("Enter a valid quota in MB");
      return;
    }
    setSavingQuota(true);
    try {
      await dusageService.putQuota(Math.round(mb * 1024 * 1024), current?.period || "monthly");
      toast.success("Quota updated");
      setEditingQuota(false);
      await Promise.all([refetch(), refetchQuotaInfo()]);
    } catch (cause) {
      toast.error("Could not update quota", { description: cause instanceof Error ? cause.message : "Please try again." });
    } finally {
      setSavingQuota(false);
    }
  };

  if (loading && !current) {
    return <div className="flex h-full items-center justify-center gap-2 text-sm text-muted-foreground"><Loader2 size={20} className="animate-spin" /> Loading data usage…</div>;
  }
  if (error || !current) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
        <AlertTriangle size={28} className="text-destructive" />
        <p className="text-sm font-semibold">Data usage could not be loaded</p>
        <p className="max-w-sm text-xs text-muted-foreground">{error?.message || "This device did not return a usage snapshot."}</p>
        <button onClick={() => void refetch()} className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground">Retry</button>
      </div>
    );
  }

  const hasQuota = current.quota_bytes != null && current.quota_bytes > 0;
  const pct = current.used_pct != null ? Math.min(100, Math.round(current.used_pct)) : 0;
  const barColor = bandColor[current.usage_band] || bandColor.none;
  const pastPeriods = (history || []).slice(-6).reverse();

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Data Usage"
        titleColor="var(--primary)"
        subtitle={`${current.period.charAt(0).toUpperCase() + current.period.slice(1)} period · since ${formatDate(current.period_start)}`}
        subtitleColor="var(--foreground)"
        right={
          <div className="flex flex-col items-end gap-1">
            <button
              onClick={() => void handleReset()}
              disabled={resetting}
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-muted disabled:opacity-50"
              style={{ color: "var(--primary)" }}
            >
              {resetting ? <Loader2 size={14} className="animate-spin" /> : <RotateCcw size={14} />} Reset
            </button>
            {lastReset && (
              <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
                <CheckCircle2 size={11} style={{ color: "var(--chart-2)" }} /> {lastReset.status} · {lastReset.at.toLocaleTimeString()}
              </span>
            )}
          </div>
        }
      />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-6xl p-4 md:p-6 flex flex-col gap-4">
          <div className="flex flex-col lg:flex-row gap-4 lg:items-stretch">

          {/* Side panel — API 1's totals + API 3's quota record, the fields the ring itself represents.
              Stretches to match the main column's height so it fills its space instead of leaving a gap below the card. */}
          <div className="w-full lg:w-[340px] lg:flex-shrink-0 lg:sticky lg:top-6 lg:order-2 flex flex-col">
            <div className="rounded-xl border overflow-hidden flex flex-1 flex-col" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
              <div style={{ height: "3px", backgroundColor: hasQuota ? barColor : "var(--border)", flexShrink: 0 }} />
              <div className="flex items-center gap-1.5 px-5 pt-4" style={{ flexShrink: 0 }}>
                <BarChart2 size={14} style={{ color: "var(--foreground)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", letterSpacing: "0.08em" }}>Usage Overview</span>
              </div>

              <div
                className="flex flex-1 flex-col items-center justify-center gap-3 px-5 py-7"
                style={{ background: `radial-gradient(circle at 50% 45%, color-mix(in srgb, ${barColor} 16%, transparent), transparent 72%)`, minHeight: "220px" }}
              >
                <UsageRing pct={hasQuota ? pct : 0} color={barColor} muted={!hasQuota} size={192} stroke={16} />
                <div className="text-center">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: hasQuota ? barColor : "var(--muted-foreground)" }}>
                    {bandLabel[current.usage_band] || current.usage_band}
                  </p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
                    {formatBytes(current.total_bytes)} used{hasQuota ? ` of ${formatBytes(current.quota_bytes as number)}` : " · no quota set"}
                  </p>
                </div>
              </div>

              <div className="px-5 pb-5 pt-4 flex flex-col gap-2" style={{ borderTop: "1px solid var(--border)", flexShrink: 0 }}>
                <div className="flex items-center gap-1.5">
                  <Gauge size={12} style={{ color: "var(--primary)" }} />
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em" }}>Quota Record</span>
                </div>
                <Row label="Period type" value={quotaInfo?.period || current.period} valueColor="var(--chart-2)" />
                <Row label="Revision" value={quotaInfo ? `#${quotaInfo.sequence}` : "—"} valueColor="var(--chart-2)" />
                {editingQuota ? (
                  <div className="flex items-center gap-2 mt-1">
                    <input
                      type="number"
                      min={0}
                      autoFocus
                      value={quotaInput}
                      onChange={(event) => setQuotaInput(event.target.value)}
                      placeholder="Quota in MB"
                      className="flex-1 rounded-md border border-border bg-transparent px-2 py-1.5 text-sm"
                    />
                    <button onClick={() => void saveQuota()} disabled={savingQuota} aria-label="Save quota" className="grid h-8 w-8 place-items-center rounded-md border border-border hover:bg-muted disabled:opacity-50">
                      {savingQuota ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
                    </button>
                    <button onClick={() => setEditingQuota(false)} disabled={savingQuota} aria-label="Cancel" className="grid h-8 w-8 place-items-center rounded-md border border-border hover:bg-muted disabled:opacity-50">
                      <X size={14} />
                    </button>
                  </div>
                ) : (
                  <button onClick={startEditQuota} className="flex items-center gap-1.5 self-start text-xs font-medium mt-1" style={{ color: "var(--primary)" }}>
                    <Pencil size={12} /> {hasQuota ? "Edit quota" : "Set a quota"}
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Main column — every other API's data stays on the left, where it already was */}
          <div className="flex-1 min-w-0 flex flex-col gap-4 lg:order-1">
            {/* API 1's interfaces[] — one card per actual interface with its rx/tx detail */}
            <SectionCard title="Network Interfaces" titleColor="var(--primary)" icon={Network}>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {current.interfaces.map((iface) => (
                  <div key={iface.iface} className="rounded-lg border p-3 flex flex-col items-center" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
                    <Network size={18} style={{ color: "var(--primary)", marginBottom: "8px" }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{guardianDisplayText(iface.iface)}</p>
                    <div className="flex items-center gap-1.5" style={{ marginTop: "6px" }}>
                      <span style={{ color: "var(--chart-4)", fontSize: "var(--text-xs)" }}>↓</span>
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--chart-2)", minWidth: "48px", textAlign: "left" }}>{formatBytes(iface.rx_bytes)}</span>
                    </div>
                    <div className="flex items-center gap-1.5" style={{ marginTop: "2px" }}>
                      <span style={{ color: "var(--chart-4)", fontSize: "var(--text-xs)" }}>↑</span>
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--chart-2)", minWidth: "48px", textAlign: "left" }}>{formatBytes(iface.tx_bytes)}</span>
                    </div>
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
                <div className="rounded-lg p-3" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Usage details</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-2)", marginTop: "2px" }}>
                    {formatDate(current.period_start)} · {formatBytes(current.total_bytes)} total
                  </p>
                </div>
                <div className="rounded-lg p-3" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Sampled</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-2)", marginTop: "2px" }}>
                    {formatDateTime(current.sampled_at)}
                  </p>
                </div>
              </div>
            </SectionCard>

            {/* API 2 (GET /dusage/history) — each entry is a full UsageSnapshot, tap to see the same detail */}
            {pastPeriods.length > 0 && (
              <SectionCard title="Past Periods" titleColor="var(--primary)" icon={History} divider>
                <div className="flex flex-col gap-1">
                  {pastPeriods.map((snapshot) => (
                    <div
                      key={snapshot.period_start}
                      className="flex items-center justify-between rounded-md py-1.5 -mx-1 px-1"
                    >
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{formatDate(snapshot.period_start)}</span>
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{formatBytes(snapshot.total_bytes)}</span>
                    </div>
                  ))}
                </div>
              </SectionCard>
            )}
          </div>
          </div>
        </div>
      </div>
    </div>
  );
}
