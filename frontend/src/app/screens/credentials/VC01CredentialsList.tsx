import { useState, useMemo, useEffect, useRef } from "react";
import { PageHeader } from "../../components/PageHeader";
import {
  Award,
  CheckCircle2,
  XCircle,
  Loader2,
  ShieldCheck,
  RefreshCw,
  Trash2,
  Plus,
  Download,
  FileText,
  AlertTriangle,
  Clock,
  User,
  Hash,
  ChevronDown,
  ChevronUp,
  Eye,
  ListChecks,
  Users,
  HardDrive,
  Activity,
  History,
  Copy,
} from "lucide-react";
import {
  useVCShow,
  useVCFilesIssued,
  useVCFilesOwn,
  useVCFilesPeers,
  useVCSummary,
  useVCAudit,
  useVCStatusList,
} from "../../hooks/useApiData";
import { vcService } from "../../services/vcService";
import type { VcMetaItem, VcShowFilters } from "../../services/vcService";
import { toast } from "sonner";

// ── Helpers ────────────────────────────────────────────────────────────────────

function shortId(id: string) {
  return id.replace("urn:uuid:", "").slice(0, 8) + "…";
}

function shortDid(did: string) {
  if (did.length <= 20) return did;
  return did.slice(0, 16) + "…" + did.slice(-6);
}

function isExpired(expDate: string) {
  return new Date(expDate) < new Date();
}

function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  } catch {
    return iso;
  }
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function StatusBadge({ item }: { item: VcMetaItem }) {
  const expired = isExpired(item.expiration_date);
  const label = item.revoked ? "Revoked" : expired ? "Expired" : "Active";
  const color = item.revoked
    ? "var(--destructive)"
    : expired
    ? "var(--chart-4)"
    : "var(--chart-2)";
  const bg = item.revoked
    ? "color-mix(in srgb, var(--destructive) 12%, transparent)"
    : expired
    ? "color-mix(in srgb, var(--chart-4) 12%, transparent)"
    : "color-mix(in srgb, var(--chart-2) 12%, transparent)";
  const Icon = item.revoked ? XCircle : expired ? Clock : CheckCircle2;
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 flex-shrink-0 whitespace-nowrap"
      style={{
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        fontFamily: "Inter, sans-serif",
        color,
        backgroundColor: bg,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
      }}
    >
      <Icon size={10} />
      {label}
    </span>
  );
}

function RoleBadge({ role }: { role: string }) {
  const isOwner = role === "owner";
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 flex-shrink-0 whitespace-nowrap"
      style={{
        fontSize: "var(--text-xs)",
        fontFamily: "Inter, sans-serif",
        color: isOwner ? "var(--chart-5)" : "var(--muted-foreground)",
        backgroundColor: isOwner
          ? "color-mix(in srgb, var(--chart-5) 12%, transparent)"
          : "color-mix(in srgb, var(--muted-foreground) 10%, transparent)",
        border: `1px solid ${isOwner ? "color-mix(in srgb, var(--chart-5) 25%, transparent)" : "var(--border)"}`,
      }}
    >
      <User size={10} />
      {role}
    </span>
  );
}

function VcCard({
  item,
  onVerify,
  onRenew,
  onRevoke,
}: {
  item: VcMetaItem;
  onVerify: (id: string) => void;
  onRenew: (id: string) => void;
  onRevoke: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState<"verify" | "renew" | "revoke" | null>(null);

  const handleVerify = async () => {
    setBusy("verify");
    try { await onVerify(item.vc_id); } finally { setBusy(null); }
  };
  const handleRenew = async () => {
    setBusy("renew");
    try { await onRenew(item.vc_id); } finally { setBusy(null); }
  };
  const handleRevoke = async () => {
    setBusy("revoke");
    try { await onRevoke(item.vc_id); } finally { setBusy(null); }
  };

  const canRenew = !item.revoked;
  const canRevoke = !item.revoked;

  return (
    <div
      style={{
        background: "var(--card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        overflow: "hidden",
      }}
    >
      {/* Header row */}
      <div
        className="flex items-center justify-between gap-3 px-4 py-3 cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
        style={{ borderBottom: expanded ? "1px solid var(--border)" : "none" }}
      >
        <div className="flex items-center gap-2 min-w-0">
          <Award size={16} style={{ color: "var(--primary)", flexShrink: 0 }} />
          <span
            className="font-mono truncate"
            style={{ fontSize: "var(--text-xs)", color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace", minWidth: 0, flexShrink: 1 }}
            title={item.vc_id}
          >
            {shortId(item.vc_id)}
          </span>
          <StatusBadge item={item} />
          <RoleBadge role={item.role} />
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif" }}>
            {fmtDate(item.expiration_date)}
          </span>
          {expanded ? <ChevronUp size={14} style={{ color: "var(--muted-foreground)" }} /> : <ChevronDown size={14} style={{ color: "var(--muted-foreground)" }} />}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 py-3 flex flex-col gap-3">
          <div className="grid gap-2" style={{ gridTemplateColumns: "1fr 1fr" }}>
            {[
              { label: "Subject", value: shortDid(item.subject), mono: true },
              { label: "Issuer", value: shortDid(item.issuer), mono: true },
              { label: "Circle", value: item.circle_id },
              { label: "Status Index", value: item.status_list_index },
              { label: "Issued", value: fmtDate(item.issuance_date) },
              { label: "Expires", value: fmtDate(item.expiration_date) },
            ].map(({ label, value, mono }) => (
              <div key={label}>
                <div style={{ fontSize: "10px", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", marginBottom: "2px" }}>{label}</div>
                <div
                  style={{
                    fontSize: "var(--text-xs)",
                    color: "var(--foreground)",
                    fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
                    wordBreak: "break-all",
                  }}
                >
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            <ActionButton
              label="Verify"
              icon={<ShieldCheck size={12} />}
              busy={busy === "verify"}
              onClick={handleVerify}
              color="var(--chart-2)"
            />
            {canRenew && (
              <ActionButton
                label="Renew"
                icon={<RefreshCw size={12} />}
                busy={busy === "renew"}
                onClick={handleRenew}
                color="var(--chart-1)"
              />
            )}
            {canRevoke && (
              <ActionButton
                label="Revoke"
                icon={<Trash2 size={12} />}
                busy={busy === "revoke"}
                onClick={handleRevoke}
                color="var(--destructive)"
                destructive
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ActionButton({
  label,
  icon,
  busy,
  onClick,
  color,
  destructive = false,
}: {
  label: string;
  icon: React.ReactNode;
  busy: boolean;
  onClick: () => void;
  color: string;
  destructive?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className="flex items-center gap-1 rounded-md px-2.5 py-1"
      style={{
        fontSize: "var(--text-xs)",
        fontFamily: "Inter, sans-serif",
        fontWeight: "var(--font-weight-medium)",
        cursor: busy ? "not-allowed" : "pointer",
        opacity: busy ? 0.6 : 1,
        color: destructive ? "var(--destructive)" : color,
        backgroundColor: destructive
          ? "color-mix(in srgb, var(--destructive) 10%, transparent)"
          : `color-mix(in srgb, ${color} 10%, transparent)`,
        border: `1px solid ${destructive ? "color-mix(in srgb, var(--destructive) 25%, transparent)" : `color-mix(in srgb, ${color} 25%, transparent)`}`,
      }}
    >
      {busy ? <Loader2 size={12} className="animate-spin" /> : icon}
      {label}
    </button>
  );
}

// ── Issue VC Modal ─────────────────────────────────────────────────────────────

function IssueVcModal({ onClose, onIssued }: { onClose: () => void; onIssued: () => void }) {
  const [to, setTo] = useState("");
  const [role, setRole] = useState<"member" | "owner">("member");
  const [days, setDays] = useState("365");
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!to.trim()) { toast.error("Subject DID is required"); return; }
    const daysNum = parseInt(days, 10);
    if (isNaN(daysNum) || daysNum < 1 || daysNum > 3650) {
      toast.error("Days must be between 1 and 3650");
      return;
    }
    setBusy(true);
    try {
      const res = await vcService.issue({ to: to.trim(), role, days: daysNum });
      toast.success(res.reused ? "Reused existing active VC" : "VC issued successfully");
      onIssued();
      onClose();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to issue VC");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ backgroundColor: "rgba(0,0,0,0.5)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-2xl p-6 flex flex-col gap-4"
        style={{ background: "var(--card)", border: "1px solid var(--border)", maxHeight: "80vh", overflowY: "auto" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            Issue Verifiable Credential
          </h2>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)" }}>
            <XCircle size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", display: "block", marginBottom: "6px" }}>
              Subject DID *
            </label>
            <input
              value={to}
              onChange={(e) => setTo(e.target.value)}
              placeholder="did:guardian:z6Mk…"
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "var(--radius-md)",
                border: "1px solid var(--border)",
                background: "var(--input)",
                color: "var(--foreground)",
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "var(--text-xs)",
                outline: "none",
                boxSizing: "border-box",
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", display: "block", marginBottom: "6px" }}>
              Role
            </label>
            <div className="flex gap-2">
              {(["member", "owner"] as const).map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => setRole(r)}
                  style={{
                    flex: 1,
                    padding: "6px",
                    borderRadius: "var(--radius-md)",
                    border: "1px solid",
                    borderColor: role === r ? "var(--primary)" : "var(--border)",
                    background: role === r ? "color-mix(in srgb, var(--primary) 10%, transparent)" : "transparent",
                    color: role === r ? "var(--primary)" : "var(--muted-foreground)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-medium)",
                    cursor: "pointer",
                    textTransform: "capitalize",
                  }}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", display: "block", marginBottom: "6px" }}>
              Validity (days)
            </label>
            <input
              type="number"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              min={1}
              max={3650}
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "var(--radius-md)",
                border: "1px solid var(--border)",
                background: "var(--input)",
                color: "var(--foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                outline: "none",
                boxSizing: "border-box",
              }}
            />
          </div>

          <button
            type="submit"
            disabled={busy}
            className="flex items-center justify-center gap-2 rounded-lg py-2.5"
            style={{
              background: "var(--primary)",
              color: "var(--primary-foreground)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              border: "none",
              cursor: busy ? "not-allowed" : "pointer",
              opacity: busy ? 0.7 : 1,
            }}
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
            {busy ? "Issuing…" : "Issue Credential"}
          </button>
        </form>
      </div>
    </div>
  );
}

// ── Renew Modal ────────────────────────────────────────────────────────────────

function RenewModal({ vcId, onClose, onRenewed }: { vcId: string; onClose: () => void; onRenewed: () => void }) {
  const [days, setDays] = useState("90");
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const daysNum = parseInt(days, 10);
    if (isNaN(daysNum) || daysNum < 1 || daysNum > 3650) {
      toast.error("Days must be between 1 and 3650");
      return;
    }
    setBusy(true);
    try {
      const res = await vcService.renew({ id: vcId, days: daysNum });
      toast.success(`VC renewed until ${fmtDate(res.new_expiration)}`);
      onRenewed();
      onClose();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to renew VC");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ backgroundColor: "rgba(0,0,0,0.5)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-2xl p-6 flex flex-col gap-4"
        style={{ background: "var(--card)", border: "1px solid var(--border)" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            Renew Credential
          </h2>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)" }}>
            <XCircle size={18} />
          </button>
        </div>
        <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", wordBreak: "break-all" }}>
          ID: <span style={{ fontFamily: "JetBrains Mono, monospace" }}>{vcId}</span>
        </p>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", display: "block", marginBottom: "6px" }}>
              New validity from now (days)
            </label>
            <input
              type="number"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              min={1}
              max={3650}
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "var(--radius-md)",
                border: "1px solid var(--border)",
                background: "var(--input)",
                color: "var(--foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                outline: "none",
                boxSizing: "border-box",
              }}
            />
          </div>
          <button
            type="submit"
            disabled={busy}
            className="flex items-center justify-center gap-2 rounded-lg py-2.5"
            style={{
              background: "var(--primary)",
              color: "var(--primary-foreground)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              border: "none",
              cursor: busy ? "not-allowed" : "pointer",
              opacity: busy ? 0.7 : 1,
            }}
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
            {busy ? "Renewing…" : "Renew Credential"}
          </button>
        </form>
      </div>
    </div>
  );
}

// ── JSON Viewer Modal ──────────────────────────────────────────────────────────

function JsonViewerModal({
  title,
  data,
  onClose,
}: {
  title: string;
  data: unknown;
  onClose: () => void;
}) {
  const text = useMemo(() => JSON.stringify(data, null, 2), [data]);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Copy failed");
    }
  };
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: "rgba(0,0,0,0.5)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-3xl rounded-2xl flex flex-col"
        style={{
          background: "var(--card)",
          border: "1px solid var(--border)",
          maxHeight: "85vh",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between px-5 py-3 flex-shrink-0"
          style={{ borderBottom: "1px solid var(--border)" }}
        >
          <h2
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-base)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
            }}
          >
            {title}
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 rounded-md px-2 py-1"
              style={{
                fontSize: "var(--text-xs)",
                fontFamily: "Inter, sans-serif",
                color: "var(--muted-foreground)",
                background: "var(--muted)",
                border: "1px solid var(--border)",
                cursor: "pointer",
              }}
            >
              <Copy size={12} />
              Copy
            </button>
            <button
              onClick={onClose}
              style={{
                background: "none",
                border: "none",
                cursor: "pointer",
                color: "var(--muted-foreground)",
              }}
            >
              <XCircle size={18} />
            </button>
          </div>
        </div>
        <pre
          className="flex-1 overflow-auto px-5 py-4 m-0"
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "var(--text-xs)",
            color: "var(--foreground)",
            background: "var(--background)",
            borderBottomLeftRadius: "var(--radius-lg)",
            borderBottomRightRadius: "var(--radius-lg)",
            lineHeight: 1.6,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}
        >
          {text}
        </pre>
      </div>
    </div>
  );
}

// ── Summary Chip Strip ─────────────────────────────────────────────────────────

function SummaryStrip() {
  const { data, loading } = useVCSummary();
  if (loading && !data) {
    return (
      <div
        className="flex items-center justify-center px-4 py-3"
        style={{ borderBottom: "1px solid var(--border)" }}
      >
        <Loader2
          size={14}
          className="animate-spin"
          style={{ color: "var(--muted-foreground)" }}
        />
      </div>
    );
  }
  if (!data) return null;
  const chips: { label: string; value: number | string; color: string; icon: typeof Hash }[] = [
    { label: "Issued", value: data.issued_total, color: "var(--primary)", icon: FileText },
    { label: "Own", value: data.own_total, color: "var(--chart-1)", icon: HardDrive },
    { label: "Peers", value: data.peer_total, color: "var(--chart-3)", icon: Users },
    { label: "Active", value: data.active_total, color: "var(--chart-2)", icon: CheckCircle2 },
    { label: "Revoked", value: data.revoked_total, color: "var(--destructive)", icon: XCircle },
    { label: "Expired", value: data.expired_total, color: "var(--chart-4)", icon: Clock },
    { label: "Next Index", value: data.next_index, color: "var(--muted-foreground)", icon: ListChecks },
  ];
  return (
    <div
      className="flex items-center gap-2 overflow-x-auto px-4 py-2"
      style={{ borderBottom: "1px solid var(--border)" }}
    >
      {chips.map(({ label, value, color, icon: Icon }) => (
        <div
          key={label}
          className="flex items-center gap-1.5 flex-shrink-0 rounded-md px-2.5 py-1"
          style={{
            background: `color-mix(in srgb, ${color} 10%, transparent)`,
            border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
          }}
        >
          <Icon size={11} style={{ color }} />
          <span
            style={{
              fontSize: "10px",
              color: "var(--muted-foreground)",
              fontFamily: "Inter, sans-serif",
            }}
          >
            {label}
          </span>
          <strong
            style={{
              fontSize: "var(--text-xs)",
              color,
              fontFamily: "Inter, sans-serif",
            }}
          >
            {value}
          </strong>
        </div>
      ))}
    </div>
  );
}

// ── File row (own / peer / issued) with View Raw action ───────────────────────

function FileRow({
  item,
  onView,
}: {
  item: VcMetaItem;
  onView: () => void;
}) {
  return (
    <div
      className="flex items-center justify-between gap-3 rounded-xl px-4 py-3"
      style={{ background: "var(--card)", border: "1px solid var(--border)" }}
    >
      <div className="flex items-center gap-3 min-w-0 flex-1">
        <FileText
          size={14}
          style={{ color: "var(--primary)", flexShrink: 0 }}
        />
        <div className="min-w-0 flex-1">
          <div
            className="truncate"
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "var(--text-xs)",
              color: "var(--foreground)",
            }}
            title={item.vc_id}
          >
            {shortId(item.vc_id)}
          </div>
          <div
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "10px",
              color: "var(--muted-foreground)",
            }}
          >
            {shortDid(item.subject)} · {fmtDate(item.expiration_date)}
          </div>
        </div>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <StatusBadge item={item} />
        <RoleBadge role={item.role} />
        <button
          onClick={onView}
          className="flex items-center gap-1 rounded-md px-2 py-1"
          style={{
            fontSize: "var(--text-xs)",
            fontFamily: "Inter, sans-serif",
            color: "var(--primary)",
            background: "color-mix(in srgb, var(--primary) 10%, transparent)",
            border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)",
            cursor: "pointer",
          }}
        >
          <Eye size={11} />
          Raw
        </button>
      </div>
    </div>
  );
}

// ── Tabs ───────────────────────────────────────────────────────────────────────

type TabKey =
  | "credentials"
  | "issued-files"
  | "own-files"
  | "peer-files"
  | "status-list"
  | "audit";

const TABS: { key: TabKey; label: string; icon: typeof Award }[] = [
  { key: "credentials", label: "Credentials", icon: Award },
  { key: "issued-files", label: "Issued", icon: FileText },
  { key: "own-files", label: "Own", icon: HardDrive },
  { key: "peer-files", label: "Peers", icon: Users },
  { key: "status-list", label: "Status List", icon: ListChecks },
  { key: "audit", label: "Audit", icon: History },
];

// ── Filters ────────────────────────────────────────────────────────────────────

const SCOPE_OPTIONS = ["all", "issued", "own", "peers"] as const;
const STATUS_OPTIONS = ["all", "active", "revoked", "expired"] as const;

// ── Main Screen ────────────────────────────────────────────────────────────────

export function VC01CredentialsList() {
  const [tab, setTab] = useState<TabKey>("credentials");
  const [scope, setScope] = useState<VcShowFilters["scope"]>("all");
  const [status, setStatus] = useState<VcShowFilters["status"]>("all");
  const [showIssueModal, setShowIssueModal] = useState(false);
  const [renewTarget, setRenewTarget] = useState<string | null>(null);
  const [pullingStatus, setPullingStatus] = useState(false);
  const [jsonView, setJsonView] = useState<{ title: string; data: unknown } | null>(null);
  const [loadingRaw, setLoadingRaw] = useState<string | null>(null);

  const { data: vcShowData, loading: vcLoading, error: vcError, refetch: refetchVcs } =
    useVCShow({ scope, status });
  const { data: filesData, loading: filesLoading, error: filesError, refetch: refetchFiles } =
    useVCFilesIssued();
  const { data: ownData, loading: ownLoading, error: ownError, refetch: refetchOwn } =
    useVCFilesOwn();
  const { data: peerData, loading: peerLoading, error: peerError, refetch: refetchPeers } =
    useVCFilesPeers();
  const { data: statusListData, loading: statusListLoading, error: statusListError, refetch: refetchStatusList } =
    useVCStatusList();
  const { data: auditData, loading: auditLoading, error: auditError, refetch: refetchAudit } =
    useVCAudit();

  const openRaw = async (
    kind: "issued" | "own" | "peer",
    id: string,
    label: string,
  ) => {
    setLoadingRaw(id);
    try {
      const fetcher =
        kind === "issued"
          ? vcService.getIssuedFile(id)
          : kind === "own"
            ? vcService.getOwnFile(id)
            : vcService.getPeerFile(id);
      const data = await fetcher;
      setJsonView({ title: label, data });
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to load VC");
    } finally {
      setLoadingRaw(null);
    }
  };

  // Re-fetch when scope or status filter changes (skip initial mount — useApiData handles that)
  const filterMounted = useRef(false);
  useEffect(() => {
    if (!filterMounted.current) { filterMounted.current = true; return; }
    refetchVcs();
  }, [scope, status]);

  const handleVerify = async (id: string) => {
    try {
      const res = await vcService.verify(id);
      if (res.valid) {
        toast.success("VC is valid");
      } else {
        toast.warning(`VC invalid: ${res.reason ?? "unknown reason"}`);
      }
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Verification failed");
    }
  };

  const handleRenew = (id: string) => {
    setRenewTarget(id);
  };

  const handleRevoke = async (id: string) => {
    if (!confirm("Revoke this credential? This cannot be undone.")) return;
    try {
      await vcService.revoke({ id, reason: "manual revoke" });
      toast.success("VC revoked");
      refetchVcs();
      refetchFiles();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Revocation failed");
    }
  };

  const handlePullStatus = async () => {
    setPullingStatus(true);
    try {
      const res = await vcService.pullStatusList();
      toast.success(`Status list pulled — next index: ${res.sgx_next_index}`);
      refetchVcs();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Pull failed");
    } finally {
      setPullingStatus(false);
    }
  };

  const items = useMemo(() => {
    const raw = vcShowData?.items ?? [];
    const seen = new Set<string>();
    return raw.filter(item => {
      if (seen.has(item.vc_id)) return false;
      seen.add(item.vc_id);
      return true;
    });
  }, [vcShowData]);

  const fileItems = useMemo(() => {
    const raw = filesData?.items ?? [];
    const seen = new Set<string>();
    return raw.filter(item => {
      if (seen.has(item.vc_id)) return false;
      seen.add(item.vc_id);
      return true;
    });
  }, [filesData]);

  return (
    <div className="flex flex-col h-full" style={{ background: "var(--background)" }}>
      <PageHeader
        title="Credentials"
        subtitle="Verifiable circle-membership credentials"
        icon={<Award size={20} />}
      />

      {/* Summary chip strip */}
      <SummaryStrip />

      {/* Tab bar */}
      <div
        className="mx-auto w-full max-w-4xl flex items-center gap-1 px-4 md:px-6 pt-3 overflow-x-auto"
        style={{ borderBottom: "1px solid var(--border)" }}
      >
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-t-md flex-shrink-0"
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: tab === key ? "var(--font-weight-semibold)" : "var(--font-weight-medium)",
              color: tab === key ? "var(--primary)" : "var(--muted-foreground)",
              background: "none",
              border: "none",
              borderBottom: tab === key ? "2px solid var(--primary)" : "2px solid transparent",
              cursor: "pointer",
              paddingBottom: "10px",
              whiteSpace: "nowrap",
            }}
          >
            <Icon size={13} />
            {label}
          </button>
        ))}
      </div>

      {/* Action bar */}
      <div className="mx-auto w-full max-w-4xl flex items-center justify-between gap-3 px-4 md:px-6 py-2" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 flex-wrap">
          {tab === "credentials" && (
            <>
              {/* Scope filter */}
              <div className="flex items-center gap-1">
                <span style={{ fontSize: "10px", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", marginRight: "2px" }}>Scope</span>
                {SCOPE_OPTIONS.map((s) => (
                  <button
                    key={s}
                    onClick={() => setScope(s === "all" ? "all" : s)}
                    style={{
                      padding: "3px 8px",
                      borderRadius: "var(--radius-sm)",
                      border: "1px solid",
                      borderColor: scope === s ? "var(--primary)" : "var(--border)",
                      background: scope === s ? "color-mix(in srgb, var(--primary) 10%, transparent)" : "transparent",
                      color: scope === s ? "var(--primary)" : "var(--muted-foreground)",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      cursor: "pointer",
                      textTransform: "capitalize",
                    }}
                  >
                    {s}
                  </button>
                ))}
              </div>
              {/* Divider */}
              <div style={{ width: "1px", height: "18px", background: "var(--border)", flexShrink: 0 }} />
              {/* Status filter */}
              <div className="flex items-center gap-1">
                <span style={{ fontSize: "10px", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", marginRight: "2px" }}>Status</span>
                {STATUS_OPTIONS.map((s) => (
                  <button
                    key={s}
                    onClick={() => setStatus(s === "all" ? "all" : s)}
                    style={{
                      padding: "3px 8px",
                      borderRadius: "var(--radius-sm)",
                      border: "1px solid",
                      borderColor: status === s ? "var(--primary)" : "var(--border)",
                      background: status === s ? "color-mix(in srgb, var(--primary) 10%, transparent)" : "transparent",
                      color: status === s ? "var(--primary)" : "var(--muted-foreground)",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      cursor: "pointer",
                      textTransform: "capitalize",
                    }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Pull status list */}
          <button
            onClick={handlePullStatus}
            disabled={pullingStatus}
            className="flex items-center gap-1.5 rounded-md px-2.5 py-1.5"
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--muted-foreground)",
              background: "var(--muted)",
              border: "1px solid var(--border)",
              cursor: pullingStatus ? "not-allowed" : "pointer",
              opacity: pullingStatus ? 0.7 : 1,
            }}
          >
            {pullingStatus ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />}
            Pull Status
          </button>
          {/* Issue new VC */}
          <button
            onClick={() => setShowIssueModal(true)}
            className="flex items-center gap-1.5 rounded-md px-2.5 py-1.5"
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--primary-foreground)",
              background: "var(--primary)",
              border: "none",
              cursor: "pointer",
            }}
          >
            <Plus size={12} />
            Issue VC
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-4xl px-4 md:px-6 py-4" style={{ gap: "12px", display: "flex", flexDirection: "column" }}>

        {/* ── Credentials tab ── */}
        {tab === "credentials" && (
          <>
            {vcLoading && (
              <div className="flex items-center justify-center py-12">
                <Loader2 size={24} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
              </div>
            )}
            {vcError && !vcLoading && (
              <div
                className="flex items-center gap-3 rounded-xl px-4 py-3"
                style={{ background: "color-mix(in srgb, var(--destructive) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)" }}
              >
                <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0 }} />
                <span style={{ fontSize: "var(--text-xs)", color: "var(--destructive)", fontFamily: "Inter, sans-serif" }}>
                  {vcError.message}
                </span>
              </div>
            )}
            {!vcLoading && !vcError && items.length === 0 && (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <Award size={40} style={{ color: "var(--muted-foreground)", opacity: 0.4 }} />
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                  No credentials found
                </p>
                <button
                  onClick={() => setShowIssueModal(true)}
                  className="flex items-center gap-1.5 rounded-md px-3 py-1.5"
                  style={{
                    fontSize: "var(--text-xs)",
                    fontFamily: "Inter, sans-serif",
                    color: "var(--primary)",
                    background: "color-mix(in srgb, var(--primary) 10%, transparent)",
                    border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)",
                    cursor: "pointer",
                  }}
                >
                  <Plus size={12} />
                  Issue first credential
                </button>
              </div>
            )}
            {!vcLoading && items.map((item) => (
              <VcCard
                key={item.vc_id}
                item={item}
                onVerify={handleVerify}
                onRenew={handleRenew}
                onRevoke={handleRevoke}
              />
            ))}
            {/* Summary footer */}
            {!vcLoading && items.length > 0 && (
              <div
                className="flex items-center gap-4 rounded-xl px-4 py-3"
                style={{ background: "var(--muted)", border: "1px solid var(--border)" }}
              >
                <div className="flex items-center gap-1.5">
                  <Hash size={12} style={{ color: "var(--muted-foreground)" }} />
                  <span style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif" }}>
                    Total: <strong style={{ color: "var(--foreground)" }}>{vcShowData?.count ?? items.length}</strong>
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 size={12} style={{ color: "var(--chart-2)" }} />
                  <span style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif" }}>
                    Active: <strong style={{ color: "var(--chart-2)" }}>
                      {items.filter((i) => !i.revoked && !isExpired(i.expiration_date)).length}
                    </strong>
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <XCircle size={12} style={{ color: "var(--destructive)" }} />
                  <span style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif" }}>
                    Revoked: <strong style={{ color: "var(--destructive)" }}>
                      {items.filter((i) => i.revoked).length}
                    </strong>
                  </span>
                </div>
              </div>
            )}
          </>
        )}

        {/* ── Issued Files tab ── */}
        {tab === "issued-files" && (
          <>
            {filesLoading && (
              <div className="flex items-center justify-center py-12">
                <Loader2 size={24} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
              </div>
            )}
            {filesError && !filesLoading && (
              <div
                className="flex items-center gap-3 rounded-xl px-4 py-3"
                style={{ background: "color-mix(in srgb, var(--destructive) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)" }}
              >
                <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0 }} />
                <span style={{ fontSize: "var(--text-xs)", color: "var(--destructive)", fontFamily: "Inter, sans-serif" }}>
                  {filesError.message}
                </span>
              </div>
            )}
            {!filesLoading && !filesError && fileItems.length === 0 && (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <FileText size={40} style={{ color: "var(--muted-foreground)", opacity: 0.4 }} />
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                  No issued VC files
                </p>
              </div>
            )}
            {!filesLoading && fileItems.map((item) => (
              <FileRow
                key={item.vc_id}
                item={item}
                onView={() => openRaw("issued", item.vc_id, `Issued VC · ${shortId(item.vc_id)}`)}
              />
            ))}
            {!filesLoading && fileItems.length > 0 && (
              <div
                className="flex items-center gap-2 rounded-xl px-4 py-3"
                style={{ background: "var(--muted)", border: "1px solid var(--border)" }}
              >
                <Hash size={12} style={{ color: "var(--muted-foreground)" }} />
                <span style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif" }}>
                  {filesData?.count ?? fileItems.length} issued file(s) cached locally
                </span>
              </div>
            )}
          </>
        )}

        {/* ── Own Files tab ── */}
        {tab === "own-files" && (
          <FileListPane
            data={ownData?.items}
            count={ownData?.count}
            loading={ownLoading}
            error={ownError}
            emptyIcon={HardDrive}
            emptyLabel="No own credentials cached"
            onView={(item) =>
              openRaw("own", item.vc_id, `Own VC · ${shortId(item.vc_id)}`)
            }
          />
        )}

        {/* ── Peer Files tab ── */}
        {tab === "peer-files" && (
          <FileListPane
            data={peerData?.items}
            count={peerData?.count}
            loading={peerLoading}
            error={peerError}
            emptyIcon={Users}
            emptyLabel="No peer credentials cached"
            onView={(item) =>
              openRaw(
                "peer",
                item.subject,
                `Peer VC · ${shortDid(item.subject)}`,
              )
            }
          />
        )}

        {/* ── Status List tab ── */}
        {tab === "status-list" && (
          <StatusListPane
            loading={statusListLoading}
            error={statusListError}
            data={statusListData}
            onRefresh={refetchStatusList}
            onView={() =>
              setJsonView({
                title: "Status List Credential",
                data: statusListData,
              })
            }
          />
        )}

        {/* ── Audit tab ── */}
        {tab === "audit" && (
          <AuditPane
            loading={auditLoading}
            error={auditError}
            items={auditData?.items ?? []}
            count={auditData?.count ?? 0}
            onRefresh={refetchAudit}
          />
        )}
        </div>
      </div>

      {/* Modals */}
      {showIssueModal && (
        <IssueVcModal
          onClose={() => setShowIssueModal(false)}
          onIssued={() => { refetchVcs(); refetchFiles(); refetchOwn(); refetchPeers(); }}
        />
      )}
      {renewTarget && (
        <RenewModal
          vcId={renewTarget}
          onClose={() => setRenewTarget(null)}
          onRenewed={() => { refetchVcs(); refetchFiles(); refetchOwn(); refetchPeers(); }}
        />
      )}
      {jsonView && (
        <JsonViewerModal
          title={jsonView.title}
          data={jsonView.data}
          onClose={() => setJsonView(null)}
        />
      )}
      {loadingRaw && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center pointer-events-none"
          style={{ background: "rgba(0,0,0,0.15)" }}
        >
          <div
            className="rounded-full px-4 py-2 flex items-center gap-2"
            style={{
              background: "var(--card)",
              border: "1px solid var(--border)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            <Loader2 size={12} className="animate-spin" />
            Loading raw VC…
          </div>
        </div>
      )}
    </div>
  );
}

// ── File list pane (used by Own / Peers tabs) ─────────────────────────────────

function FileListPane({
  data,
  count,
  loading,
  error,
  emptyIcon: EmptyIcon,
  emptyLabel,
  onView,
}: {
  data: VcMetaItem[] | undefined;
  count: number | undefined;
  loading: boolean;
  error: Error | null;
  emptyIcon: typeof Award;
  emptyLabel: string;
  onView: (item: VcMetaItem) => void;
}) {
  const items = useMemo(() => {
    const raw = data ?? [];
    const seen = new Set<string>();
    return raw.filter((i) => {
      if (seen.has(i.vc_id)) return false;
      seen.add(i.vc_id);
      return true;
    });
  }, [data]);

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 size={24} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
      </div>
    );
  }
  if (error && !loading) {
    return (
      <div
        className="flex items-center gap-3 rounded-xl px-4 py-3"
        style={{
          background: "color-mix(in srgb, var(--destructive) 10%, transparent)",
          border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
        }}
      >
        <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0 }} />
        <span
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--destructive)",
            fontFamily: "Inter, sans-serif",
          }}
        >
          {error.message}
        </span>
      </div>
    );
  }
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 gap-3">
        <EmptyIcon size={40} style={{ color: "var(--muted-foreground)", opacity: 0.4 }} />
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
          }}
        >
          {emptyLabel}
        </p>
      </div>
    );
  }
  return (
    <>
      {items.map((item) => (
        <FileRow key={item.vc_id} item={item} onView={() => onView(item)} />
      ))}
      <div
        className="flex items-center gap-2 rounded-xl px-4 py-3"
        style={{ background: "var(--muted)", border: "1px solid var(--border)" }}
      >
        <Hash size={12} style={{ color: "var(--muted-foreground)" }} />
        <span
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
            fontFamily: "Inter, sans-serif",
          }}
        >
          {count ?? items.length} file(s) cached locally
        </span>
      </div>
    </>
  );
}

// ── Status List pane ──────────────────────────────────────────────────────────

function StatusListPane({
  loading,
  error,
  data,
  onRefresh,
  onView,
}: {
  loading: boolean;
  error: Error | null;
  data: import("../../services/vcService").VcStatusListResponse | null;
  onRefresh: () => void;
  onView: () => void;
}) {
  if (loading && !data) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 size={24} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
      </div>
    );
  }
  if (error && !loading) {
    return (
      <div
        className="flex items-center gap-3 rounded-xl px-4 py-3"
        style={{
          background: "color-mix(in srgb, var(--destructive) 10%, transparent)",
          border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
        }}
      >
        <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0 }} />
        <span
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--destructive)",
            fontFamily: "Inter, sans-serif",
          }}
        >
          {error.message}
        </span>
      </div>
    );
  }

  return (
    <div
      className="flex flex-col gap-3 rounded-xl px-4 py-4"
      style={{ background: "var(--card)", border: "1px solid var(--border)" }}
    >
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <ListChecks size={16} style={{ color: "var(--primary)" }} />
          <div>
            <div
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
              }}
            >
              Local Status List Credential
            </div>
            <div
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
              }}
            >
              Cached status-list VC issued by the CA
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className="flex items-center gap-1 rounded-md px-2.5 py-1"
            style={{
              fontSize: "var(--text-xs)",
              fontFamily: "Inter, sans-serif",
              color: "var(--muted-foreground)",
              background: "var(--muted)",
              border: "1px solid var(--border)",
              cursor: "pointer",
            }}
          >
            <RefreshCw size={11} />
            Reload
          </button>
          <button
            onClick={onView}
            disabled={!data}
            className="flex items-center gap-1 rounded-md px-2.5 py-1"
            style={{
              fontSize: "var(--text-xs)",
              fontFamily: "Inter, sans-serif",
              color: "var(--primary)",
              background: "color-mix(in srgb, var(--primary) 10%, transparent)",
              border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)",
              cursor: data ? "pointer" : "not-allowed",
              opacity: data ? 1 : 0.5,
            }}
          >
            <Eye size={11} />
            View JSON
          </button>
        </div>
      </div>
      {!data ? (
        <div
          className="rounded-md px-3 py-3"
          style={{
            background: "var(--muted)",
            border: "1px dashed var(--border)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
          }}
        >
          No status list cached yet. Use <strong>Pull Status</strong> in the action bar to fetch from the CA.
        </div>
      ) : (
        <>
          <div
            className="grid gap-2"
            style={{ gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}
          >
            <StatusListField label="Issuer" value={shortDid(data.issuer)} mono copy={data.issuer} />
            <StatusListField
              label="Issued"
              value={data.issuanceDate ? fmtDate(data.issuanceDate) : "—"}
            />
            <StatusListField
              label="Next Index"
              value={String(data.sgxNextIndex ?? "—")}
            />
            <StatusListField
              label="Status Purpose"
              value={data.credentialSubject?.statusPurpose ?? "—"}
            />
          </div>
          {data.credentialSubject?.encodedList && (
            <div
              className="rounded-md px-3 py-2"
              style={{
                background: "var(--background)",
                border: "1px solid var(--border)",
              }}
            >
              <div
                style={{
                  fontSize: "10px",
                  color: "var(--muted-foreground)",
                  fontFamily: "Inter, sans-serif",
                  marginBottom: "3px",
                }}
              >
                Encoded List (gzip+base64)
              </div>
              <code
                className="block truncate"
                style={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: "var(--text-xs)",
                  color: "var(--foreground)",
                }}
                title={data.credentialSubject.encodedList}
              >
                {data.credentialSubject.encodedList}
              </code>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function StatusListField({
  label,
  value,
  mono,
  copy,
}: {
  label: string;
  value: string;
  mono?: boolean;
  copy?: string;
}) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ background: "var(--background)", border: "1px solid var(--border)" }}
    >
      <div
        style={{
          fontSize: "10px",
          color: "var(--muted-foreground)",
          fontFamily: "Inter, sans-serif",
          marginBottom: "3px",
        }}
      >
        {label}
      </div>
      <div className="flex items-center gap-2">
        <span
          className="flex-1 break-all"
          style={{
            fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--foreground)",
          }}
          title={copy}
        >
          {value}
        </span>
        {copy && (
          <button
            onClick={() => {
              navigator.clipboard.writeText(copy).then(
                () => toast.success("Copied"),
                () => toast.error("Copy failed"),
              );
            }}
            className="rounded p-1"
            style={{
              background: "none",
              border: "none",
              color: "var(--muted-foreground)",
              cursor: "pointer",
              display: "inline-flex",
            }}
          >
            <Copy size={11} />
          </button>
        )}
      </div>
    </div>
  );
}

// ── Audit pane ─────────────────────────────────────────────────────────────────

function AuditPane({
  loading,
  error,
  items,
  count,
  onRefresh,
}: {
  loading: boolean;
  error: Error | null;
  items: import("../../services/vcService").VcAuditItem[];
  count: number;
  onRefresh: () => void;
}) {
  if (loading && items.length === 0) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 size={24} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
      </div>
    );
  }
  if (error && items.length === 0) {
    return (
      <div
        className="flex items-center gap-3 rounded-xl px-4 py-3"
        style={{
          background: "color-mix(in srgb, var(--destructive) 10%, transparent)",
          border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
        }}
      >
        <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0 }} />
        <span
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--destructive)",
            fontFamily: "Inter, sans-serif",
          }}
        >
          {error.message}
        </span>
      </div>
    );
  }
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 gap-3">
        <History size={40} style={{ color: "var(--muted-foreground)", opacity: 0.4 }} />
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
          }}
        >
          No audit events recorded yet
        </p>
      </div>
    );
  }
  return (
    <>
      <div className="flex items-center justify-between gap-2">
        <span
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
            fontFamily: "Inter, sans-serif",
          }}
        >
          {count} event(s)
        </span>
        <button
          onClick={onRefresh}
          className="flex items-center gap-1 rounded-md px-2 py-1"
          style={{
            fontSize: "var(--text-xs)",
            fontFamily: "Inter, sans-serif",
            color: "var(--muted-foreground)",
            background: "var(--muted)",
            border: "1px solid var(--border)",
            cursor: "pointer",
          }}
        >
          <RefreshCw size={11} />
          Refresh
        </button>
      </div>
      {items.map((item, idx) => (
        <AuditRow key={`${item.timestamp}-${idx}`} item={item} />
      ))}
    </>
  );
}

function severityColor(sev: string): string {
  switch (sev) {
    case "Error":
      return "var(--destructive)";
    case "Warn":
    case "Warning":
      return "var(--chart-4)";
    case "Info":
    default:
      return "var(--chart-2)";
  }
}

function actionIsFailure(action: string): boolean {
  return /FAIL|ERROR|DENIED|REVOKED/i.test(action);
}

function AuditRow({ item }: { item: import("../../services/vcService").VcAuditItem }) {
  const failure = actionIsFailure(item.action) || item.severity === "Error";
  const sevColor = severityColor(item.severity);
  const actionColor = failure ? "var(--destructive)" : "var(--chart-2)";
  return (
    <div
      className="flex items-start gap-3 rounded-xl px-4 py-3"
      style={{ background: "var(--card)", border: "1px solid var(--border)" }}
    >
      <Activity size={14} style={{ color: actionColor, marginTop: "2px", flexShrink: 0 }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
            }}
          >
            {item.action}
          </span>
          <span
            className="inline-flex items-center rounded-md px-1.5 py-0.5"
            style={{
              fontSize: "10px",
              fontFamily: "Inter, sans-serif",
              color: sevColor,
              background: `color-mix(in srgb, ${sevColor} 10%, transparent)`,
              border: `1px solid color-mix(in srgb, ${sevColor} 25%, transparent)`,
            }}
          >
            {item.severity}
          </span>
          {item.node_id && (
            <span
              style={{
                fontSize: "10px",
                fontFamily: "JetBrains Mono, monospace",
                color: "var(--muted-foreground)",
              }}
            >
              {item.node_id}
            </span>
          )}
          <span
            style={{
              fontSize: "10px",
              fontFamily: "JetBrains Mono, monospace",
              color: "var(--muted-foreground)",
              marginLeft: "auto",
            }}
            title="audit sequence number"
          >
            #{item.timestamp}
          </span>
        </div>
        <div
          className="mt-1"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
            wordBreak: "break-word",
          }}
        >
          {item.message}
        </div>
      </div>
    </div>
  );
}
