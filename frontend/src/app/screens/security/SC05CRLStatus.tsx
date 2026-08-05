import { useCallback, useEffect, useMemo, useState, type CSSProperties, type FormEvent, type KeyboardEvent, type ReactNode } from "react";
import { useNavigate } from "react-router";
import {
  AlertTriangle,
  Ban,
  Check,
  CheckCircle2,
  Copy,
  Eye,
  FileJson,
  Fingerprint,
  Hash,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { useDIDDocumentPeers, useVCSummary, useVCShow } from "../../hooks/useApiData";
import { useCurrentUser } from "../../hooks/useCurrentUser";
import {
  crlService,
  type CrlEntry,
  type CrlListResponse,
  type CrlReason,
  type CrlRevokePayload,
  type CrlRootResponse,
  type CrlSeverity,
  type CrlVerifyResponse,
} from "../../services/crlService";
import type { DIDDocumentPeerSummary } from "../../services/didService";
import { CrlOperationsPanel } from "./CrlOperationsPanel";

type IconComponent = typeof ShieldCheck;
type SortKey = "severity" | "reason" | "timestamp";
type SortDirection = "asc" | "desc";
type DateFilter = "24h" | "7d" | "30d" | "all";
type RawView = "formatted" | "raw";
type RoleKind = "owner" | "member" | "viewer" | "unknown";
type QuickRevokeTarget = { did: string; nodeName?: string };

const REASONS: { value: CrlReason; label: string }[] = [
  { value: "compromised", label: "Compromised" },
  { value: "lost", label: "Lost" },
  { value: "stolen", label: "Stolen" },
  { value: "policy_violation", label: "Policy Violation" },
  { value: "administrative_removal", label: "Administrative Removal" },
  { value: "voluntary_departure", label: "Voluntary Departure" },
];

const SEVERITIES: { value: CrlSeverity; label: string }[] = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const SECURITY_CRITICAL_REASONS = new Set<CrlReason>([
  "compromised",
  "lost",
  "stolen",
  "policy_violation",
]);

const severityRank: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function normalize(value?: string) {
  return String(value ?? "").trim().toLowerCase();
}

function reasonLabel(reason?: string) {
  const value = normalize(reason);
  return REASONS.find((item) => item.value === value)?.label ?? (reason || "Unknown");
}

function severityLabel(severity?: string) {
  const value = normalize(severity);
  return SEVERITIES.find((item) => item.value === value)?.label ?? (severity || "Unknown");
}

function severityColor(severity?: string) {
  switch (normalize(severity)) {
    case "critical":
      return "var(--destructive)";
    case "high":
      return "var(--chart-4)";
    case "medium":
      return "var(--primary)";
    case "low":
      return "var(--muted-foreground)";
    default:
      return "var(--muted-foreground)";
  }
}

function formatDate(value?: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function timestampValue(value?: string) {
  const date = value ? new Date(value) : null;
  return date && !Number.isNaN(date.getTime()) ? date.getTime() : 0;
}

function shortMiddle(value?: string, head = 18, tail = 8) {
  if (!value) return "-";
  if (value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

function roleKind(role?: string): RoleKind {
  const value = normalize(role);
  if (value.includes("owner")) return "owner";
  if (value.includes("member")) return "member";
  if (value.includes("viewer") || value.includes("read")) return "viewer";
  return "unknown";
}

function activeCrlEntryForDid(entries: CrlEntry[], did?: string) {
  const target = normalize(did);
  if (!target) return undefined;
  return entries.find((entry) => normalize(entry.revoked_did) === target);
}

function isOwnerDid(did?: string, ownerDid?: string) {
  const target = normalize(did);
  return !!target && target === normalize(ownerDid);
}

function canRevokeDid(role: RoleKind, did?: string, ownerDid?: string) {
  if (role === "viewer") return false;
  if (role === "member" && isOwnerDid(did, ownerDid)) return false;
  return true;
}

function isActiveDidNode(status?: string) {
  const value = normalize(status);
  return value === "active" || value === "running" || value === "online";
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Unknown error";
}

async function copyValue(value: string | undefined, label = "Copied") {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    toast.success(label);
  } catch {
    toast.error("Copy failed");
  }
}

function IconButton({
  label,
  icon: Icon,
  onClick,
  disabled,
  color = "var(--muted-foreground)",
}: {
  label: string;
  icon: IconComponent;
  onClick: () => void;
  disabled?: boolean;
  color?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={label}
      className="inline-flex items-center justify-center rounded-md"
      style={{
        width: "34px",
        height: "34px",
        border: "1px solid var(--border)",
        backgroundColor: "var(--card)",
        color,
        opacity: disabled ? 0.55 : 1,
      }}
    >
      <Icon size={15} />
    </button>
  );
}

function ActionButton({
  children,
  icon: Icon,
  onClick,
  disabled,
  loading,
  variant = "primary",
  type = "button",
}: {
  children: string;
  icon: IconComponent;
  onClick?: () => void;
  disabled?: boolean;
  loading?: boolean;
  variant?: "primary" | "secondary" | "danger" | "success" | "muted";
  type?: "button" | "submit";
}) {
  const colors = {
    primary: {
      bg: "var(--primary)",
      border: "var(--primary)",
      color: "var(--primary-foreground)",
    },
    secondary: {
      bg: "color-mix(in srgb, var(--primary) 10%, transparent)",
      border: "color-mix(in srgb, var(--primary) 25%, transparent)",
      color: "var(--primary)",
    },
    danger: {
      bg: "color-mix(in srgb, var(--destructive) 12%, transparent)",
      border: "color-mix(in srgb, var(--destructive) 30%, transparent)",
      color: "var(--destructive)",
    },
    success: {
      bg: "color-mix(in srgb, var(--chart-2) 12%, transparent)",
      border: "color-mix(in srgb, var(--chart-2) 30%, transparent)",
      color: "var(--chart-2)",
    },
    muted: {
      bg: "var(--muted)",
      border: "var(--border)",
      color: "var(--foreground)",
    },
  }[variant];

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      className="inline-flex items-center justify-center gap-2 rounded-md px-3"
      style={{
        minHeight: "36px",
        border: `1px solid ${colors.border}`,
        backgroundColor: colors.bg,
        color: colors.color,
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-semibold)",
        opacity: disabled || loading ? 0.65 : 1,
        whiteSpace: "nowrap",
      }}
    >
      {loading ? <Loader2 size={14} className="animate-spin" /> : <Icon size={14} />}
      {children}
    </button>
  );
}

function StatusPill({
  children,
  color,
  icon: Icon,
}: {
  children: string;
  color: string;
  icon?: IconComponent;
}) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md"
      style={{
        padding: "3px 8px",
        backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
        color,
        fontFamily: "Inter, sans-serif",
        fontSize: "10px",
        fontWeight: "var(--font-weight-semibold)",
        whiteSpace: "nowrap",
      }}
    >
      {Icon && <Icon size={10} />}
      {children}
    </span>
  );
}

function SeverityBadge({ severity }: { severity?: string }) {
  const color = severityColor(severity);
  return <StatusPill color={color} icon={normalize(severity) === "critical" ? ShieldAlert : undefined}>{severityLabel(severity)}</StatusPill>;
}

function ReasonBadge({ reason }: { reason?: string }) {
  return <StatusPill color="var(--primary)">{reasonLabel(reason)}</StatusPill>;
}

function RoleBadge({ role }: { role?: string }) {
  const owner = normalize(role) === "owner";
  return (
    <StatusPill color={owner ? "var(--chart-5)" : "var(--muted-foreground)"}>
      {role ? role.charAt(0).toUpperCase() + role.slice(1) : "Unknown"}
    </StatusPill>
  );
}

function PropagationBadge({ entry }: { entry: CrlEntry }) {
  const count = entry.peers_notified?.length ?? 0;
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <StatusPill color={entry.propagated ? "var(--chart-2)" : "var(--chart-4)"} icon={entry.propagated ? CheckCircle2 : AlertTriangle}>
        {entry.propagated ? "Propagated" : "Pending"}
      </StatusPill>
      <span style={{ fontSize: "10px", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif" }}>
        {count} peer{count === 1 ? "" : "s"}
      </span>
    </span>
  );
}

function CopyButton({ value, label = "Copied" }: { value?: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation();
        if (!value) return;
        navigator.clipboard.writeText(value).then(
          () => {
            setCopied(true);
            toast.success(label);
            window.setTimeout(() => setCopied(false), 1600);
          },
          () => toast.error("Copy failed"),
        );
      }}
      disabled={!value}
      aria-label="Copy"
      title="Copy"
      className="inline-flex items-center justify-center rounded"
      style={{
        width: "24px",
        height: "24px",
        border: "none",
        backgroundColor: copied ? "color-mix(in srgb, var(--chart-2) 14%, transparent)" : "transparent",
        color: copied ? "var(--chart-2)" : "var(--muted-foreground)",
        flexShrink: 0,
      }}
    >
      {copied ? <Check size={13} /> : <Copy size={13} />}
    </button>
  );
}

function MonoValue({
  value,
  truncate = true,
  copyable = true,
}: {
  value?: string;
  truncate?: boolean;
  copyable?: boolean;
}) {
  return (
    <div className="flex items-center gap-1 min-w-0">
      <code
        className={truncate ? "truncate" : ""}
        title={value}
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "var(--text-xs)",
          color: "var(--foreground)",
          wordBreak: truncate ? "normal" : "break-all",
          whiteSpace: truncate ? "nowrap" : "normal",
          minWidth: 0,
        }}
      >
        {value || "-"}
      </code>
      {copyable && value && <CopyButton value={value} />}
    </div>
  );
}

function SectionLabel({ children }: { children: string }) {
  return (
    <p
      style={{
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-semibold)",
        color: "var(--muted-foreground)",
        letterSpacing: "0.08em",
      }}
    >
      {children}
    </p>
  );
}

function FieldRow({ label, value, mono }: { label: string; value?: string | number | boolean | null; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2" style={{ borderBottom: "1px solid var(--border)" }}>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", flexShrink: 0 }}>
        {label}
      </span>
      <span
        style={{
          fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          color: "var(--foreground)",
          textAlign: "right",
          wordBreak: "break-all",
        }}
      >
        {value === undefined || value === null || value === "" ? "-" : String(value)}
      </span>
    </div>
  );
}

function NativeSelect({
  label,
  value,
  onChange,
  children,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1 min-w-[130px]" style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        style={{
          height: "36px",
          borderRadius: "var(--radius)",
          border: "1px solid var(--border)",
          backgroundColor: "var(--input-background)",
          color: "var(--foreground)",
          padding: "0 10px",
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          outline: "none",
        }}
      >
        {children}
      </select>
    </label>
  );
}

function TextField({
  label,
  value,
  onChange,
  placeholder,
  mono,
  required,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  mono?: boolean;
  required?: boolean;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
        {label}{required ? " *" : ""}
      </span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        style={{
          height: "38px",
          borderRadius: "var(--radius)",
          border: "1px solid var(--border)",
          backgroundColor: "var(--input-background)",
          color: "var(--foreground)",
          padding: "0 11px",
          fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          outline: "none",
        }}
      />
    </label>
  );
}

function SummaryCards({
  entries,
  root,
  verifyResult,
  verifyCheckedAt,
  verifyStale,
  loading,
}: {
  entries: CrlEntry[];
  root: CrlRootResponse | null;
  verifyResult: CrlVerifyResponse | null;
  verifyCheckedAt: string | null;
  verifyStale: boolean;
  loading: boolean;
}) {
  const highestSeverity = useMemo(() => {
    if (entries.length === 0) return "None";
    const found = [...entries].sort((a, b) => (severityRank[normalize(b.severity)] ?? 0) - (severityRank[normalize(a.severity)] ?? 0))[0];
    return severityLabel(found.severity);
  }, [entries]);

  const highestColor = entries.length === 0 ? "var(--muted-foreground)" : severityColor(highestSeverity);
  const integrityLabel = !verifyResult ? (verifyStale ? "Not checked" : "Not checked") : verifyResult.ok ? "Verified" : "Needs attention";
  const integrityColor = !verifyResult ? "var(--muted-foreground)" : verifyResult.ok ? "var(--chart-2)" : "var(--destructive)";
  const integrityText = verifyStale
    ? "after latest CRL update"
    : verifyCheckedAt
      ? `last checked ${formatDate(verifyCheckedAt)}`
      : "manual verification";

  const cards = [
    {
      label: "Total Revocations",
      value: loading ? "..." : String(entries.length),
      detail: "active CRL entries",
      icon: Ban,
      color: "var(--primary)",
    },
    {
      label: "Highest Severity",
      value: loading ? "..." : highestSeverity,
      detail: "from current entries",
      icon: ShieldAlert,
      color: highestColor,
    },
    {
      label: "CRL Sequence",
      value: root ? String(root.sequence) : loading ? "..." : "-",
      detail: "monotonic update index",
      icon: Hash,
      color: "var(--primary)",
      mono: true,
    },
    {
      label: "Integrity",
      value: integrityLabel,
      detail: integrityText,
      icon: verifyResult?.ok ? ShieldCheck : verifyResult ? ShieldX : ShieldAlert,
      color: integrityColor,
    },
  ];

  return (
    <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))" }}>
      {cards.map(({ label, value, detail, icon: Icon, color, mono }) => (
        <div
          key={label}
          className="rounded-lg border p-4"
          style={{
            backgroundColor: "var(--card)",
            borderColor: "var(--border)",
          }}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif" }}>{label}</p>
              <p
                className="truncate"
                style={{
                  marginTop: "6px",
                  fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
                  fontSize: "var(--text-lg)",
                  fontWeight: "var(--font-weight-semibold)",
                  color,
                }}
              >
                {value}
              </p>
              <p style={{ marginTop: "2px", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif" }}>{detail}</p>
            </div>
            <div
              className="flex items-center justify-center rounded-md"
              style={{
                width: "36px",
                height: "36px",
                backgroundColor: `color-mix(in srgb, ${color} 10%, transparent)`,
                color,
                flexShrink: 0,
              }}
            >
              <Icon size={18} />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function DidNodesPanel({
  peers,
  entries,
  loading,
  error,
  refreshing,
  canRevoke,
  localRole,
  ownerDid,
  onRefresh,
  onRevoke,
  onCheckDid,
  onViewEntry,
}: {
  peers: DIDDocumentPeerSummary[];
  entries: CrlEntry[];
  loading: boolean;
  error: Error | null;
  refreshing: boolean;
  canRevoke: boolean;
  localRole: RoleKind;
  ownerDid?: string;
  onRefresh: () => void;
  onRevoke: (peer: DIDDocumentPeerSummary) => void;
  onCheckDid: (did: string) => void;
  onViewEntry: (entry: CrlEntry) => void;
}) {
  const sortedPeers = useMemo(
    () => [...peers].sort((a, b) => Number(isActiveDidNode(b.status)) - Number(isActiveDidNode(a.status)) || a.node_name.localeCompare(b.node_name)),
    [peers],
  );
  const activeCount = peers.filter((peer) => isActiveDidNode(peer.status)).length;

  return (
    <section className="rounded-lg border" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", overflow: "hidden" }}>
      <div className="p-4 flex flex-col gap-3" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="min-w-0">
            <SectionLabel>DID NODES</SectionLabel>
            <p style={{ marginTop: "4px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {loading ? "Loading nodes" : `${activeCount} running / ${peers.length} known`}
            </p>
            <p style={{ marginTop: "2px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
              Same DID document peers shown on the DID Status page.
            </p>
          </div>
          <ActionButton icon={RefreshCw} variant="muted" onClick={onRefresh} loading={refreshing}>
            Refresh Nodes
          </ActionButton>
        </div>
      </div>

      {loading ? (
        <div className="p-4 flex flex-col gap-2">
          {[0, 1, 2].map((item) => (
            <div key={item} className="rounded-md" style={{ height: "58px", backgroundColor: "var(--muted)", opacity: 0.7 }} />
          ))}
        </div>
      ) : error ? (
        <div className="p-6 flex flex-col items-center text-center gap-3">
          <AlertTriangle size={32} style={{ color: "var(--chart-4)" }} />
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              DID nodes unavailable
            </p>
            <p style={{ marginTop: "4px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{error.message}</p>
          </div>
          <ActionButton icon={RefreshCw} variant="secondary" onClick={onRefresh} loading={refreshing}>
            Retry
          </ActionButton>
        </div>
      ) : sortedPeers.length === 0 ? (
        <div className="p-8 flex flex-col items-center text-center gap-3">
          <Fingerprint size={36} style={{ color: "var(--muted-foreground)", opacity: 0.65 }} />
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              No DID peer nodes found
            </p>
            <p style={{ marginTop: "4px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Publish or sync DID documents to populate this list.
            </p>
          </div>
        </div>
      ) : (
        <div className="flex flex-col">
          {sortedPeers.map((peer, index) => {
            const revokedEntry = activeCrlEntryForDid(entries, peer.did);
            const running = isActiveDidNode(peer.status);
            const protectedOwner = localRole === "member" && isOwnerDid(peer.did, ownerDid);
            const statusColor = revokedEntry ? "var(--destructive)" : running ? "var(--chart-2)" : "var(--muted-foreground)";
            return (
              <div
                key={peer.did || `${peer.node_name}-${index}`}
                className="p-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between"
                style={{ borderTop: index === 0 ? undefined : "1px solid var(--border)" }}
              >
                <div className="flex items-start gap-3 min-w-0">
                  <div
                    className="flex items-center justify-center rounded-md flex-shrink-0"
                    style={{ width: "38px", height: "38px", backgroundColor: `color-mix(in srgb, ${statusColor} 12%, transparent)`, color: statusColor }}
                  >
                    <Fingerprint size={18} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="truncate" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                        {peer.node_name || "Unnamed node"}
                      </p>
                      {isOwnerDid(peer.did, ownerDid) && <StatusPill color="var(--primary)">Owner</StatusPill>}
                      <StatusPill color={statusColor}>{revokedEntry ? "Revoked" : peer.status || "Unknown"}</StatusPill>
                      <StatusPill color="var(--muted-foreground)">{`v${peer.version}`}</StatusPill>
                      <StatusPill color="var(--muted-foreground)">{`${peer.services} svc`}</StatusPill>
                    </div>
                    <div className="mt-2">
                      <MonoValue value={peer.did} truncate={false} />
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 lg:justify-end">
                  <ActionButton icon={ShieldCheck} variant="secondary" onClick={() => onCheckDid(peer.did)}>
                    Check
                  </ActionButton>
                  {revokedEntry ? (
                    <ActionButton icon={Eye} variant="muted" onClick={() => onViewEntry(revokedEntry)}>
                      View Entry
                    </ActionButton>
                  ) : protectedOwner ? (
                    <ActionButton icon={ShieldX} variant="muted" disabled>
                      Owner Protected
                    </ActionButton>
                  ) : (
                    <ActionButton icon={ShieldX} variant="danger" onClick={() => onRevoke(peer)} disabled={!canRevoke || !canRevokeDid(localRole, peer.did, ownerDid)}>
                      Revoke
                    </ActionButton>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
function DidCheckPanel({
  didInput,
  setDidInput,
  checking,
  checkResult,
  checkError,
  onCheck,
  onViewEntry,
  onUnrevoke,
  canAttemptUnrevoke,
}: {
  didInput: string;
  setDidInput: (value: string) => void;
  checking: boolean;
  checkResult: { did: string; revoked: boolean; entry?: CrlEntry | null } | null;
  checkError: string | null;
  onCheck: () => void;
  onViewEntry: (entry: CrlEntry) => void;
  onUnrevoke: (entry: CrlEntry) => void;
  canAttemptUnrevoke: boolean;
}) {
  const didIsValid = didInput.trim().startsWith("did:");

  const resultColor = checkError
    ? "var(--chart-4)"
    : checkResult?.revoked
      ? "var(--destructive)"
      : checkResult
        ? "var(--chart-2)"
        : "var(--muted-foreground)";

  return (
    <div className="rounded-lg border p-4 flex flex-col gap-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <SectionLabel>DID CHECK</SectionLabel>
          <p style={{ marginTop: "4px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            Use the full did:guardian:... value. Short IDs can produce misleading results.
          </p>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1 min-w-0">
          <Search size={14} style={{ position: "absolute", left: "11px", top: "50%", transform: "translateY(-50%)", color: "var(--muted-foreground)" }} />
          <input
            value={didInput}
            onChange={(event) => setDidInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && didIsValid && !checking) onCheck();
            }}
            placeholder="did:guardian:..."
            style={{
              width: "100%",
              height: "38px",
              borderRadius: "var(--radius)",
              border: `1px solid ${didInput && !didIsValid ? "var(--chart-4)" : "var(--border)"}`,
              backgroundColor: "var(--input-background)",
              color: "var(--foreground)",
              padding: "0 40px 0 34px",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "var(--text-xs)",
              outline: "none",
              boxSizing: "border-box",
            }}
          />
          {didInput && (
            <button
              type="button"
              onClick={() => setDidInput("")}
              aria-label="Clear DID"
              title="Clear DID"
              className="absolute right-2 top-1/2 inline-flex items-center justify-center rounded"
              style={{ transform: "translateY(-50%)", width: "24px", height: "24px", border: "none", backgroundColor: "transparent", color: "var(--muted-foreground)" }}
            >
              <X size={13} />
            </button>
          )}
        </div>
        <ActionButton icon={ShieldCheck} onClick={onCheck} disabled={!didIsValid} loading={checking}>
          Check DID
        </ActionButton>
      </div>

      {(checkResult || checkError) && (
        <div
          className="rounded-lg border p-3 flex items-start gap-3"
          style={{
            backgroundColor: `color-mix(in srgb, ${resultColor} 9%, transparent)`,
            borderColor: `color-mix(in srgb, ${resultColor} 24%, transparent)`,
          }}
        >
          {checkError ? (
            <AlertTriangle size={18} style={{ color: resultColor, flexShrink: 0, marginTop: "2px" }} />
          ) : checkResult?.revoked ? (
            <ShieldX size={18} style={{ color: resultColor, flexShrink: 0, marginTop: "2px" }} />
          ) : (
            <ShieldCheck size={18} style={{ color: resultColor, flexShrink: 0, marginTop: "2px" }} />
          )}
          <div className="flex-1 min-w-0">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: resultColor }}>
              {checkError ? "Unable to check DID" : checkResult?.revoked ? "DID revoked" : "DID not revoked"}
            </p>
            {checkError ? (
              <p style={{ marginTop: "2px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{checkError}</p>
            ) : checkResult?.revoked && checkResult.entry ? (
              <div className="mt-2 flex flex-col gap-2">
                <div className="flex flex-wrap gap-1.5">
                  <SeverityBadge severity={checkResult.entry.severity} />
                  <ReasonBadge reason={checkResult.entry.reason} />
                  <RoleBadge role={checkResult.entry.revoker_role} />
                </div>
                <MonoValue value={checkResult.did} />
                <div className="flex flex-wrap gap-2">
                  <ActionButton icon={Eye} variant="muted" onClick={() => checkResult.entry && onViewEntry(checkResult.entry)}>
                    View Entry
                  </ActionButton>
                  <ActionButton icon={Copy} variant="muted" onClick={() => copyValue(checkResult.did, "DID copied")}>
                    Copy DID
                  </ActionButton>
                  {canAttemptUnrevoke && (
                    <ActionButton icon={ShieldX} variant="danger" onClick={() => checkResult.entry && onUnrevoke(checkResult.entry)}>
                      Unrevoke
                    </ActionButton>
                  )}
                </div>
              </div>
            ) : (
              <p style={{ marginTop: "2px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                No active CRL entry found for this DID.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function EntriesSection({
  entries,
  filteredEntries,
  loading,
  error,
  search,
  setSearch,
  severityFilter,
  setSeverityFilter,
  reasonFilter,
  setReasonFilter,
  propagationFilter,
  setPropagationFilter,
  roleFilter,
  setRoleFilter,
  dateFilter,
  setDateFilter,
  sortKey,
  sortDirection,
  onSort,
  onView,
  onCheckDid,
  onUnrevoke,
  canAttemptUnrevoke,
  onRetry,
  lastUpdated,
  onRaw,
}: {
  entries: CrlEntry[];
  filteredEntries: CrlEntry[];
  loading: boolean;
  error: string | null;
  search: string;
  setSearch: (value: string) => void;
  severityFilter: string;
  setSeverityFilter: (value: string) => void;
  reasonFilter: string;
  setReasonFilter: (value: string) => void;
  propagationFilter: string;
  setPropagationFilter: (value: string) => void;
  roleFilter: string;
  setRoleFilter: (value: string) => void;
  dateFilter: DateFilter;
  setDateFilter: (value: DateFilter) => void;
  sortKey: SortKey;
  sortDirection: SortDirection;
  onSort: (key: SortKey) => void;
  onView: (entry: CrlEntry) => void;
  onCheckDid: (did: string) => void;
  onUnrevoke: (entry: CrlEntry) => void;
  canAttemptUnrevoke: boolean;
  onRetry: () => void;
  lastUpdated: string | null;
  onRaw: () => void;
}) {
  const hasFilters = Boolean(search || severityFilter !== "all" || reasonFilter !== "all" || propagationFilter !== "all" || roleFilter !== "all" || dateFilter !== "all");

  return (
    <div className="rounded-lg border" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", overflow: "hidden" }}>
      <div className="p-4 flex flex-col gap-3" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <SectionLabel>CRL ENTRIES</SectionLabel>
            <p style={{ marginTop: "4px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              {filteredEntries.length} of {entries.length} entries{lastUpdated ? ` - updated ${formatDate(lastUpdated)}` : ""}
            </p>
          </div>
          <ActionButton icon={FileJson} variant="muted" onClick={onRaw} disabled={entries.length === 0}>
            View Raw List
          </ActionButton>
        </div>

        <div className="flex flex-col gap-2">
          <div className="relative">
            <Search size={14} style={{ position: "absolute", left: "11px", top: "50%", transform: "translateY(-50%)", color: "var(--muted-foreground)" }} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search DID, device, user, entry ID, revoker..."
              style={{
                width: "100%",
                height: "36px",
                borderRadius: "var(--radius)",
                border: "1px solid var(--border)",
                backgroundColor: "var(--input-background)",
                color: "var(--foreground)",
                padding: "0 11px 0 34px",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                outline: "none",
                boxSizing: "border-box",
              }}
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <NativeSelect label="Severity" value={severityFilter} onChange={setSeverityFilter}>
              <option value="all">All</option>
              {SEVERITIES.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
            </NativeSelect>
            <NativeSelect label="Reason" value={reasonFilter} onChange={setReasonFilter}>
              <option value="all">All</option>
              {REASONS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
            </NativeSelect>
            <NativeSelect label="Propagation" value={propagationFilter} onChange={setPropagationFilter}>
              <option value="all">All</option>
              <option value="propagated">Propagated</option>
              <option value="pending">Pending</option>
            </NativeSelect>
            <NativeSelect label="Revoker" value={roleFilter} onChange={setRoleFilter}>
              <option value="all">All</option>
              <option value="owner">Owner</option>
              <option value="member">Member</option>
            </NativeSelect>
            <NativeSelect label="Date" value={dateFilter} onChange={(value) => setDateFilter(value as DateFilter)}>
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7d</option>
              <option value="30d">Last 30d</option>
              <option value="all">All</option>
            </NativeSelect>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="p-4 flex flex-col gap-2">
          {[0, 1, 2, 3].map((item) => (
            <div key={item} className="rounded-md" style={{ height: "42px", backgroundColor: "var(--muted)", opacity: 0.75 }} />
          ))}
        </div>
      ) : error ? (
        <div className="p-6 flex flex-col items-center text-center gap-3">
          <AlertTriangle size={34} style={{ color: "var(--destructive)" }} />
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              Unable to load CRL
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "4px" }}>{error}</p>
          </div>
          <ActionButton icon={RefreshCw} variant="secondary" onClick={onRetry}>
            Retry
          </ActionButton>
        </div>
      ) : filteredEntries.length === 0 ? (
        <div className="p-10 flex flex-col items-center text-center gap-3">
          {hasFilters ? <Search size={38} style={{ color: "var(--muted-foreground)", opacity: 0.55 }} /> : <ShieldCheck size={38} style={{ color: "var(--chart-2)" }} />}
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {hasFilters ? "No matching entries" : "No revoked DIDs"}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "4px" }}>
              {hasFilters ? "Adjust filters or clear search." : "The current CRL has no active entries."}
            </p>
          </div>
        </div>
      ) : (
        <>
          <div className="hidden md:block overflow-x-auto">
            <table style={{ width: "100%", borderCollapse: "collapse", tableLayout: "fixed" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  <HeaderCell width="110px" sortKey="severity" active={sortKey === "severity"} direction={sortDirection} onSort={onSort}>Severity</HeaderCell>
                  <th style={headerStyle}>Revoked DID</th>
                  <HeaderCell width="150px" sortKey="reason" active={sortKey === "reason"} direction={sortDirection} onSort={onSort}>Reason</HeaderCell>
                  <th style={{ ...headerStyle, width: "130px" }}>Revoker</th>
                  <th style={{ ...headerStyle, width: "130px" }}>Propagation</th>
                  <HeaderCell width="160px" sortKey="timestamp" active={sortKey === "timestamp"} direction={sortDirection} onSort={onSort}>Revoked At</HeaderCell>
                  <th style={{ ...headerStyle, width: "126px" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredEntries.map((entry, index) => (
                  <tr
                    key={`${entry.id ?? entry.revoked_did}-${index}`}
                    tabIndex={0}
                    onClick={() => onView(entry)}
                    onKeyDown={(event: KeyboardEvent<HTMLTableRowElement>) => {
                      if (event.key === "Enter" || event.key === " ") onView(entry);
                    }}
                    style={{
                      borderBottom: index < filteredEntries.length - 1 ? "1px solid var(--border)" : undefined,
                      cursor: "pointer",
                    }}
                  >
                    <td style={cellStyle}><SeverityBadge severity={entry.severity} /></td>
                    <td style={cellStyle}><MonoValue value={entry.revoked_did} /></td>
                    <td style={cellStyle}><ReasonBadge reason={entry.reason} /></td>
                    <td style={cellStyle}>
                      <div className="flex flex-col gap-1 min-w-0">
                        <RoleBadge role={entry.revoker_role} />
                        {entry.revoker_did && (
                          <code className="truncate" title={entry.revoker_did} style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)" }}>
                            {shortMiddle(entry.revoker_did, 8, 5)}
                          </code>
                        )}
                      </div>
                    </td>
                    <td style={cellStyle}><PropagationBadge entry={entry} /></td>
                    <td style={cellStyle}>
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{formatDate(entry.timestamp)}</span>
                    </td>
                    <td style={cellStyle}>
                      <div className="flex items-center gap-1">
                        <IconButton label="View entry" icon={Eye} onClick={() => onView(entry)} color="var(--primary)" />
                        <IconButton label="Copy DID" icon={Copy} onClick={() => copyValue(entry.revoked_did, "DID copied")} />
                        <IconButton
                          label={canAttemptUnrevoke ? "Unrevoke DID" : "Only owner can unrevoke"}
                          icon={ShieldX}
                          onClick={() => onUnrevoke(entry)}
                          disabled={!canAttemptUnrevoke}
                          color="var(--destructive)"
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="md:hidden flex flex-col">
            {filteredEntries.map((entry, index) => (
              <div
                key={`${entry.id ?? entry.revoked_did}-${index}`}
                className="p-4 flex flex-col gap-3"
                style={{ borderBottom: index < filteredEntries.length - 1 ? "1px solid var(--border)" : undefined }}
              >
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex flex-wrap gap-1.5">
                    <SeverityBadge severity={entry.severity} />
                    <ReasonBadge reason={entry.reason} />
                  </div>
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>{formatDate(entry.timestamp)}</span>
                </div>
                <MonoValue value={entry.revoked_did} truncate={false} />
                <div className="flex items-center gap-2 flex-wrap">
                  <RoleBadge role={entry.revoker_role} />
                  <StatusPill color={entry.propagated ? "var(--chart-2)" : "var(--chart-4)"}>{entry.propagated ? "Propagated" : "Pending"}</StatusPill>
                  {entry.circle_id && <StatusPill color="var(--muted-foreground)">{entry.circle_id}</StatusPill>}
                </div>
                <div className="flex flex-wrap gap-2">
                  <ActionButton icon={Eye} variant="muted" onClick={() => onView(entry)}>View</ActionButton>
                  <ActionButton icon={ShieldCheck} variant="secondary" onClick={() => onCheckDid(entry.revoked_did)}>Check DID</ActionButton>
                  {canAttemptUnrevoke && <ActionButton icon={ShieldX} variant="danger" onClick={() => onUnrevoke(entry)}>Unrevoke</ActionButton>}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

const headerStyle: CSSProperties = {
  padding: "10px 12px",
  textAlign: "left",
  fontFamily: "Inter, sans-serif",
  fontSize: "10px",
  fontWeight: "var(--font-weight-semibold)",
  color: "var(--muted-foreground)",
  letterSpacing: "0.06em",
  textTransform: "uppercase",
};

const cellStyle: CSSProperties = {
  padding: "12px",
  verticalAlign: "middle",
  minWidth: 0,
};

function HeaderCell({
  children,
  sortKey,
  active,
  direction,
  onSort,
  width,
}: {
  children: string;
  sortKey: SortKey;
  active: boolean;
  direction: SortDirection;
  onSort: (key: SortKey) => void;
  width: string;
}) {
  return (
    <th style={{ ...headerStyle, width }}>
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="inline-flex items-center gap-1"
        style={{
          border: "none",
          backgroundColor: "transparent",
          color: active ? "var(--primary)" : "var(--muted-foreground)",
          font: "inherit",
          padding: 0,
        }}
      >
        {children}
        {active && <span>{direction === "asc" ? "up" : "down"}</span>}
      </button>
    </th>
  );
}

function IntegrityPanel({
  root,
  rootError,
  verifying,
  verifyResult,
  verifyCheckedAt,
  verifyStale,
  onVerify,
  onRefreshRoot,
  onRawRoot,
  onRawVerify,
}: {
  root: CrlRootResponse | null;
  rootError: string | null;
  verifying: boolean;
  verifyResult: CrlVerifyResponse | null;
  verifyCheckedAt: string | null;
  verifyStale: boolean;
  onVerify: () => void;
  onRefreshRoot: () => void;
  onRawRoot: () => void;
  onRawVerify: () => void;
}) {
  const statusColor = !verifyResult ? "var(--muted-foreground)" : verifyResult.ok ? "var(--chart-2)" : "var(--destructive)";
  const statusLabel = !verifyResult ? "Not checked" : verifyResult.ok ? "Verified" : "Invalid";

  return (
    <div className="rounded-lg border p-4 flex flex-col gap-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <SectionLabel>MERKLE ROOT</SectionLabel>
          <p style={{ marginTop: "4px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            CRL sequence and integrity root
          </p>
        </div>
        <StatusPill color={statusColor} icon={verifyResult?.ok ? ShieldCheck : verifyResult ? ShieldX : ShieldAlert}>
          {statusLabel}
        </StatusPill>
      </div>

      {rootError && (
        <div className="rounded-md border p-3 flex gap-2" style={{ backgroundColor: "color-mix(in srgb, var(--chart-4) 8%, transparent)", borderColor: "color-mix(in srgb, var(--chart-4) 24%, transparent)" }}>
          <AlertTriangle size={14} style={{ color: "var(--chart-4)", flexShrink: 0, marginTop: "2px" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-4)" }}>{rootError}</span>
        </div>
      )}

      <div className="grid gap-3">
        <div className="rounded-md p-3" style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginBottom: "4px" }}>Sequence</p>
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            {root ? root.sequence : "-"}
          </p>
        </div>
        <div className="rounded-md p-3" style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
          <div className="flex items-center justify-between gap-2">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Merkle root</p>
            <CopyButton value={root?.merkle_root} label="Root copied" />
          </div>
          <code style={{ display: "block", marginTop: "4px", fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", wordBreak: "break-all", lineHeight: 1.55 }}>
            {root?.merkle_root ?? "-"}
          </code>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <FieldRow label="Last verified" value={verifyCheckedAt ? formatDate(verifyCheckedAt) : "-"} />
        <FieldRow label="Verify state" value={verifyStale ? "Not checked after latest update" : statusLabel} />
      </div>

      {verifyResult && !verifyResult.ok && verifyResult.errors.length > 0 && (
        <div className="rounded-md border p-3" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)", borderColor: "color-mix(in srgb, var(--destructive) 24%, transparent)" }}>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--destructive)", marginBottom: "6px" }}>
            Verification errors
          </p>
          <ul className="flex flex-col gap-1" style={{ margin: 0, paddingLeft: "18px" }}>
            {verifyResult.errors.map((item, index) => (
              <li key={`${item}-${index}`} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid grid-cols-2 gap-2">
        <ActionButton icon={ShieldCheck} variant={verifyResult?.ok ? "success" : "secondary"} onClick={onVerify} loading={verifying}>
          Verify CRL
        </ActionButton>
        <ActionButton icon={RefreshCw} variant="muted" onClick={onRefreshRoot}>
          Refresh Root
        </ActionButton>
        <ActionButton icon={Copy} variant="muted" onClick={() => copyValue(root?.merkle_root, "Root copied")} disabled={!root?.merkle_root}>
          Copy Root
        </ActionButton>
        <ActionButton icon={FileJson} variant="muted" onClick={onRawRoot} disabled={!root}>
          Raw Root
        </ActionButton>
        <div className="col-span-2">
          <ActionButton icon={FileJson} variant="muted" onClick={onRawVerify} disabled={!verifyResult}>
            View Raw Verify Result
          </ActionButton>
        </div>
      </div>
    </div>
  );
}

function EntryLookupPanel({
  value,
  setValue,
  loading,
  error,
  onLookup,
}: {
  value: string;
  setValue: (value: string) => void;
  loading: boolean;
  error: string | null;
  onLookup: () => void;
}) {
  return (
    <div className="rounded-lg border p-4 flex flex-col gap-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
      <div>
        <SectionLabel>ENTRY LOOKUP</SectionLabel>
        <p style={{ marginTop: "4px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          Paste a CRL entry UUID from logs or CLI output.
        </p>
      </div>
      <input
        value={value}
        onChange={(event) => setValue(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" && value.trim()) onLookup();
        }}
        placeholder="urn:uuid:..."
        style={{
          height: "38px",
          borderRadius: "var(--radius)",
          border: "1px solid var(--border)",
          backgroundColor: "var(--input-background)",
          color: "var(--foreground)",
          padding: "0 11px",
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "var(--text-xs)",
          outline: "none",
        }}
      />
      {error && (
        <div className="rounded-md p-2" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)", color: "var(--destructive)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}>
          {error}
        </div>
      )}
      <ActionButton icon={Search} onClick={onLookup} disabled={!value.trim()} loading={loading}>
        Find Entry
      </ActionButton>
    </div>
  );
}

function EntryDrawer({
  entry,
  onClose,
  onCheckDid,
  onUnrevoke,
  canAttemptUnrevoke,
}: {
  entry: CrlEntry;
  onClose: () => void;
  onCheckDid: (did: string) => void;
  onUnrevoke: (entry: CrlEntry) => void;
  canAttemptUnrevoke: boolean;
}) {
  const [view, setView] = useState<"details" | "raw">("details");
  const [showProof, setShowProof] = useState(false);
  const json = JSON.stringify(entry, null, 2);
  const proofValue = entry.proof?.proofValue;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ backgroundColor: "rgba(0,0,0,0.45)" }} onClick={onClose}>
      <div
        className="h-full w-full sm:max-w-[520px] flex flex-col shadow-2xl"
        style={{ backgroundColor: "var(--card)", borderLeft: "1px solid var(--border)" }}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="p-4 flex items-start justify-between gap-3" style={{ borderBottom: "1px solid var(--border)" }}>
          <div className="min-w-0">
            <div className="flex flex-wrap gap-1.5 mb-2">
              <SeverityBadge severity={entry.severity} />
              <ReasonBadge reason={entry.reason} />
            </div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              CRL Entry
            </p>
            <MonoValue value={entry.id ?? "No entry ID returned"} truncate={false} copyable={Boolean(entry.id)} />
            <p style={{ marginTop: "4px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              {formatDate(entry.timestamp)}
            </p>
          </div>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>

        <div className="px-4 pt-3">
          <div className="flex p-1 rounded-md" style={{ backgroundColor: "var(--muted)" }}>
            {[
              { id: "details", label: "Details", icon: Eye },
              { id: "raw", label: "Raw JSON", icon: FileJson },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => setView(id as "details" | "raw")}
                className="flex-1 inline-flex items-center justify-center gap-1.5 rounded"
                style={{
                  height: "32px",
                  border: view === id ? "1px solid var(--border)" : "none",
                  backgroundColor: view === id ? "var(--card)" : "transparent",
                  color: view === id ? "var(--foreground)" : "var(--muted-foreground)",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: view === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                }}
              >
                <Icon size={12} />
                {label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {view === "raw" ? (
            <pre style={{ margin: 0, padding: "12px", borderRadius: "var(--radius-card)", border: "1px solid var(--border)", backgroundColor: "var(--muted)", fontFamily: "JetBrains Mono, monospace", fontSize: "11px", lineHeight: 1.5, color: "var(--foreground)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {json}
            </pre>
          ) : (
            <div className="flex flex-col gap-4">
              <DrawerSection title="Revoked Identity" icon={ShieldX}>
                <div className="py-2" style={{ borderBottom: "1px solid var(--border)" }}>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "4px" }}>Revoked DID</p>
                  <MonoValue value={entry.revoked_did} truncate={false} />
                </div>
                <FieldRow label="Device ID" value={entry.device_id} mono />
                <FieldRow label="User ID" value={entry.user_id} mono />
                <FieldRow label="Circle ID" value={entry.circle_id} mono />
              </DrawerSection>

              <DrawerSection title="Issuer" icon={ShieldCheck}>
                <div className="py-2" style={{ borderBottom: "1px solid var(--border)" }}>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "4px" }}>Revoker DID</p>
                  <MonoValue value={entry.revoker_did} truncate={false} />
                </div>
                <FieldRow label="Revoker role" value={entry.revoker_role} />
                <p style={{ marginTop: "8px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                  Owner can revoke any DID. Member revocations are limited to security-critical reasons with Critical or High severity.
                </p>
              </DrawerSection>

              <DrawerSection title="Integrity Proof" icon={FileJson}>
                <FieldRow label="Type" value={entry.proof?.type ?? "DataIntegrityProof"} />
                <FieldRow label="Cryptosuite" value={entry.proof?.cryptosuite ?? "ecdsa-2019"} />
                <FieldRow label="Verification method" value={entry.proof?.verificationMethod} mono />
                <FieldRow label="Proof purpose" value={entry.proof?.proofPurpose} />
                {proofValue && (
                  <div className="pt-3">
                    <button
                      type="button"
                      onClick={() => setShowProof((value) => !value)}
                      className="inline-flex items-center gap-2 rounded-md px-2 py-1"
                      style={{ border: "1px solid var(--border)", backgroundColor: "var(--muted)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
                    >
                      {showProof ? "Hide proof" : "Show proof"}
                    </button>
                    {showProof && (
                      <div className="mt-2 rounded-md p-3" style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Proof value</span>
                          <CopyButton value={proofValue} label="Proof copied" />
                        </div>
                        <code style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", wordBreak: "break-all" }}>{proofValue}</code>
                      </div>
                    )}
                  </div>
                )}
              </DrawerSection>

              <DrawerSection title="Gossip Propagation" icon={RefreshCw}>
                <FieldRow label="Status" value={entry.propagated ? "Propagated" : "Pending"} />
                <FieldRow label="Peer acknowledgements" value={entry.peers_notified?.length ?? 0} />
                {(entry.peers_notified?.length ?? 0) > 0 ? (
                  <div className="flex flex-wrap gap-1.5 pt-2">
                    {entry.peers_notified?.map((peer) => (
                      <span key={peer} style={{ padding: "3px 7px", borderRadius: "var(--radius)", backgroundColor: "var(--muted)", border: "1px solid var(--border)", fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--foreground)", wordBreak: "break-all" }}>
                        {peer}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p style={{ marginTop: "8px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                    Schema fields are present. Active gossip acknowledgements may not be populated yet.
                  </p>
                )}
              </DrawerSection>
            </div>
          )}
        </div>

        <div className="p-4 flex flex-wrap gap-2" style={{ borderTop: "1px solid var(--border)" }}>
          <ActionButton icon={ShieldCheck} variant="secondary" onClick={() => onCheckDid(entry.revoked_did)}>
            Check DID
          </ActionButton>
          <ActionButton icon={Copy} variant="muted" onClick={() => copyValue(json, "Entry JSON copied")}>
            Copy Entry JSON
          </ActionButton>
          <ActionButton icon={ShieldX} variant="danger" disabled={!canAttemptUnrevoke} onClick={() => onUnrevoke(entry)}>
            Unrevoke DID
          </ActionButton>
        </div>
      </div>
    </div>
  );
}

function DrawerSection({ title, icon: Icon, children }: { title: string; icon: IconComponent; children: ReactNode }) {
  return (
    <section className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
      <div className="flex items-center gap-2 mb-3">
        <Icon size={15} style={{ color: "var(--primary)" }} />
        <SectionLabel>{title.toUpperCase()}</SectionLabel>
      </div>
      {children}
    </section>
  );
}

function RawJsonModal({ title, data, onClose }: { title: string; data: unknown; onClose: () => void }) {
  const [view, setView] = useState<RawView>("formatted");
  const formatted = JSON.stringify(data, null, 2);
  const raw = JSON.stringify(data);

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" style={{ backgroundColor: "rgba(0,0,0,0.55)" }} onClick={onClose}>
      <div className="w-full max-w-2xl rounded-lg border flex flex-col" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", maxHeight: "85dvh" }} onClick={(event) => event.stopPropagation()}>
        <div className="p-4 flex items-center justify-between gap-3" style={{ borderBottom: "1px solid var(--border)" }}>
          <div className="flex items-center gap-2 min-w-0">
            <FileJson size={18} style={{ color: "var(--primary)", flexShrink: 0 }} />
            <p className="truncate" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {title}
            </p>
          </div>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>
        <div className="p-4 flex flex-col gap-3 min-h-0">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex p-1 rounded-md" style={{ backgroundColor: "var(--muted)" }}>
              {(["formatted", "raw"] as const).map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setView(item)}
                  className="rounded px-3"
                  style={{
                    height: "30px",
                    border: view === item ? "1px solid var(--border)" : "none",
                    backgroundColor: view === item ? "var(--card)" : "transparent",
                    color: view === item ? "var(--foreground)" : "var(--muted-foreground)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: view === item ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                    textTransform: "capitalize",
                  }}
                >
                  {item}
                </button>
              ))}
            </div>
            <ActionButton icon={Copy} variant="muted" onClick={() => copyValue(formatted, "JSON copied")}>
              Copy JSON
            </ActionButton>
          </div>
          <div className="overflow-auto rounded-md border" style={{ borderColor: "var(--border)", backgroundColor: "var(--muted)" }}>
            <pre style={{ margin: 0, padding: "12px", fontFamily: "JetBrains Mono, monospace", fontSize: "11px", lineHeight: 1.5, color: "var(--foreground)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {view === "formatted" ? formatted : raw}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

function RevokeDialog({
  role,
  ownerDid,
  onClose,
  onRevoked,
  initialTarget,
}: {
  role: RoleKind;
  ownerDid?: string;
  onClose: () => void;
  onRevoked: (entry?: CrlEntry) => Promise<void>;
  initialTarget?: QuickRevokeTarget | null;
}) {
  const [did, setDid] = useState(initialTarget?.did ?? "");
  const [reason, setReason] = useState<CrlReason>("compromised");
  const [severity, setSeverity] = useState<CrlSeverity>("critical");
  const [deviceId, setDeviceId] = useState("");
  const [userId, setUserId] = useState("");
  const [note, setNote] = useState(initialTarget?.nodeName ? `Selected from DID node list: ${initialTarget.nodeName}` : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isMember = role === "member";
  const didValid = did.trim().startsWith("did:");
  const securityCritical = SECURITY_CRITICAL_REASONS.has(reason);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (!didValid) {
      setError("Full DID is required and must start with did:");
      return;
    }
    if (isMember && !securityCritical) {
      setError("Member revocations must use a security-critical reason.");
      return;
    }
    if (isMember && isOwnerDid(did, ownerDid)) {
      setError("Member nodes cannot revoke the admin/owner DID.");
      return;
    }
    if (isMember && !["critical", "high"].includes(severity)) {
      setError("Member revocations must be Critical or High severity.");
      return;
    }

    const payload: CrlRevokePayload = {
      did: did.trim(),
      reason,
      severity,
      device_id: deviceId.trim() || undefined,
      user_id: userId.trim() || undefined,
      note: note.trim() || undefined,
    };

    setBusy(true);
    try {
      const response = await crlService.revoke(payload);
      toast.success(response.message || "CRL entry issued");
      await onRevoked(response.entry);
      onClose();
    } catch (err) {
      const message = mapCrlError(errorMessage(err));
      setError(message);
      toast.error("Revoke failed", { description: message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" style={{ backgroundColor: "rgba(0,0,0,0.55)" }} onClick={onClose}>
      <form
        onSubmit={submit}
        className="w-full max-w-lg rounded-lg border flex flex-col"
        style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", maxHeight: "calc(100dvh - 32px)" }}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="p-4 flex items-start justify-between gap-3" style={{ borderBottom: "1px solid var(--border)" }}>
          <div className="flex items-start gap-3">
            <div className="flex items-center justify-center rounded-md" style={{ width: "38px", height: "38px", backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)", color: "var(--destructive)" }}>
              <ShieldX size={18} />
            </div>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Revoke DID</p>
              <p style={{ marginTop: "2px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                Issue a signed CRL entry for a Guardian DID.
              </p>
            </div>
          </div>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>

        <div className="p-4 overflow-y-auto flex flex-col gap-4">
          {error && (
            <div className="rounded-md border p-3 flex gap-2" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)", borderColor: "color-mix(in srgb, var(--destructive) 24%, transparent)" }}>
              <AlertTriangle size={14} style={{ color: "var(--destructive)", flexShrink: 0, marginTop: "2px" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>{error}</span>
            </div>
          )}

          {initialTarget && (
            <div className="rounded-md border p-3 flex items-start gap-3" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 6%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 18%, transparent)" }}>
              <div className="flex items-center justify-center rounded-md flex-shrink-0" style={{ width: "32px", height: "32px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", color: "var(--primary)" }}>
                <Fingerprint size={15} />
              </div>
              <div className="min-w-0 flex-1">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                  {initialTarget.nodeName || "Selected DID node"}
                </p>
                <div className="mt-1">
                  <MonoValue value={initialTarget.did} truncate={false} />
                </div>
              </div>
            </div>
          )}

          <TextField label="DID" value={did} onChange={setDid} placeholder="did:guardian:..." mono required />

          <div className="grid sm:grid-cols-2 gap-3">
            <label className="flex flex-col gap-1.5">
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Reason *</span>
              <select
                value={reason}
                onChange={(event) => setReason(event.target.value as CrlReason)}
                style={dialogSelectStyle}
              >
                {REASONS.map((item) => (
                  <option key={item.value} value={item.value} disabled={isMember && !SECURITY_CRITICAL_REASONS.has(item.value)}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1.5">
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Severity *</span>
              <select
                value={severity}
                onChange={(event) => setSeverity(event.target.value as CrlSeverity)}
                style={dialogSelectStyle}
              >
                {SEVERITIES.map((item) => (
                  <option key={item.value} value={item.value} disabled={isMember && !["critical", "high"].includes(item.value)}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {securityCritical && (
            <div className="rounded-md border p-3 flex gap-2" style={{ backgroundColor: "color-mix(in srgb, var(--chart-4) 8%, transparent)", borderColor: "color-mix(in srgb, var(--chart-4) 24%, transparent)" }}>
              <AlertTriangle size={14} style={{ color: "var(--chart-4)", flexShrink: 0, marginTop: "2px" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-4)", lineHeight: 1.45 }}>
                Security-critical revocations may trigger emergency propagation and session termination behavior on the backend.
              </span>
            </div>
          )}

          <div className="grid sm:grid-cols-2 gap-3">
            <TextField label="Device ID" value={deviceId} onChange={setDeviceId} placeholder="se050-nodeB-001" mono />
            <TextField label="User ID" value={userId} onChange={setUserId} placeholder="user-nodeB" mono />
          </div>

          <label className="flex flex-col gap-1.5">
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Audit note</span>
            <textarea
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Optional operational note"
              style={{
                minHeight: "82px",
                resize: "vertical",
                borderRadius: "var(--radius)",
                border: "1px solid var(--border)",
                backgroundColor: "var(--input-background)",
                color: "var(--foreground)",
                padding: "10px 11px",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                outline: "none",
              }}
            />
          </label>
        </div>

        <div className="p-4 flex justify-end gap-2" style={{ borderTop: "1px solid var(--border)" }}>
          <ActionButton icon={X} variant="muted" onClick={onClose}>Cancel</ActionButton>
          <ActionButton icon={ShieldX} variant="danger" type="submit" loading={busy}>Revoke DID</ActionButton>
        </div>
      </form>
    </div>
  );
}

const dialogSelectStyle: CSSProperties = {
  height: "38px",
  borderRadius: "var(--radius)",
  border: "1px solid var(--border)",
  backgroundColor: "var(--input-background)",
  color: "var(--foreground)",
  padding: "0 11px",
  fontFamily: "Inter, sans-serif",
  fontSize: "var(--text-xs)",
  outline: "none",
};

function UnrevokeDialog({
  entry,
  onClose,
  onConfirm,
}: {
  entry: CrlEntry;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);

  async function handleConfirm() {
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" style={{ backgroundColor: "rgba(0,0,0,0.55)" }} onClick={onClose}>
      <div className="w-full max-w-md rounded-lg border p-5 flex flex-col gap-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }} onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="flex items-center justify-center rounded-md" style={{ width: "38px", height: "38px", backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)", color: "var(--destructive)" }}>
              <ShieldX size={18} />
            </div>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Unrevoke DID?</p>
              <p style={{ marginTop: "2px", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                Only the Circle owner can unrevoke a DID. This removes the active CRL entry and recomputes the Merkle root.
              </p>
            </div>
          </div>
          <IconButton label="Close" icon={X} onClick={onClose} />
        </div>

        <div className="rounded-md border p-3 flex flex-col gap-2" style={{ backgroundColor: "var(--muted)", borderColor: "var(--border)" }}>
          <MonoValue value={entry.revoked_did} truncate={false} />
          <div className="flex flex-wrap gap-1.5">
            <SeverityBadge severity={entry.severity} />
            <ReasonBadge reason={entry.reason} />
          </div>
        </div>

        <div className="flex justify-end gap-2">
          <ActionButton icon={X} variant="muted" onClick={onClose}>Cancel</ActionButton>
          <ActionButton icon={ShieldX} variant="danger" onClick={handleConfirm} loading={busy}>Unrevoke</ActionButton>
        </div>
      </div>
    </div>
  );
}

function mapCrlError(message: string) {
  const lower = message.toLowerCase();
  if (lower.includes("already revoked")) return "This DID already has an active CRL entry.";
  if (lower.includes("revoker may not revoke themselves") || lower.includes("self")) return "The local revoker cannot revoke itself.";
  if (lower.includes("revoke the circle owner")) return "Member nodes cannot revoke the admin/owner DID.";
  if (lower.includes("unauthorized") || lower.includes("not authorized")) return "This node is not authorized to issue that CRL entry.";
  if (lower.includes("only the circle owner") || lower.includes("owner can unrevoke")) return "Only the Circle owner can unrevoke a DID.";
  return message;
}

export function SC05CRLStatus() {
  const navigate = useNavigate();
  const currentUser = useCurrentUser();
  const { data: ownVcData } = useVCShow({ scope: "own", status: "active" });
  const { data: vcSummaryData } = useVCSummary();
  const localVcRole = useMemo(() => {
    const activeOwn = ownVcData?.items.find((item) => normalize(item.membership_status) === "active") ?? ownVcData?.items[0];
    return roleKind(activeOwn?.role);
  }, [ownVcData]);
  const currentRole = localVcRole !== "unknown" ? localVcRole : roleKind(currentUser.role);
  const ownerDid = vcSummaryData?.owner_did;
  const canRevoke = currentRole !== "viewer";
  const canAttemptUnrevoke = currentRole === "owner";
  const { data: didPeersData, loading: didPeersLoading, error: didPeersError, refetch: refetchDidPeers } = useDIDDocumentPeers();

  const [entries, setEntries] = useState<CrlEntry[]>([]);
  const [listRaw, setListRaw] = useState<CrlListResponse | null>(null);
  const [root, setRoot] = useState<CrlRootResponse | null>(null);
  const [rootRaw, setRootRaw] = useState<CrlRootResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [rootError, setRootError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const [verifyResult, setVerifyResult] = useState<CrlVerifyResponse | null>(null);
  const [verifyCheckedAt, setVerifyCheckedAt] = useState<string | null>(null);
  const [verifyRaw, setVerifyRaw] = useState<CrlVerifyResponse | null>(null);
  const [verifyStale, setVerifyStale] = useState(false);
  const [verifying, setVerifying] = useState(false);

  const [didInput, setDidInput] = useState("");
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<{ did: string; revoked: boolean; entry?: CrlEntry | null } | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [reasonFilter, setReasonFilter] = useState("all");
  const [propagationFilter, setPropagationFilter] = useState("all");
  const [roleFilter, setRoleFilter] = useState("all");
  const [dateFilter, setDateFilter] = useState<DateFilter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");

  const [selectedEntry, setSelectedEntry] = useState<CrlEntry | null>(null);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<QuickRevokeTarget | null>(null);
  const [peerRefreshing, setPeerRefreshing] = useState(false);
  const [unrevokeTarget, setUnrevokeTarget] = useState<CrlEntry | null>(null);
  const [rawModal, setRawModal] = useState<{ title: string; data: unknown } | null>(null);

  const [entryLookup, setEntryLookup] = useState("");
  const [entryLookupBusy, setEntryLookupBusy] = useState(false);
  const [entryLookupError, setEntryLookupError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<"crl" | "gossip" | "emergency" | "offline">("crl");

  const loadCrl = useCallback(async (initial = false) => {
    if (initial) setLoading(true);
    else setRefreshing(true);
    setListError(null);
    setRootError(null);

    const [listResult, rootResult] = await Promise.allSettled([
      crlService.list(),
      crlService.root(),
    ]);

    if (listResult.status === "fulfilled") {
      setListRaw(listResult.value);
      setEntries(listResult.value.entries);
      setSelectedEntry((previous) => {
        if (!previous) return previous;
        const fresh = listResult.value.entries.find((entry) => (entry.id && entry.id === previous.id) || entry.revoked_did === previous.revoked_did);
        return fresh ?? previous;
      });
    } else {
      setListError(errorMessage(listResult.reason));
    }

    if (rootResult.status === "fulfilled") {
      setRoot(rootResult.value);
      setRootRaw(rootResult.value);
    } else {
      setRootError(errorMessage(rootResult.reason));
    }

    setLastUpdated(new Date().toISOString());
    if (initial) setLoading(false);
    else setRefreshing(false);
  }, []);

  useEffect(() => {
    loadCrl(true);
  }, [loadCrl]);

  const didPeers = useMemo(() => didPeersData?.peers ?? [], [didPeersData]);

  const filteredEntries = useMemo(() => {
    const now = Date.now();
    const rangeMs =
      dateFilter === "24h" ? 24 * 60 * 60 * 1000
        : dateFilter === "7d" ? 7 * 24 * 60 * 60 * 1000
          : dateFilter === "30d" ? 30 * 24 * 60 * 60 * 1000
            : null;
    const query = normalize(search);

    const filtered = entries.filter((entry) => {
      if (severityFilter !== "all" && normalize(entry.severity) !== severityFilter) return false;
      if (reasonFilter !== "all" && normalize(entry.reason) !== reasonFilter) return false;
      if (propagationFilter === "propagated" && !entry.propagated) return false;
      if (propagationFilter === "pending" && entry.propagated) return false;
      if (roleFilter !== "all" && normalize(entry.revoker_role) !== roleFilter) return false;
      if (rangeMs !== null) {
        const ts = timestampValue(entry.timestamp);
        if (!ts || now - ts > rangeMs) return false;
      }
      if (!query) return true;
      return [
        entry.id,
        entry.revoked_did,
        entry.device_id,
        entry.user_id,
        entry.circle_id,
        entry.revoker_did,
        entry.revoker_role,
        entry.reason,
        entry.severity,
      ].some((value) => normalize(value).includes(query));
    });

    return [...filtered].sort((a, b) => {
      let value = 0;
      if (sortKey === "severity") {
        value = (severityRank[normalize(a.severity)] ?? 0) - (severityRank[normalize(b.severity)] ?? 0);
      } else if (sortKey === "reason") {
        value = reasonLabel(a.reason).localeCompare(reasonLabel(b.reason));
      } else {
        value = timestampValue(a.timestamp) - timestampValue(b.timestamp);
      }
      if (value === 0) {
        value = (severityRank[normalize(a.severity)] ?? 0) - (severityRank[normalize(b.severity)] ?? 0);
      }
      return sortDirection === "asc" ? value : -value;
    });
  }, [dateFilter, entries, propagationFilter, reasonFilter, roleFilter, search, severityFilter, sortDirection, sortKey]);

  function handleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDirection((value) => (value === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(key);
    setSortDirection(key === "timestamp" || key === "severity" ? "desc" : "asc");
  }

  async function handleVerify() {
    setVerifying(true);
    try {
      const result = await crlService.verify();
      setVerifyResult(result);
      setVerifyRaw(result);
      setVerifyCheckedAt(new Date().toISOString());
      setVerifyStale(false);
      if (result.ok) {
        toast.success("CRL verified");
      } else {
        toast.error("CRL verification failed", { description: result.errors.join(", ") || "Integrity check returned invalid" });
      }
    } catch (err) {
      const message = errorMessage(err);
      toast.error("CRL verification failed", { description: message });
      setVerifyResult({ ok: false, errors: [message] });
      setVerifyRaw({ ok: false, errors: [message] });
      setVerifyCheckedAt(new Date().toISOString());
    } finally {
      setVerifying(false);
    }
  }

  async function handleRefreshRoot() {
    setRootError(null);
    try {
      const result = await crlService.root();
      setRoot(result);
      setRootRaw(result);
      toast.success("CRL root refreshed");
    } catch (err) {
      const message = errorMessage(err);
      setRootError(message);
      toast.error("Root refresh failed", { description: message });
    }
  }

  async function handleCheckDid(customDid?: string) {
    const did = (customDid ?? didInput).trim();
    if (!did.startsWith("did:")) {
      setCheckError("Use the full did:guardian:... value.");
      setCheckResult(null);
      return;
    }
    setDidInput(did);
    setChecking(true);
    setCheckError(null);
    try {
      const result = await crlService.check(did);
      setCheckResult({ did: result.did ?? did, revoked: result.revoked, entry: result.entry });
    } catch (err) {
      setCheckResult(null);
      setCheckError(errorMessage(err));
    } finally {
      setChecking(false);
    }
  }

  async function openEntry(entry: CrlEntry) {
    if (!entry.id) {
      setSelectedEntry(entry);
      return;
    }
    setSelectedEntry(entry);
    try {
      const fresh = await crlService.getEntry(entry.id);
      setSelectedEntry(fresh);
    } catch {
      // Keep the list item visible if the compact detail lookup is unavailable.
    }
  }

  async function lookupEntry() {
    const id = entryLookup.trim();
    if (!id) return;
    setEntryLookupBusy(true);
    setEntryLookupError(null);
    try {
      const entry = await crlService.getEntry(id);
      setSelectedEntry(entry);
    } catch (err) {
      setEntryLookupError(errorMessage(err));
    } finally {
      setEntryLookupBusy(false);
    }
  }

  async function afterMutation(entry?: CrlEntry) {
    setVerifyStale(true);
    await loadCrl(false);
    if (entry) setSelectedEntry(entry);
  }

  async function refreshDidPeers() {
    setPeerRefreshing(true);
    try {
      await refetchDidPeers();
    } finally {
      setPeerRefreshing(false);
    }
  }

  function openManualRevoke() {
    setRevokeTarget(null);
    setRevokeOpen(true);
  }

  function openPeerRevoke(peer: DIDDocumentPeerSummary) {
    if (!canRevokeDid(currentRole, peer.did, ownerDid)) {
      toast.error("Protected DID", { description: "Member nodes cannot revoke the admin/owner DID." });
      return;
    }
    setRevokeTarget({ did: peer.did, nodeName: peer.node_name });
    setRevokeOpen(true);
  }

  async function confirmUnrevoke() {
    if (!unrevokeTarget) return;
    try {
      const response = await crlService.unrevoke(unrevokeTarget.revoked_did);
      toast.success(response.message || "CRL entry unrevoked");
      const targetDid = unrevokeTarget.revoked_did;
      setUnrevokeTarget(null);
      setSelectedEntry((entry) => (entry?.revoked_did === targetDid ? null : entry));
      if (checkResult?.did === targetDid) {
        setCheckResult({ did: targetDid, revoked: false, entry: null });
      }
      await afterMutation();
    } catch (err) {
      const message = mapCrlError(errorMessage(err));
      toast.error("Unrevoke failed", { description: message });
      throw err;
    }
  }

  const headerActions = (
    <div className="hidden sm:flex items-center gap-2">
      <ActionButton icon={ShieldCheck} variant={verifyResult?.ok ? "success" : "primary"} onClick={handleVerify} loading={verifying}>
        Verify CRL
      </ActionButton>
      {canRevoke && (
        <ActionButton icon={ShieldX} variant="danger" onClick={openManualRevoke}>
          Revoke DID
        </ActionButton>
      )}
      <IconButton label="Refresh CRL" icon={RefreshCw} onClick={() => loadCrl(false)} disabled={refreshing} color="var(--primary)" />
    </div>
  );

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Certificate Revocation List"
        subtitle="Revoked DIDs, CRL integrity, and propagation status"
        onBack={() => navigate("/settings")}
        right={headerActions}
      />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1180px] p-4 md:p-6 flex flex-col gap-4">
          <div className="flex rounded-lg border border-border bg-card p-1" role="tablist" aria-label="CRL sections">
            <button type="button" role="tab" aria-selected={activeSection === "crl"} onClick={() => setActiveSection("crl")} className={`flex-1 rounded-md px-4 py-2.5 text-sm font-semibold transition ${activeSection === "crl" ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>CRL entries</button>
            <button type="button" role="tab" aria-selected={activeSection === "gossip"} onClick={() => setActiveSection("gossip")} className={`flex-1 rounded-md px-4 py-2.5 text-sm font-semibold transition ${activeSection === "gossip" ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>Gossip</button>
            <button type="button" role="tab" aria-selected={activeSection === "emergency"} onClick={() => setActiveSection("emergency")} className={`flex-1 rounded-md px-4 py-2.5 text-sm font-semibold transition ${activeSection === "emergency" ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>Emergency revocation</button>
            <button type="button" role="tab" aria-selected={activeSection === "offline"} onClick={() => setActiveSection("offline")} className={`flex-1 rounded-md px-4 py-2.5 text-sm font-semibold transition ${activeSection === "offline" ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>Offline revocation</button>
          </div>
          {activeSection === "gossip" ? <CrlOperationsPanel section="gossip" /> : activeSection === "emergency" ? <CrlOperationsPanel section="emergency" /> : activeSection === "offline" ? <CrlOperationsPanel section="offline" /> : <>
          <div className="sm:hidden grid grid-cols-2 gap-2">
            <ActionButton icon={ShieldCheck} variant={verifyResult?.ok ? "success" : "primary"} onClick={handleVerify} loading={verifying}>
              Verify CRL
            </ActionButton>
            {canRevoke && (
              <ActionButton icon={ShieldX} variant="danger" onClick={openManualRevoke}>
                Revoke DID
              </ActionButton>
            )}
            <div className="col-span-2">
              <ActionButton icon={RefreshCw} variant="muted" onClick={() => loadCrl(false)} loading={refreshing}>
                Refresh
              </ActionButton>
            </div>
          </div>

          <SummaryCards
            entries={entries}
            root={root}
            verifyResult={verifyResult}
            verifyCheckedAt={verifyCheckedAt}
            verifyStale={verifyStale}
            loading={loading}
          />

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
            <main className="flex flex-col gap-4 min-w-0">
              <DidNodesPanel
                peers={didPeers}
                entries={entries}
                loading={didPeersLoading}
                error={didPeersError}
                refreshing={peerRefreshing}
                canRevoke={canRevoke}
                localRole={currentRole}
                ownerDid={ownerDid}
                onRefresh={refreshDidPeers}
                onRevoke={openPeerRevoke}
                onCheckDid={(did) => handleCheckDid(did)}
                onViewEntry={openEntry}
              />
              <EntriesSection
                entries={entries}
                filteredEntries={filteredEntries}
                loading={loading}
                error={listError}
                search={search}
                setSearch={setSearch}
                severityFilter={severityFilter}
                setSeverityFilter={setSeverityFilter}
                reasonFilter={reasonFilter}
                setReasonFilter={setReasonFilter}
                propagationFilter={propagationFilter}
                setPropagationFilter={setPropagationFilter}
                roleFilter={roleFilter}
                setRoleFilter={setRoleFilter}
                dateFilter={dateFilter}
                setDateFilter={setDateFilter}
                sortKey={sortKey}
                sortDirection={sortDirection}
                onSort={handleSort}
                onView={openEntry}
                onCheckDid={(did) => handleCheckDid(did)}
                onUnrevoke={(entry) => setUnrevokeTarget(entry)}
                canAttemptUnrevoke={canAttemptUnrevoke}
                onRetry={() => loadCrl(false)}
                lastUpdated={lastUpdated}
                onRaw={() => listRaw && setRawModal({ title: "CRL List Response", data: listRaw })}
              />
            </main>

            <aside className="flex flex-col gap-4 min-w-0">
              <IntegrityPanel
                root={root}
                rootError={rootError}
                verifying={verifying}
                verifyResult={verifyResult}
                verifyCheckedAt={verifyCheckedAt}
                verifyStale={verifyStale}
                onVerify={handleVerify}
                onRefreshRoot={handleRefreshRoot}
                onRawRoot={() => rootRaw && setRawModal({ title: "CRL Root Response", data: rootRaw })}
                onRawVerify={() => verifyRaw && setRawModal({ title: "CRL Verify Result", data: verifyRaw })}
              />
              <DidCheckPanel
                didInput={didInput}
                setDidInput={setDidInput}
                checking={checking}
                checkResult={checkResult}
                checkError={checkError}
                onCheck={() => handleCheckDid()}
                onViewEntry={(entry) => openEntry(entry)}
                onUnrevoke={(entry) => setUnrevokeTarget(entry)}
                canAttemptUnrevoke={canAttemptUnrevoke}
              />
              <EntryLookupPanel
                value={entryLookup}
                setValue={setEntryLookup}
                loading={entryLookupBusy}
                error={entryLookupError}
                onLookup={lookupEntry}
              />
            </aside>
          </div>
          </>}
        </div>
      </div>

      {selectedEntry && (
        <EntryDrawer
          entry={selectedEntry}
          onClose={() => setSelectedEntry(null)}
          onCheckDid={(did) => handleCheckDid(did)}
          onUnrevoke={(entry) => setUnrevokeTarget(entry)}
          canAttemptUnrevoke={canAttemptUnrevoke}
        />
      )}
      {revokeOpen && (
        <RevokeDialog
          role={currentRole}
          ownerDid={ownerDid}
          initialTarget={revokeTarget}
          onClose={() => {
            setRevokeOpen(false);
            setRevokeTarget(null);
          }}
          onRevoked={afterMutation}
        />
      )}
      {unrevokeTarget && (
        <UnrevokeDialog
          entry={unrevokeTarget}
          onClose={() => setUnrevokeTarget(null)}
          onConfirm={confirmUnrevoke}
        />
      )}
      {rawModal && (
        <RawJsonModal
          title={rawModal.title}
          data={rawModal.data}
          onClose={() => setRawModal(null)}
        />
      )}
    </div>
  );
}
