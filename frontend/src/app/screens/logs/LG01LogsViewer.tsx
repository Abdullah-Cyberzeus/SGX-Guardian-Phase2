import { useEffect, useState, useMemo } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  FileText,
  Search,
  Filter,
  Download,
  RefreshCw,
  Info,
  AlertTriangle,
  XCircle,
  Bug,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  X,
  Check,
  Server,
  Loader2,
  Code2,
  Copy,
  CheckCircle2,
  Braces,
  ShieldCheck,
  ListChecks,
  Fingerprint,
  ShieldAlert,
  AlertOctagon,
} from "lucide-react";
import type { LogEntry, LogLevel, LogCategory } from "../../data/mockData";
import { useLogs, useAuditLogs } from "../../hooks/useApiData";
import type { AuditLogEntry } from "../../services/auditLogService";
import { toast } from "sonner";

// --- JSON-payload parsing ---
// Many guardian log entries arrive as a single JSON blob crammed into
// `message`. Parse it once per row so the collapsed display can use a clean
// summary and the expanded view can render structured fields.

type ParsedLog =
  | { kind: "json"; summary: string; summaryKey?: string; fields: Array<[string, unknown]>; raw: string }
  | { kind: "plain"; summary: string; raw: string };

const PRIMARY_KEYS = ["msg", "message", "event", "log-message", "log_message"];
const FIRST_ORDER = ["timestamp", "time", "level", "node", "service", "source"];

function parseLog(text: string | undefined | null): ParsedLog {
  const raw = (text ?? "").trim();
  if (!raw.startsWith("{") || !raw.endsWith("}")) {
    return { kind: "plain", summary: raw, raw };
  }
  try {
    const obj = JSON.parse(raw);
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
      return { kind: "plain", summary: raw, raw };
    }
    const o = obj as Record<string, unknown>;
    const summaryKey = PRIMARY_KEYS.find(k => typeof o[k] === "string" && (o[k] as string).length > 0);
    const summary = summaryKey ? String(o[summaryKey]) : raw;
    // Stable ordering: known headline fields first, then the rest alpha.
    const keys = Object.keys(o);
    const ordered: string[] = [
      ...FIRST_ORDER.filter(k => keys.includes(k)),
      ...keys.filter(k => !FIRST_ORDER.includes(k)).sort(),
    ];
    const fields = ordered.map(k => [k, o[k]] as [string, unknown]);
    return { kind: "json", summary, summaryKey, fields, raw: JSON.stringify(o, null, 2) };
  } catch {
    return { kind: "plain", summary: raw, raw };
  }
}

function formatFieldValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

// Compact secondary context for the collapsed row: a few short scalar fields
// (excluding the one already used as the headline) so JSON logs read like
// "ADVERTISE  ·  node=nodeA  ·  service=_sgx-guardian._tcp" at a glance.
function buildContext(parsed: ParsedLog): string {
  if (parsed.kind !== "json") return "";
  return parsed.fields
    .filter(([k]) => k !== parsed.summaryKey)
    .filter(([, v]) => {
      const t = typeof v;
      return (t === "string" || t === "number" || t === "boolean") && String(v).length <= 48;
    })
    .slice(0, 3)
    .map(([k, v]) => `${k}=${v}`)
    .join("  ·  ");
}

// Lightweight JSON syntax highlighting for the raw payload view — matches the
// policy YAML view's palette (keys=primary, strings=chart-2, numbers/bools=chart-4).
function HighlightedJson({ json }: { json: string }) {
  const nodes: React.ReactNode[] = [];
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0;
  let i = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(json)) !== null) {
    if (m.index > last) nodes.push(json.slice(last, m.index));
    if (m[1] !== undefined) {
      const isKey = m[2] !== undefined;
      nodes.push(
        <span key={i++} style={{ color: isKey ? "var(--primary)" : "var(--chart-2)" }}>{m[1]}</span>,
      );
      if (m[2] !== undefined) {
        nodes.push(<span key={i++} style={{ color: "var(--muted-foreground)" }}>{m[2]}</span>);
      }
    } else if (m[3] !== undefined || m[4] !== undefined) {
      nodes.push(<span key={i++} style={{ color: "var(--chart-4)" }}>{m[3] ?? m[4]}</span>);
    }
    last = re.lastIndex;
  }
  if (last < json.length) nodes.push(json.slice(last));
  return <>{nodes}</>;
}

// Log Level Badge
function LevelBadge({ level }: { level: LogLevel }) {
  const config = {
    info: { icon: Info, color: "var(--primary)", bg: "var(--primary)" },
    warning: { icon: AlertTriangle, color: "var(--chart-5)", bg: "var(--chart-5)" },
    error: { icon: XCircle, color: "var(--destructive)", bg: "var(--destructive)" },
    debug: { icon: Bug, color: "var(--muted-foreground)", bg: "var(--muted-foreground)" },
  };

  const { icon: Icon, color, bg } = config[level];

  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
      style={{
        backgroundColor: `color-mix(in srgb, ${bg} 15%, transparent)`,
        color: color,
        fontFamily: "JetBrains Mono, monospace",
        fontSize: "10px",
      }}
    >
      <Icon size={10} />
      {level}
    </span>
  );
}

// Category Badge
function CategoryBadge({ category }: { category: LogCategory }) {
  return (
    <span
      className="px-2 py-0.5 rounded"
      style={{
        backgroundColor: "var(--muted)",
        color: "var(--muted-foreground)",
        fontFamily: "JetBrains Mono, monospace",
        fontSize: "10px",
      }}
    >
      {category}
    </span>
  );
}

// Log Entry Row
function LogRow({ entry, isExpanded, onToggle }: { entry: LogEntry; isExpanded: boolean; onToggle: () => void }) {
  const [showRaw, setShowRaw] = useState(false);
  const [copied, setCopied] = useState(false);

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  };

  // Parse both message and details — fall back to whichever yielded structure.
  const parsedMessage = useMemo(() => parseLog(entry.message), [entry.message]);
  const parsedDetails = useMemo(
    () => (entry.details ? parseLog(entry.details) : null),
    [entry.details],
  );
  const parsed: ParsedLog =
    parsedMessage.kind === "json"
      ? parsedMessage
      : parsedDetails?.kind === "json"
      ? parsedDetails
      : parsedMessage;
  const summary = parsed.summary || entry.message;
  const context = useMemo(() => buildContext(parsed), [parsed]);

  const handleCopy = () => {
    navigator.clipboard.writeText(parsed.raw).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div
      className="border-b transition-colors"
      style={{
        borderColor: "var(--border)",
        backgroundColor: isExpanded ? "color-mix(in srgb, var(--primary) 5%, transparent)" : "transparent",
      }}
    >
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 p-3 text-left"
        style={{ border: "none", cursor: "pointer", backgroundColor: "transparent" }}
      >
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "11px",
            color: "var(--muted-foreground)",
            minWidth: "70px",
            flexShrink: 0,
          }}
        >
          {formatTime(entry.timestamp)}
        </span>
        <LevelBadge level={entry.level} />
        <CategoryBadge category={entry.category} />
        <span
          className="flex-1 min-w-0"
          style={{
            display: "block",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--foreground)",
          }}
          title={context ? `${summary}  ·  ${context}` : summary}
        >
          {summary}
          {context && (
            <span
              style={{
                marginLeft: "10px",
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "11px",
                color: "var(--muted-foreground)",
              }}
            >
              {context}
            </span>
          )}
        </span>
        {parsed.kind === "json" && (
          <span
            className="inline-flex items-center gap-1"
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "10px",
              color: "var(--primary)",
              backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)",
              padding: "2px 6px",
              borderRadius: "4px",
              flexShrink: 0,
            }}
            title={`${parsed.fields.length} structured fields — expand to view`}
          >
            <Braces size={10} />
            {parsed.fields.length}
          </span>
        )}
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "10px",
            color: "var(--muted-foreground)",
            backgroundColor: "var(--muted)",
            padding: "2px 6px",
            borderRadius: "4px",
            flexShrink: 0,
          }}
        >
          {entry.node}
        </span>
        {isExpanded ? (
          <ChevronUp size={14} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
        ) : (
          <ChevronDown size={14} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
        )}
      </button>

      {isExpanded && (
        <div
          className="px-3 pb-3"
          style={{
            marginLeft: "calc(70px + 12px)",
            borderLeft: "2px solid color-mix(in srgb, var(--primary) 40%, var(--border))",
            paddingLeft: "12px",
          }}
          onClick={e => e.stopPropagation()}
        >
          {/* Toolbar */}
          <div className="flex items-center gap-2 mb-2">
            {parsed.kind === "json" && (
              <button
                onClick={() => setShowRaw(v => !v)}
                className="flex items-center gap-1.5 rounded-md"
                style={{
                  padding: "4px 8px",
                  border: "1px solid var(--border)",
                  backgroundColor: showRaw ? "var(--muted)" : "transparent",
                  color: "var(--foreground)",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "11px",
                  fontWeight: "var(--font-weight-medium)",
                  cursor: "pointer",
                }}
                title={showRaw ? "Switch to structured view" : "Show raw JSON"}
              >
                <Code2 size={11} />
                {showRaw ? "Structured" : "Raw JSON"}
              </button>
            )}
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 rounded-md"
              style={{
                padding: "4px 8px",
                border: "1px solid var(--border)",
                backgroundColor: "transparent",
                color: "var(--foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "11px",
                fontWeight: "var(--font-weight-medium)",
                cursor: "pointer",
              }}
              title="Copy raw payload to clipboard"
            >
              {copied ? (
                <CheckCircle2 size={11} style={{ color: "var(--chart-2)" }} />
              ) : (
                <Copy size={11} />
              )}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>

          {parsed.kind === "json" && !showRaw ? (
            <div
              className="rounded-md"
              style={{
                border: "1px solid var(--border)",
                backgroundColor: "var(--card)",
                overflow: "hidden",
              }}
            >
              {parsed.fields.map(([k, v], i, arr) => (
                <div
                  key={k}
                  className="flex items-start gap-3 px-3 py-1.5"
                  style={{
                    borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined,
                  }}
                >
                  <span
                    style={{
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: "11px",
                      color: "var(--muted-foreground)",
                      minWidth: "120px",
                      flexShrink: 0,
                    }}
                  >
                    {k}
                  </span>
                  <span
                    style={{
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: "11px",
                      color: "var(--foreground)",
                      wordBreak: "break-all",
                      flex: 1,
                    }}
                  >
                    {formatFieldValue(v)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <pre
              className="rounded-md p-3"
              style={{
                border: "1px solid var(--border)",
                backgroundColor: "var(--muted)",
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "11px",
                color: "var(--foreground)",
                lineHeight: 1.55,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                margin: 0,
                overflow: "auto",
                maxHeight: "320px",
              }}
            >
              {parsed.kind === "json" ? <HighlightedJson json={parsed.raw} /> : parsed.raw || summary}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// Filter Chip
function FilterChip({
  label,
  active,
  onClick,
  count,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  count?: number;
}) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-colors"
      style={{
        backgroundColor: active ? "var(--primary)" : "var(--secondary)",
        color: active ? "var(--primary-foreground)" : "var(--secondary-foreground)",
        border: "none",
        cursor: "pointer",
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: active ? "var(--font-weight-semibold)" : "var(--font-weight-medium)",
      }}
    >
      {label}
      {count !== undefined && (
        <span
          style={{
            backgroundColor: active ? "rgba(255,255,255,0.2)" : "var(--muted)",
            padding: "0 6px",
            borderRadius: "10px",
            fontSize: "10px",
          }}
        >
          {count}
        </span>
      )}
    </button>
  );
}

// --- Audit Logs (hash-chained audit trail) ---

const AUDIT_SEVERITY_CONFIG: Record<string, { icon: typeof Info; color: string }> = {
  Info: { icon: Info, color: "var(--primary)" },
  Warning: { icon: ShieldAlert, color: "var(--chart-5)" },
  Critical: { icon: AlertOctagon, color: "var(--destructive)" },
};

function AuditSeverityBadge({ severity }: { severity: string }) {
  const { icon: Icon, color } = AUDIT_SEVERITY_CONFIG[severity] || AUDIT_SEVERITY_CONFIG.Info;
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
      style={{
        backgroundColor: `color-mix(in srgb, ${color} 15%, transparent)`,
        color,
        fontFamily: "JetBrains Mono, monospace",
        fontSize: "10px",
      }}
    >
      <Icon size={10} />
      {severity}
    </span>
  );
}

function AuditCategoryBadge({ category }: { category: string }) {
  return (
    <span
      className="px-2 py-0.5 rounded"
      style={{
        backgroundColor: "var(--muted)",
        color: "var(--muted-foreground)",
        fontFamily: "JetBrains Mono, monospace",
        fontSize: "10px",
      }}
    >
      {category}
    </span>
  );
}

function formatAuditTime(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function truncateHash(hash: string): string {
  if (!hash || hash.length <= 16) return hash || "—";
  return `${hash.slice(0, 8)}…${hash.slice(-8)}`;
}

function AuditLogRow({
  entry,
  isExpanded,
  onToggle,
}: {
  entry: AuditLogEntry;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const { event, hash, previous_hash } = entry;

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(entry, null, 2)).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div
      className="border-b transition-colors"
      style={{
        borderColor: "var(--border)",
        backgroundColor: isExpanded ? "color-mix(in srgb, var(--primary) 5%, transparent)" : "transparent",
      }}
    >
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 p-3 text-left"
        style={{ border: "none", cursor: "pointer", backgroundColor: "transparent" }}
      >
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "11px",
            color: "var(--muted-foreground)",
            minWidth: "70px",
            flexShrink: 0,
          }}
        >
          {formatAuditTime(event.timestamp)}
        </span>
        <AuditSeverityBadge severity={event.severity} />
        <AuditCategoryBadge category={event.category} />
        <span
          className="flex-1 min-w-0"
          style={{
            display: "block",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--foreground)",
          }}
          title={event.message}
        >
          {event.message}
          <span
            style={{
              marginLeft: "10px",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "11px",
              color: "var(--muted-foreground)",
            }}
          >
            {event.action}
          </span>
        </span>
        <span
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "10px",
            color: "var(--muted-foreground)",
            backgroundColor: "var(--muted)",
            padding: "2px 6px",
            borderRadius: "4px",
            flexShrink: 0,
          }}
        >
          {event.node_id}
        </span>
        {isExpanded ? (
          <ChevronUp size={14} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
        ) : (
          <ChevronDown size={14} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
        )}
      </button>

      {isExpanded && (
        <div
          className="px-3 pb-3"
          style={{
            marginLeft: "calc(70px + 12px)",
            borderLeft: "2px solid color-mix(in srgb, var(--primary) 40%, var(--border))",
            paddingLeft: "12px",
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center gap-2 mb-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 rounded-md"
              style={{
                padding: "4px 8px",
                border: "1px solid var(--border)",
                backgroundColor: "transparent",
                color: "var(--foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "11px",
                fontWeight: "var(--font-weight-medium)",
                cursor: "pointer",
              }}
              title="Copy full event JSON to clipboard"
            >
              {copied ? <CheckCircle2 size={11} style={{ color: "var(--chart-2)" }} /> : <Copy size={11} />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>

          <div
            className="rounded-md"
            style={{ border: "1px solid var(--border)", backgroundColor: "var(--card)", overflow: "hidden" }}
          >
            {[
              ["action", event.action],
              ["hash", hash],
              ["previous_hash", previous_hash],
            ].map(([k, v], i, arr) => (
              <div
                key={k}
                className="flex items-start gap-3 px-3 py-1.5"
                style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}
              >
                <span
                  style={{
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: "11px",
                    color: "var(--muted-foreground)",
                    minWidth: "120px",
                    flexShrink: 0,
                  }}
                >
                  {k}
                </span>
                <span
                  style={{
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: "11px",
                    color: "var(--foreground)",
                    wordBreak: "break-all",
                    flex: 1,
                  }}
                >
                  {v}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function AuditLogsPanel() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedNode, setSelectedNode] = useState<string>("all");
  const [expandedHash, setExpandedHash] = useState<string | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const { data, loading } = useAuditLogs();
  const entries = useMemo(() => data?.items ?? [], [data]);

  const nodes = useMemo(
    () => Array.from(new Set(entries.map((e) => e.event.node_id))).sort(),
    [entries],
  );
  const categories = useMemo(
    () => Array.from(new Set(entries.map((e) => e.event.category))).sort(),
    [entries],
  );
  const severities = ["Info", "Warning", "Critical"];

  const filteredEntries = useMemo(() => {
    return entries.filter((entry) => {
      const { event } = entry;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (
          !event.message.toLowerCase().includes(q) &&
          !event.action.toLowerCase().includes(q) &&
          !event.category.toLowerCase().includes(q)
        ) {
          return false;
        }
      }
      if (selectedSeverities.length > 0 && !selectedSeverities.includes(event.severity)) return false;
      if (selectedCategories.length > 0 && !selectedCategories.includes(event.category)) return false;
      if (selectedNode !== "all" && event.node_id !== selectedNode) return false;
      return true;
    });
  }, [entries, searchQuery, selectedSeverities, selectedCategories, selectedNode]);
  const totalPages = Math.max(1, Math.ceil(filteredEntries.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pageStart = filteredEntries.length === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const pageEnd = Math.min(filteredEntries.length, currentPage * pageSize);
  const visibleEntries = useMemo(
    () => filteredEntries.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    [currentPage, filteredEntries],
  );

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { Info: 0, Warning: 0, Critical: 0 };
    entries.forEach((e) => {
      counts[e.event.severity] = (counts[e.event.severity] || 0) + 1;
    });
    return counts;
  }, [entries]);

  const toggleSeverity = (severity: string) => {
    setSelectedSeverities((prev) =>
      prev.includes(severity) ? prev.filter((s) => s !== severity) : [...prev, severity],
    );
  };

  const toggleCategory = (category: string) => {
    setSelectedCategories((prev) =>
      prev.includes(category) ? prev.filter((c) => c !== category) : [...prev, category],
    );
  };

  const clearFilters = () => {
    setSearchQuery("");
    setSelectedSeverities([]);
    setSelectedCategories([]);
    setSelectedNode("all");
  };

  useEffect(() => {
    setPage(1);
    setExpandedHash(null);
  }, [searchQuery, selectedSeverities, selectedCategories, selectedNode]);

  const handleExport = () => {
    const text = filteredEntries
      .map(
        (entry) =>
          `[${new Date(entry.event.timestamp * 1000).toISOString()}] [${entry.event.severity.toUpperCase()}] [${entry.event.category}] [${entry.event.node_id}] ${entry.event.action}: ${entry.event.message} (hash=${entry.hash})`,
      )
      .join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sgx-guardian-audit-logs-${new Date().toISOString().split("T")[0]}.log`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Audit logs exported", { description: `${filteredEntries.length} entries exported` });
  };

  const hasActiveFilters =
    selectedSeverities.length > 0 || selectedCategories.length > 0 || selectedNode !== "all" || !!searchQuery;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center flex-1" style={{ minHeight: "40vh" }}>
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-hidden flex flex-col w-full max-w-4xl mx-auto">
      {/* Search and Actions Bar */}
      <div className="p-4 border-b flex flex-col gap-3" style={{ borderColor: "var(--border)" }}>
        <div className="relative">
          <Search
            size={16}
            style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--muted-foreground)" }}
          />
          <input
            type="text"
            placeholder="Search audit trail..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border"
            style={{
              height: "40px",
              paddingLeft: "40px",
              paddingRight: "12px",
              backgroundColor: "var(--secondary)",
              borderColor: "var(--border)",
              color: "var(--foreground)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
            }}
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              style={{ position: "absolute", right: "12px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", padding: "4px" }}
            >
              <X size={14} style={{ color: "var(--muted-foreground)" }} />
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: showFilters || hasActiveFilters ? "var(--primary)" : "var(--secondary)",
              color: showFilters || hasActiveFilters ? "var(--primary-foreground)" : "var(--secondary-foreground)",
              border: "none",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
            }}
          >
            <Filter size={14} />
            Filters
            {hasActiveFilters && (
              <span style={{ backgroundColor: "rgba(255,255,255,0.2)", padding: "0 6px", borderRadius: "10px", fontSize: "10px" }}>
                {selectedSeverities.length + selectedCategories.length + (selectedNode !== "all" ? 1 : 0)}
              </span>
            )}
          </button>

          <div className="flex-1" />

          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: "var(--secondary)",
              color: "var(--secondary-foreground)",
              border: "none",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
            }}
          >
            <Download size={14} />
            Export
          </button>
        </div>

        {showFilters && (
          <div className="flex flex-col gap-3 pt-3 border-t" style={{ borderColor: "var(--border)" }}>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", marginBottom: "8px" }}>
                Node
              </p>
              <div className="flex flex-wrap gap-2">
                <FilterChip label="All Nodes" active={selectedNode === "all"} onClick={() => setSelectedNode("all")} />
                {nodes.map((node) => (
                  <FilterChip key={node} label={node} active={selectedNode === node} onClick={() => setSelectedNode(node)} />
                ))}
              </div>
            </div>

            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", marginBottom: "8px" }}>
                Severity
              </p>
              <div className="flex flex-wrap gap-2">
                {severities.map((severity) => (
                  <FilterChip
                    key={severity}
                    label={severity}
                    active={selectedSeverities.includes(severity)}
                    onClick={() => toggleSeverity(severity)}
                    count={severityCounts[severity]}
                  />
                ))}
              </div>
            </div>

            {categories.length > 0 && (
              <div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", marginBottom: "8px" }}>
                  Category
                </p>
                <div className="flex flex-wrap gap-2">
                  {categories.map((category) => (
                    <FilterChip
                      key={category}
                      label={category}
                      active={selectedCategories.includes(category)}
                      onClick={() => toggleCategory(category)}
                    />
                  ))}
                </div>
              </div>
            )}

            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="flex items-center gap-2 px-3 py-2 rounded-lg self-start"
                style={{
                  backgroundColor: "color-mix(in srgb, var(--destructive) 15%, transparent)",
                  color: "var(--destructive)",
                  border: "none",
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                }}
              >
                <X size={14} />
                Clear all filters
              </button>
            )}
          </div>
        )}
      </div>

      {/* Stats Bar */}
      <div className="px-4 py-2 flex items-center gap-4 border-b" style={{ borderColor: "var(--border)", backgroundColor: "var(--muted)" }}>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          Showing <strong style={{ color: "var(--foreground)" }}>{filteredEntries.length}</strong> of {entries.length} entries
        </span>
        <div className="flex-1" />
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1" style={{ fontSize: "11px", color: "var(--destructive)" }}>
            <AlertOctagon size={12} /> {severityCounts.Critical}
          </span>
          <span className="flex items-center gap-1" style={{ fontSize: "11px", color: "var(--chart-5)" }}>
            <ShieldAlert size={12} /> {severityCounts.Warning}
          </span>
          <span className="flex items-center gap-1" style={{ fontSize: "11px", color: "var(--primary)" }}>
            <Info size={12} /> {severityCounts.Info}
          </span>
        </div>
      </div>

      {/* Entries */}
      <div className="flex-1 overflow-y-auto" style={{ backgroundColor: "var(--card)" }}>
        {filteredEntries.length > 0 ? (
          visibleEntries.map((entry) => (
            <AuditLogRow
              key={entry.hash}
              entry={entry}
              isExpanded={expandedHash === entry.hash}
              onToggle={() => setExpandedHash(expandedHash === entry.hash ? null : entry.hash)}
            />
          ))
        ) : (
          <div className="flex flex-col items-center justify-center py-16 gap-4">
            <div className="rounded-full flex items-center justify-center" style={{ width: "64px", height: "64px", backgroundColor: "var(--muted)" }}>
              <ShieldCheck size={28} style={{ color: "var(--muted-foreground)" }} />
            </div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              No audit events found
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", textAlign: "center", maxWidth: "280px" }}>
              {hasActiveFilters ? "Try adjusting your filters or search query" : "No audit trail entries available at this time"}
            </p>
            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="flex items-center gap-2 px-4 py-2 rounded-lg"
                style={{
                  backgroundColor: "var(--primary)",
                  color: "var(--primary-foreground)",
                  border: "none",
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                Clear filters
              </button>
            )}
          </div>
        )}
        {totalPages > 1 && (
          <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-3" style={{ backgroundColor: "var(--card)" }}>
            <p className="text-xs text-muted-foreground">
              Showing {pageStart}-{pageEnd} of {filteredEntries.length}
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage((current) => Math.max(1, current - 1))}
                disabled={currentPage === 1}
                className="grid h-8 w-8 place-items-center rounded-full border border-border disabled:cursor-not-allowed disabled:opacity-40"
                aria-label="Previous audit page"
              >
                <ChevronLeft size={16} />
              </button>
              <span className="min-w-16 text-center text-xs text-muted-foreground">
                {currentPage} / {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                disabled={currentPage === totalPages}
                className="grid h-8 w-8 place-items-center rounded-full border border-border disabled:cursor-not-allowed disabled:opacity-40"
                aria-label="Next audit page"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Info Footer */}
      <div className="p-4 border-t" style={{ borderColor: "var(--border)", backgroundColor: "var(--background)" }}>
        <div
          className="flex items-start gap-3 p-3 rounded-lg"
          style={{ backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)" }}
        >
          <Fingerprint size={16} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", lineHeight: 1.5 }}>
            Audit events form a tamper-evident hash chain — each entry's hash is derived from its content plus the previous entry's hash. Expand a row to inspect the chain values.
          </p>
        </div>
      </div>
    </div>
  );
}

// Main Component
export function LG01LogsViewer() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<"logs" | "audit">("logs");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedLevels, setSelectedLevels] = useState<LogLevel[]>([]);
  const [selectedCategories, setSelectedCategories] = useState<LogCategory[]>([]);
  const [selectedNode, setSelectedNode] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [page, setPage] = useState(1);
  const pageSize = 10;

  // Fetch data from backend API
  const { data: logsData, loading, error, source } = useLogs();
  const logEntries = useMemo(() => {
    if (!logsData) return [];
    const logs = logsData.logs || logsData;
    return Array.isArray(logs) ? logs : [];
  }, [logsData]);

  // Node filter chips are derived from whatever nodes actually appear in the
  // fetched logs, rather than a fabricated static list.
  const availableNodes = useMemo(() => {
    const nodes = new Set<string>();
    for (const log of logEntries) {
      if (log.node) nodes.add(log.node);
    }
    return [...nodes].sort();
  }, [logEntries]);

  const levels: LogLevel[] = ["error", "warning", "info", "debug"];
  const categories: LogCategory[] = ["attestation", "peer", "security", "system", "dkp", "policy"];

  // Filter logs - must be called before any conditional returns
  const filteredLogs = useMemo(() => {
    return logEntries.filter((log: LogEntry) => {
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        if (
          !log.message.toLowerCase().includes(query) &&
          !log.details?.toLowerCase().includes(query) &&
          !log.category.toLowerCase().includes(query)
        ) {
          return false;
        }
      }

      // Level filter
      if (selectedLevels.length > 0 && !selectedLevels.includes(log.level)) {
        return false;
      }

      // Category filter
      if (selectedCategories.length > 0 && !selectedCategories.includes(log.category)) {
        return false;
      }

      // Node filter
      if (selectedNode !== "all" && log.node !== selectedNode) {
        return false;
      }

      return true;
    });
  }, [logEntries, searchQuery, selectedLevels, selectedCategories, selectedNode]);
  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pageStart = filteredLogs.length === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const pageEnd = Math.min(filteredLogs.length, currentPage * pageSize);
  const visibleLogs = useMemo(
    () => filteredLogs.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    [currentPage, filteredLogs],
  );

  // Count by level
  const levelCounts = useMemo(() => {
    const counts: Record<LogLevel, number> = { info: 0, warning: 0, error: 0, debug: 0 };
    logEntries.forEach((log: LogEntry) => {
      counts[log.level]++;
    });
    return counts;
  }, [logEntries]);

  const toggleLevel = (level: LogLevel) => {
    setSelectedLevels((prev) =>
      prev.includes(level) ? prev.filter((l) => l !== level) : [...prev, level]
    );
  };

  const toggleCategory = (category: LogCategory) => {
    setSelectedCategories((prev) =>
      prev.includes(category) ? prev.filter((c) => c !== category) : [...prev, category]
    );
  };

  const clearFilters = () => {
    setSearchQuery("");
    setSelectedLevels([]);
    setSelectedCategories([]);
    setSelectedNode("all");
  };

  useEffect(() => {
    setPage(1);
    setExpandedId(null);
  }, [searchQuery, selectedLevels, selectedCategories, selectedNode]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
      toast.success("Logs refreshed", { description: "Fetched latest log entries" });
    }, 1000);
  };

  const handleExport = () => {
    const logText = filteredLogs
      .map((log) => `[${log.timestamp}] [${log.level.toUpperCase()}] [${log.category}] [${log.node}] ${log.message}${log.details ? `\n  ${log.details}` : ""}`)
      .join("\n");

    const blob = new Blob([logText], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sgx-guardian-logs-${new Date().toISOString().split("T")[0]}.log`;
    a.click();
    URL.revokeObjectURL(url);

    toast.success("Logs exported", { description: `${filteredLogs.length} entries exported` });
  };

  const hasActiveFilters = selectedLevels.length > 0 || selectedCategories.length > 0 || selectedNode !== "all" || searchQuery;

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Logs" subtitle="System Events" onBack={() => navigate("/settings")} />

      {/* Tabs */}
      <div className="flex border-b" style={{ borderColor: "var(--border)", backgroundColor: "var(--card)" }}>
        {(
          [
            { id: "logs" as const, label: "Logs", icon: FileText },
            { id: "audit" as const, label: "Audit Logs", icon: ShieldCheck },
          ]
        ).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex-1 flex items-center justify-center gap-1.5 py-3 transition-opacity active:opacity-70 ${id === "audit" ? "group" : ""}`}
            style={{
              backgroundColor: "transparent",
              border: "none",
              cursor: "pointer",
              borderBottom: activeTab === id ? "2px solid var(--primary)" : "2px solid transparent",
            }}
          >
            <Icon size={14} style={{ color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }} />
            <span>
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: activeTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                  color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)",
                }}
              >
                {label}
              </span>
              {id === "audit" ? (
                <span className="relative inline-flex cursor-help align-middle">
                  <Info size={14} style={{ color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)", marginLeft: "4px" }} />
                  <span className="pointer-events-none absolute right-0 top-7 z-20 hidden w-72 rounded-md border border-border bg-popover px-3 py-2 text-left text-xs leading-5 text-popover-foreground shadow-lg group-hover:block group-focus-within:block">
                    Audit logs keep a secure history of important activity, such as sign-ins, device changes, Circle activity, and admin actions.
                  </span>
                </span>
              ) : null}
            </span>
          </button>
        ))}
      </div>

      {activeTab === "audit" ? (
        <AuditLogsPanel />
      ) : loading ? (
        <div className="flex flex-col items-center justify-center flex-1" style={{ minHeight: "40vh" }}>
          <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
          <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
        </div>
      ) : (
      <div className="flex-1 overflow-hidden flex flex-col w-full max-w-4xl mx-auto">
        {/* Search and Actions Bar */}
        <div className="p-4 border-b flex flex-col gap-3" style={{ borderColor: "var(--border)" }}>
          {/* Search Input */}
          <div className="relative">
            <Search
              size={16}
              style={{
                position: "absolute",
                left: "12px",
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--muted-foreground)",
              }}
            />
            <input
              type="text"
              placeholder="Search logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border"
              style={{
                height: "40px",
                paddingLeft: "40px",
                paddingRight: "12px",
                backgroundColor: "var(--secondary)",
                borderColor: "var(--border)",
                color: "var(--foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
              }}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
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
                <X size={14} style={{ color: "var(--muted-foreground)" }} />
              </button>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
              style={{
                backgroundColor: showFilters || hasActiveFilters ? "var(--primary)" : "var(--secondary)",
                color: showFilters || hasActiveFilters ? "var(--primary-foreground)" : "var(--secondary-foreground)",
                border: "none",
                cursor: "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
              }}
            >
              <Filter size={14} />
              Filters
              {hasActiveFilters && (
                <span
                  style={{
                    backgroundColor: "rgba(255,255,255,0.2)",
                    padding: "0 6px",
                    borderRadius: "10px",
                    fontSize: "10px",
                  }}
                >
                  {selectedLevels.length + selectedCategories.length + (selectedNode !== "all" ? 1 : 0)}
                </span>
              )}
            </button>

            <div className="flex-1" />

            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
              style={{
                backgroundColor: "var(--secondary)",
                color: "var(--secondary-foreground)",
                border: "none",
                cursor: isRefreshing ? "not-allowed" : "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                opacity: isRefreshing ? 0.7 : 1,
              }}
            >
              <RefreshCw size={14} style={{ animation: isRefreshing ? "spin 1s linear infinite" : "none" }} />
            </button>

            <button
              onClick={handleExport}
              className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
              style={{
                backgroundColor: "var(--secondary)",
                color: "var(--secondary-foreground)",
                border: "none",
                cursor: "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
              }}
            >
              <Download size={14} />
              Export
            </button>
          </div>

          {/* Filter Panel */}
          {showFilters && (
            <div className="flex flex-col gap-3 pt-3 border-t" style={{ borderColor: "var(--border)" }}>
              {/* Node Selector */}
              <div>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-semibold)",
                    color: "var(--muted-foreground)",
                    marginBottom: "8px",
                  }}
                >
                  Node
                </p>
                <div className="flex flex-wrap gap-2">
                  <FilterChip
                    label="All Nodes"
                    active={selectedNode === "all"}
                    onClick={() => setSelectedNode("all")}
                  />
                  {availableNodes.map((node) => (
                    <FilterChip
                      key={node}
                      label={node}
                      active={selectedNode === node}
                      onClick={() => setSelectedNode(node)}
                    />
                  ))}
                </div>
              </div>

              {/* Level Filters */}
              <div>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-semibold)",
                    color: "var(--muted-foreground)",
                    marginBottom: "8px",
                  }}
                >
                  Log Level
                </p>
                <div className="flex flex-wrap gap-2">
                  {levels.map((level) => (
                    <FilterChip
                      key={level}
                      label={level.charAt(0).toUpperCase() + level.slice(1)}
                      active={selectedLevels.includes(level)}
                      onClick={() => toggleLevel(level)}
                      count={levelCounts[level]}
                    />
                  ))}
                </div>
              </div>

              {/* Category Filters */}
              <div>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-semibold)",
                    color: "var(--muted-foreground)",
                    marginBottom: "8px",
                  }}
                >
                  Category
                </p>
                <div className="flex flex-wrap gap-2">
                  {categories.map((category) => (
                    <FilterChip
                      key={category}
                      label={category.charAt(0).toUpperCase() + category.slice(1)}
                      active={selectedCategories.includes(category)}
                      onClick={() => toggleCategory(category)}
                    />
                  ))}
                </div>
              </div>

              {/* Clear Filters */}
              {hasActiveFilters && (
                <button
                  onClick={clearFilters}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg self-start"
                  style={{
                    backgroundColor: "color-mix(in srgb, var(--destructive) 15%, transparent)",
                    color: "var(--destructive)",
                    border: "none",
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                  }}
                >
                  <X size={14} />
                  Clear all filters
                </button>
              )}
            </div>
          )}
        </div>

        {/* Stats Bar */}
        <div
          className="px-4 py-2 flex items-center gap-4 border-b"
          style={{ borderColor: "var(--border)", backgroundColor: "var(--muted)" }}
        >
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            Showing <strong style={{ color: "var(--foreground)" }}>{filteredLogs.length}</strong> of{" "}
            {logEntries.length} entries
          </span>
          <div className="flex-1" />
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1" style={{ fontSize: "11px", color: "var(--destructive)" }}>
              <XCircle size={12} /> {levelCounts.error}
            </span>
            <span className="flex items-center gap-1" style={{ fontSize: "11px", color: "var(--chart-5)" }}>
              <AlertTriangle size={12} /> {levelCounts.warning}
            </span>
            <span className="flex items-center gap-1" style={{ fontSize: "11px", color: "var(--primary)" }}>
              <Info size={12} /> {levelCounts.info}
            </span>
          </div>
        </div>

        {/* Log Entries */}
        <div className="flex-1 overflow-y-auto" style={{ backgroundColor: "var(--card)" }}>
          {filteredLogs.length > 0 ? (
            visibleLogs.map((entry) => (
              <LogRow
                key={entry.id}
                entry={entry}
                isExpanded={expandedId === entry.id}
                onToggle={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
              />
            ))
          ) : (
            <div className="flex flex-col items-center justify-center py-16 gap-4">
              <div
                className="rounded-full flex items-center justify-center"
                style={{ width: "64px", height: "64px", backgroundColor: "var(--muted)" }}
              >
                <FileText size={28} style={{ color: "var(--muted-foreground)" }} />
              </div>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-base)",
                  fontWeight: "var(--font-weight-semibold)",
                  color: "var(--foreground)",
                }}
              >
                No logs found
              </p>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  color: "var(--muted-foreground)",
                  textAlign: "center",
                  maxWidth: "280px",
                }}
              >
                {hasActiveFilters
                  ? "Try adjusting your filters or search query"
                  : "No log entries available at this time"}
              </p>
              {hasActiveFilters && (
                <button
                  onClick={clearFilters}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg"
                  style={{
                    backgroundColor: "var(--primary)",
                    color: "var(--primary-foreground)",
                    border: "none",
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-medium)",
                  }}
                >
                  Clear filters
                </button>
              )}
            </div>
          )}
        </div>
        {totalPages > 1 && (
          <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-3" style={{ backgroundColor: "var(--card)" }}>
            <p className="text-xs text-muted-foreground">
              Showing {pageStart}-{pageEnd} of {filteredLogs.length}
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage((current) => Math.max(1, current - 1))}
                disabled={currentPage === 1}
                className="grid h-8 w-8 place-items-center rounded-full border border-border disabled:cursor-not-allowed disabled:opacity-40"
                aria-label="Previous log page"
              >
                <ChevronLeft size={16} />
              </button>
              <span className="min-w-16 text-center text-xs text-muted-foreground">
                {currentPage} / {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                disabled={currentPage === totalPages}
                className="grid h-8 w-8 place-items-center rounded-full border border-border disabled:cursor-not-allowed disabled:opacity-40"
                aria-label="Next log page"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}

        {/* Info Footer */}
        <div
          className="p-4 border-t"
          style={{ borderColor: "var(--border)", backgroundColor: "var(--background)" }}
        >
          <div
            className="flex items-start gap-3 p-3 rounded-lg"
            style={{
              backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)",
              border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)",
            }}
          >
            <Info size={16} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", lineHeight: 1.5 }}>
              Logs are collected from all Guardian nodes. Use filters to narrow down by node, severity, or category. Export logs for offline analysis.
            </p>
          </div>
        </div>
      </div>
      )}

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
