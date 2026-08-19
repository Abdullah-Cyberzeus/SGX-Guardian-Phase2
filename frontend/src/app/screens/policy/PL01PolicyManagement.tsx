import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  FileText,
  FileCheck,
  FileX,
  CheckCircle2,
  XCircle,
  Clock,
  Key,
  Upload,
  RefreshCw,
  Copy,
  Check,
  Info,
  Pen,
  ShieldCheck,
  AlertTriangle,
  Loader2,
  Save,
  Send,
  RotateCcw,
  Archive,
  GitCompare,
  FileCode,
  Eye,
  ChevronDown,
  LayoutList,
} from "lucide-react";
import type { SignedPolicy } from "../../data/mockData";
import { policyService } from "../../services/policyService";
import { toast } from "sonner";

type TabId = "policies" | "sign" | "keys";
type PolicyCategory = "active" | "backup" | "signed";

// Status Badge
function VerifiedBadge({ verified, archived = false }: { verified: boolean; archived?: boolean }) {
  if (archived) {
    return (
      <span
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full"
        style={{
          backgroundColor: "color-mix(in srgb, var(--muted-foreground) 12%, transparent)",
          border: "1px solid color-mix(in srgb, var(--muted-foreground) 25%, transparent)",
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-medium)",
          color: "var(--muted-foreground)",
        }}
      >
        <Archive size={12} />
        Archived
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full"
      style={{
        backgroundColor: verified
          ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
          : "color-mix(in srgb, var(--chart-5) 15%, transparent)",
        border: `1px solid ${verified
          ? "color-mix(in srgb, var(--chart-2) 30%, transparent)"
          : "color-mix(in srgb, var(--chart-5) 30%, transparent)"}`,
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        color: verified ? "var(--chart-2)" : "var(--chart-5)",
      }}
    >
      {verified ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
      {verified ? "Verified" : "Unverified"}
    </span>
  );
}

// ── YAML viewer (backup preview) ─────────────────────────────────────────────

function yamlValueColor(value: string): string {
  const v = value.trim();
  if (!v) return "var(--foreground)";
  if (/^(true|false|null|~|on|off|yes|no)$/i.test(v)) return "var(--chart-4)";
  if (/^-?\d+(\.\d+)?$/.test(v)) return "var(--chart-4)";
  if (v.startsWith('"') || v.startsWith("'")) return "var(--chart-2)";
  return "var(--foreground)";
}

function YamlLine({ line }: { line: string }) {
  if (line.trimStart().startsWith("#")) {
    return <span style={{ color: "var(--muted-foreground)", fontStyle: "italic" }}>{line}</span>;
  }
  const m = line.match(/^(\s*(?:- )?)([^:#]+):(\s.*|$)/);
  if (m) {
    const [, indent, key, rest] = m;
    return (
      <>
        <span>{indent}</span>
        <span style={{ color: "var(--primary)" }}>{key}</span>
        <span style={{ color: "var(--muted-foreground)" }}>:</span>
        <span style={{ color: yamlValueColor(rest) }}>{rest}</span>
      </>
    );
  }
  return <span style={{ color: yamlValueColor(line) }}>{line}</span>;
}

function YamlCodeView({ yaml }: { yaml: string }) {
  const lines = yaml.replace(/\n$/, "").split("\n");
  return (
    <div style={{ backgroundColor: "var(--background)", maxHeight: 420, overflow: "auto" }}>
      <table style={{ borderCollapse: "collapse", fontFamily: "JetBrains Mono, monospace", fontSize: "12px", lineHeight: 1.6 }}>
        <tbody>
          {lines.map((line, i) => (
            <tr key={i}>
              <td style={{ width: 1, padding: "0 12px 0 14px", textAlign: "right", color: "var(--muted-foreground)", opacity: 0.45, userSelect: "none", verticalAlign: "top" }}>
                {i + 1}
              </td>
              <td style={{ whiteSpace: "pre", paddingRight: 14, color: "var(--foreground)" }}>
                <YamlLine line={line} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Structured (rendered) YAML view ───────────────────────────────────────────
type ParsedContent =
  | { kind: "map"; entries: { key: string; value: string }[] }
  | { kind: "list"; items: string[] }
  | { kind: "mixed"; raw: string };

function parseSectionContent(lines: string[]): ParsedContent {
  const nonEmpty = lines.filter((l) => l.trim() && !l.trim().startsWith("#"));
  if (!nonEmpty.length) return { kind: "mixed", raw: "" };
  const baseIndent = Math.min(...nonEmpty.map((l) => l.search(/\S/)));
  const isAllList = nonEmpty.every((l) => {
    const rel = l.slice(baseIndent).trimStart();
    return rel.startsWith("- ");
  });
  if (isAllList) {
    const items: string[] = [];
    for (const l of nonEmpty) {
      const rel = l.slice(baseIndent).trimStart();
      if (rel.startsWith("- ")) items.push(rel.slice(2).trim());
    }
    return { kind: "list", items };
  }
  const isSimpleMap = nonEmpty.every((l) => {
    const rel = l.slice(baseIndent);
    const t = rel.trimStart();
    const extraIndent = rel.search(/\S/);
    return extraIndent === 0 && t.includes(":");
  });
  if (isSimpleMap) {
    const entries: { key: string; value: string }[] = [];
    for (const l of nonEmpty) {
      const t = l.slice(baseIndent).trim();
      const ci = t.indexOf(":");
      if (ci === -1) continue;
      const k = t.slice(0, ci).trim();
      const v = t.slice(ci + 1).trim().replace(/^["']|["']$/g, "");
      if (k) entries.push({ key: k, value: v });
    }
    return { kind: "map", entries };
  }
  return { kind: "mixed", raw: nonEmpty.map((l) => l.slice(baseIndent)).join("\n") };
}

function parseSections(yaml: string): {
  meta: { key: string; value: string }[];
  sections: { key: string; content: ParsedContent }[];
} {
  const lines = yaml.split("\n");
  const meta: { key: string; value: string }[] = [];
  const sections: { key: string; content: ParsedContent }[] = [];
  let i = 0;
  while (i < lines.length) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) { i++; continue; }
    const indent = rawLine.search(/\S/);
    if (indent !== 0) { i++; continue; }
    const ci = trimmed.indexOf(":");
    if (ci === -1) { i++; continue; }
    const key = trimmed.slice(0, ci).trim();
    const value = trimmed.slice(ci + 1).trim();
    if (value && !value.startsWith("#")) {
      meta.push({ key, value: value.replace(/^["']|["']$/g, "") });
      i++;
    } else {
      const sectionLines: string[] = [];
      i++;
      while (i < lines.length) {
        const next = lines[i];
        const nt = next.trim();
        if (!nt) { sectionLines.push(""); i++; continue; }
        if (next.search(/\S/) === 0) break;
        sectionLines.push(next);
        i++;
      }
      sections.push({ key, content: parseSectionContent(sectionLines) });
    }
  }
  return { meta, sections };
}

function YamlRenderedView({ yaml }: { yaml: string }) {
  const { meta, sections } = useMemo(() => parseSections(yaml), [yaml]);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const toggle = (key: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });

  if (!yaml.trim()) {
    return (
      <div style={{ padding: "32px 16px", textAlign: "center", backgroundColor: "var(--background)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
        No policy content to display.
      </div>
    );
  }

  return (
    <div style={{ padding: "12px 14px", backgroundColor: "var(--background)", maxHeight: 420, overflow: "auto" }}>
      {meta.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 14 }}>
          {meta.map(({ key, value }) => (
            <div
              key={key}
              style={{
                display: "flex", alignItems: "center", gap: 5,
                padding: "3px 10px", borderRadius: 999,
                backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--primary) 22%, transparent)",
              }}
            >
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", color: "var(--muted-foreground)", fontWeight: 500 }}>{key}</span>
              <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", fontWeight: 600 }}>{value || "(empty)"}</span>
            </div>
          ))}
        </div>
      )}
      {sections.map(({ key, content }) => {
        const isOpen = !collapsed.has(key);
        const label = key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
        return (
          <div key={key} style={{ marginBottom: 6, border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
            <button
              onClick={() => toggle(key)}
              style={{
                width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "7px 12px", backgroundColor: "var(--card)", border: "none", cursor: "pointer",
                textAlign: "left",
              }}
            >
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: 600, color: "var(--foreground)" }}>{label}</span>
              <ChevronDown size={13} style={{ color: "var(--muted-foreground)", transform: isOpen ? "none" : "rotate(-90deg)", transition: "transform 0.15s", flexShrink: 0 }} />
            </button>
            {isOpen && (
              <div style={{ padding: "8px 12px", borderTop: "1px solid var(--border)", backgroundColor: "var(--background)" }}>
                {content.kind === "map" && (
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <tbody>
                      {content.entries.map(({ key: k, value: v }) => (
                        <tr key={k}>
                          <td style={{ padding: "3px 10px 3px 0", fontFamily: "Inter, sans-serif", fontSize: "11px", color: "var(--muted-foreground)", fontWeight: 500, whiteSpace: "nowrap", verticalAlign: "top" }}>
                            {k.replace(/_/g, " ")}
                          </td>
                          <td style={{ padding: "3px 0", fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", wordBreak: "break-all" }}>
                            {v || <span style={{ color: "var(--muted-foreground)" }}>(empty)</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {content.kind === "list" && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                    {content.items.map((item, idx) => (
                      <span key={idx} style={{
                        padding: "2px 8px", borderRadius: 4,
                        backgroundColor: "color-mix(in srgb, var(--chart-2) 12%, transparent)",
                        border: "1px solid color-mix(in srgb, var(--chart-2) 22%, transparent)",
                        fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)",
                      }}>{item}</span>
                    ))}
                  </div>
                )}
                {content.kind === "mixed" && content.raw && (
                  <pre style={{ margin: 0, fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                    {content.raw}
                  </pre>
                )}
                {content.kind === "mixed" && !content.raw && (
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", color: "var(--muted-foreground)" }}>(empty)</span>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// Line-based LCS diff between the backup snapshot and the active policy.
type DiffRow = { type: "same" | "removed" | "added"; text: string };

function diffLines(oldText: string, newText: string): DiffRow[] {
  const a = oldText.replace(/\n$/, "").split("\n");
  const b = newText.replace(/\n$/, "").split("\n");
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const rows: DiffRow[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      rows.push({ type: "same", text: a[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ type: "removed", text: a[i] });
      i++;
    } else {
      rows.push({ type: "added", text: b[j] });
      j++;
    }
  }
  while (i < n) rows.push({ type: "removed", text: a[i++] });
  while (j < m) rows.push({ type: "added", text: b[j++] });
  return rows;
}

function BackupDiffView({ backupYaml, activeYaml }: { backupYaml: string; activeYaml: string }) {
  const rows = useMemo(() => diffLines(backupYaml, activeYaml), [backupYaml, activeYaml]);
  const changed = rows.filter(r => r.type !== "same").length;

  if (changed === 0) {
    return (
      <div className="flex flex-col items-center justify-center text-center" style={{ minHeight: 200, padding: "32px 24px", backgroundColor: "var(--background)" }}>
        <CheckCircle2 size={26} style={{ color: "var(--chart-2)", marginBottom: 10 }} />
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
          Backup matches the active policy
        </p>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: 4 }}>
          No lines differ between the snapshot and the deployed policy.
        </p>
      </div>
    );
  }

  return (
    <div style={{ backgroundColor: "var(--background)", maxHeight: 420, overflow: "auto" }}>
      <div className="px-4 py-2 border-b" style={{ borderColor: "var(--border)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
        <span style={{ color: "var(--destructive)" }}>− backup</span>
        {"  "}
        <span style={{ color: "var(--chart-2)" }}>+ active</span>
        {`  ·  ${changed} changed line${changed === 1 ? "" : "s"}`}
      </div>
      <table style={{ borderCollapse: "collapse", width: "100%", fontFamily: "JetBrains Mono, monospace", fontSize: "12px", lineHeight: 1.6 }}>
        <tbody>
          {rows.map((row, i) => {
            const bg =
              row.type === "added"
                ? "color-mix(in srgb, var(--chart-2) 10%, transparent)"
                : row.type === "removed"
                  ? "color-mix(in srgb, var(--destructive) 10%, transparent)"
                  : "transparent";
            const marker = row.type === "added" ? "+" : row.type === "removed" ? "−" : " ";
            const markerColor = row.type === "added" ? "var(--chart-2)" : row.type === "removed" ? "var(--destructive)" : "var(--muted-foreground)";
            return (
              <tr key={i} style={{ backgroundColor: bg }}>
                <td style={{ width: 1, padding: "0 10px 0 14px", color: markerColor, userSelect: "none", verticalAlign: "top", fontWeight: row.type === "same" ? "normal" : "bold" }}>
                  {marker}
                </td>
                <td style={{ whiteSpace: "pre", paddingRight: 14, color: row.type === "same" ? "var(--muted-foreground)" : "var(--foreground)" }}>
                  {row.text}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Policy Card
function PolicyCard({ policy, onVerify }: { policy: SignedPolicy; onVerify: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const handleCopyDigest = () => {
    navigator.clipboard.writeText(policy.digest).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className="rounded-lg border overflow-hidden"
      style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left"
        style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
      >
        <div
          className="flex items-center justify-center rounded-lg flex-shrink-0"
          style={{
            width: "40px",
            height: "40px",
            backgroundColor: policy.verified
              ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
              : "color-mix(in srgb, var(--chart-5) 15%, transparent)",
          }}
        >
          {policy.verified ? (
            <FileCheck size={20} style={{ color: "var(--chart-2)" }} />
          ) : (
            <FileX size={20} style={{ color: "var(--chart-5)" }} />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
              marginBottom: "2px",
            }}
          >
            {policy.name}
          </p>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            Signed {formatDate(policy.signedAt)}
          </p>
        </div>
        <VerifiedBadge verified={policy.verified} archived={policy.status === "backup"} />
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-2 border-t flex flex-col gap-3" style={{ borderColor: "var(--border)" }}>
          {/* Details */}
          <div
            className="rounded-lg border overflow-hidden"
            style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}
          >
            {[
              { label: "Signed By", value: policy.signedBy },
              { label: "Envelope Version", value: policy.envelopeVersion },
              { label: "Last Verified", value: policy.lastVerified ? formatDate(policy.lastVerified) : "Never" },
            ].map(({ label, value }, i, arr) => (
              <div
                key={label}
                className="flex items-center justify-between px-4 py-2.5"
                style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}
              >
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  {label}
                </span>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
                  {value}
                </span>
              </div>
            ))}
          </div>

          {/* Digest */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                Digest (SHA-256)
              </span>
              <button
                onClick={handleCopyDigest}
                className="flex items-center gap-1 px-2 py-1 rounded"
                style={{
                  backgroundColor: copied ? "color-mix(in srgb, var(--chart-2) 15%, transparent)" : "var(--muted)",
                  border: "none",
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: copied ? "var(--chart-2)" : "var(--muted-foreground)",
                }}
              >
                {copied ? <Check size={12} /> : <Copy size={12} />}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <code
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "10px",
                color: "var(--foreground)",
                backgroundColor: "var(--muted)",
                padding: "8px 10px",
                borderRadius: "6px",
                display: "block",
                wordBreak: "break-all",
              }}
            >
              {policy.digest}
            </code>
          </div>

          {/* Path */}
          <div>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", display: "block", marginBottom: "4px" }}>
              File Path
            </span>
            <code
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "10px",
                color: "var(--muted-foreground)",
                backgroundColor: "var(--muted)",
                padding: "6px 10px",
                borderRadius: "4px",
                display: "block",
              }}
            >
              {policy.path}
            </code>
          </div>

          {/* Verify Button */}
          <button
            onClick={onVerify}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg transition-opacity active:opacity-80"
            style={{
              backgroundColor: "var(--primary)",
              color: "var(--primary-foreground)",
              border: "none",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
            }}
          >
            <ShieldCheck size={16} />
            Verify Signature
          </button>
        </div>
      )}
    </div>
  );
}

// Main Component
export function PL01PolicyManagement() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<TabId>("policies");
  const [policyCategory, setPolicyCategory] = useState<PolicyCategory>("active");
  const [selectedActiveId, setSelectedActiveId] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isSigning, setIsSigning] = useState(false);
  const [policyFile, setPolicyFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // ── New "active policy" flow state ─────────────────────────────────────
  // Loads YAML via GET /policy/current, saves with PUT /policy/current,
  // signs+deploys with POST /policy/sign-deploy-current.
  const [currentYaml, setCurrentYaml] = useState<string>("");
  const [savedYaml, setSavedYaml] = useState<string>("");
  const [currentPath, setCurrentPath] = useState<string>("");
  const [currentDigest, setCurrentDigest] = useState<string>("");
  const [currentUpdatedAt, setCurrentUpdatedAt] = useState<string>("");
  const [currentLoading, setCurrentLoading] = useState(false);
  const [currentLoadError, setCurrentLoadError] = useState<string | null>(null);
  const [isSavingCurrent, setIsSavingCurrent] = useState(false);
  const [isDeployingCurrent, setIsDeployingCurrent] = useState(false);
  const [isVerifyingDeployed, setIsVerifyingDeployed] = useState(false);

  // ── Backup policy state ──────────────────────────────────────────────────
  // ── Guardian key state ───────────────────────────────────────────────────
  const [keyStatus, setKeyStatus] = useState<{ exists: boolean; privateKeyExists: boolean; publicKeyExists: boolean; privateKeyPath: string; publicKeyPath: string; provider: string; algorithm: string; fingerprint?: string } | null>(null);
  const [keyLoading, setKeyLoading] = useState(false);
  const [isGeneratingKey, setIsGeneratingKey] = useState(false);

  const loadKeyStatus = async () => {
    setKeyLoading(true);
    try {
      const res = await policyService.getKeyStatus();
      setKeyStatus(res);
    } catch {
      // silently fail — falls back to showing "Unknown"
    } finally {
      setKeyLoading(false);
    }
  };

  const handleGenerateKey = async (force: boolean) => {
    setIsGeneratingKey(true);
    try {
      const res = await policyService.generateKey(force);
      if (res.alreadyExists && !force) {
        toast.info("Keys already exist", { description: "Use Regenerate to overwrite existing keys." });
      } else if (res.success) {
        toast.success("Keypair generated", {
          description: res.fingerprint ? `Fingerprint: ${res.fingerprint}` : res.stdout?.trim() || "Keys written successfully",
        });
      } else {
        toast.error("Key generation failed", { description: res.stderr?.trim() || res.stdout?.trim() || "Check guardian logs" });
      }
    } catch (err) {
      toast.error("Key generation failed", { description: err instanceof Error ? err.message : "Unknown error" });
    } finally {
      setIsGeneratingKey(false);
      await loadKeyStatus();
    }
  };

  // ── Backup policy state ──────────────────────────────────────────────────
  const [backupYaml, setBackupYaml] = useState<string>("");
  const [backupPath, setBackupPath] = useState<string>("");
  const [backupUpdatedAt, setBackupUpdatedAt] = useState<string>("");
  const [backupLoading, setBackupLoading] = useState(false);
  const [backupLoadError, setBackupLoadError] = useState<string | null>(null);
  const [backupView, setBackupView] = useState<"rendered" | "yaml" | "diff">("rendered");
  const [backupCopied, setBackupCopied] = useState(false);

  // Active policy YAML: "rendered" = structured view (default), "code" = syntax-highlighted raw,
  // "edit" = editable textarea.
  const [activePreviewMode, setActivePreviewMode] = useState<"rendered" | "code" | "edit">("rendered");
  const editingCurrent = activePreviewMode === "edit";

  const handleCopyBackup = async () => {
    try {
      await navigator.clipboard.writeText(backupYaml);
      setBackupCopied(true);
      setTimeout(() => setBackupCopied(false), 1500);
    } catch {
      toast.error("Could not copy to clipboard");
    }
  };

  const loadBackup = async () => {
    setBackupLoading(true);
    setBackupLoadError(null);
    try {
      const res = await policyService.getBackup();
      setBackupYaml(res.yaml ?? "");
      setBackupPath(res.path ?? "");
      setBackupUpdatedAt(res.updatedAt ?? "");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load backup policy";
      setBackupLoadError(msg);
    } finally {
      setBackupLoading(false);
    }
  };

  const dirty = currentYaml !== savedYaml;

  const loadCurrent = async () => {
    setCurrentLoading(true);
    setCurrentLoadError(null);
    try {
      const res = await policyService.getCurrent();
      setCurrentYaml(res.yaml ?? "");
      setSavedYaml(res.yaml ?? "");
      setCurrentPath(res.path ?? "");
      setCurrentDigest(res.digest ?? "");
      setCurrentUpdatedAt(res.updatedAt ?? "");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load current policy";
      setCurrentLoadError(msg);
      toast.error("Could not load current policy", { description: msg });
    } finally {
      setCurrentLoading(false);
    }
  };

  useEffect(() => {
    loadCurrent();
    loadBackup();
    loadKeyStatus();
  }, []);

  const handleSaveCurrent = async () => {
    setIsSavingCurrent(true);
    try {
      // Normalize: CRLF → LF, trim trailing whitespace per line, ensure single trailing newline
      const normalized = currentYaml
        .replace(/\r\n/g, '\n')
        .split('\n')
        .map((line) => line.trimEnd())
        .join('\n')
        .trimEnd() + '\n';
      const res = await policyService.updateCurrent(normalized);
      // Trust whatever the server canonicalised back; fall back to normalized local copy.
      const next = res.yaml ?? normalized;
      setCurrentYaml(next);
      setSavedYaml(next);
      if (res.digest) setCurrentDigest(res.digest);
      toast.success("Saved", { description: currentPath ? `Wrote ${currentPath}` : "Atomic write OK" });
    } catch (err) {
      toast.error("Save failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsSavingCurrent(false);
    }
  };

  const handleSignDeployCurrent = async () => {
    if (dirty) {
      toast.error("Unsaved changes", { description: "Save the policy before signing." });
      return;
    }
    setIsDeployingCurrent(true);
    try {
      const res = await policyService.signDeployCurrent();
      const detail = (res.stderr && res.stderr.trim()) || (res.stdout && res.stdout.trim()) || res.signaturePath || "";
      if (res.success) {
        toast.success(res.message || "Policy signed & deployed", {
          description: detail || "policy.sig written",
        });
        if (res.digest) setCurrentDigest(res.digest);
        await refetch();
      } else {
        toast.error(res.message || "Sign-deploy reported errors", {
          description: detail || "Check guardian logs",
        });
      }
    } catch (err) {
      toast.error("Sign & deploy failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsDeployingCurrent(false);
    }
  };

  const handleToggleActiveRow = (policyId: string) => {
    if (selectedActiveId === policyId) {
      setSelectedActiveId(null);
      return;
    }
    setSelectedActiveId(policyId);
    if (!currentYaml && !currentLoading) {
      loadCurrent();
    }
  };

  const handleVerifyDeployed = async () => {
    setIsVerifyingDeployed(true);
    try {
      const res = await policyService.verifyDeployed();
      const detail = (res.stdout && res.stdout.trim()) || (res.stderr && res.stderr.trim()) || "";
      if (res.success) {
        toast.success("Signature valid", {
          description: detail || "Deployed policy.sig verified",
        });
      } else {
        toast.error("Signature invalid", {
          description: detail || "Verification failed",
        });
      }
    } catch (err) {
      toast.error("Verify failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsVerifyingDeployed(false);
    }
  };

  // Refresh both current + backup after mutations (getAll has no backend endpoint)
  const refetch = async () => { await Promise.all([loadCurrent(), loadBackup()]); };

  // Build real signed-policies list from current + backup endpoints
  const realPolicies = useMemo<SignedPolicy[]>(() => {
    const list: SignedPolicy[] = [];
    if (currentYaml) {
      list.push({
        id: "active",
        name: currentPath ? currentPath.split("/").pop() ?? "active_policy.yaml" : "active_policy.yaml",
        path: currentPath || "/etc/sgx-guardian/policies/active_policy.yaml",
        digest: currentDigest || "",
        signature: "",
        signedAt: currentUpdatedAt || new Date().toISOString(),
        signedBy: "guardian_primary",
        verified: true,
        lastVerified: currentUpdatedAt || undefined,
        envelopeVersion: "1",
        status: "active",
      });
    }
    if (backupYaml) {
      list.push({
        id: "backup",
        name: backupPath ? backupPath.split("/").pop() ?? "backup_policy.yaml" : "backup_policy.yaml",
        path: backupPath || "/etc/sgx-guardian/policies/backup_policy.yaml",
        digest: "",
        signature: "",
        signedAt: backupUpdatedAt || new Date().toISOString(),
        signedBy: "guardian_primary",
        verified: false,
        envelopeVersion: "1",
        status: "backup",
      });
    }
    return list;
  }, [currentYaml, currentPath, currentDigest, currentUpdatedAt, backupYaml, backupPath, backupUpdatedAt]);

  const [policies, setPolicies] = useState<SignedPolicy[]>(realPolicies);

  // Keep policies in sync when real data loads
  useEffect(() => {
    setPolicies(realPolicies);
  }, [realPolicies]);

  const activePolicies = useMemo(
    () => policies.filter(p => (p.status ?? "active") === "active"),
    [policies],
  );
  const backupPolicies = useMemo(
    () => policies.filter(p => p.status === "backup"),
    [policies],
  );

  const tabs: { id: TabId; label: string; icon: typeof FileText }[] = [
    { id: "policies", label: "Policies", icon: FileText },
    { id: "sign", label: "Sign", icon: Pen },
    { id: "keys", label: "Keys", icon: Key },
  ];

  const categories: { id: PolicyCategory; label: string; icon: typeof FileText }[] = [
    { id: "active", label: "Active", icon: ShieldCheck },
    { id: "backup", label: "Backup", icon: Archive },
    { id: "signed", label: "Signed Policies", icon: FileCheck },
  ];

  const verifiedCount = policies.filter(p => p.verified).length;

  const handleVerify = async (policyId: string) => {
    setIsVerifying(true);
    try {
      const res = await policyService.verifyDeployed();
      setPolicies(prev => prev.map(p =>
        p.id === policyId ? { ...p, verified: res.success, lastVerified: new Date().toISOString() } : p
      ));
      if (res.success) {
        toast.success(res.message || "Signature valid", {
          description: res.stdout || "Policy verified successfully",
        });
      } else {
        toast.error(res.message || "Signature invalid", {
          description: res.stderr || res.stdout || "Verification failed",
        });
      }
    } catch (err) {
      toast.error("Verification failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSign = async () => {
    if (!policyFile) {
      toast.error("Select a policy file", {
        description: "Drop a .yaml or .json policy file before signing.",
      });
      return;
    }
    setIsSigning(true);
    try {
      const res = await policyService.sign(policyFile);
      console.log("[Policy Sign] POST /policy/sign →", res);
      // CLI always exits 0 (backend bug) — detect actual success from stdout content.
      const signedOk = res.stdout?.toLowerCase().includes("signed successfully") || res.stdout?.includes("policy.sig");
      const hasError = res.stderr?.includes("❌") || res.stderr?.toLowerCase().includes("failed") || res.stderr?.toLowerCase().includes("error");
      const detail = (res.stderr && res.stderr.trim()) || (res.stdout && res.stdout.trim()) || "";
      if (signedOk && !hasError) {
        toast.success("Policy signed", { description: detail || "policy.sig written" });
        setPolicyFile(null);
        if (fileInputRef.current) fileInputRef.current.value = "";
        await refetch();
      } else {
        toast.error("Signing reported errors", { description: detail || "Check guardian logs" });
      }
    } catch (err) {
      toast.error("Signing failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsSigning(false);
    }
  };

  const acceptPolicyFile = (file: File | null | undefined) => {
    if (!file) return;
    const ok = /\.(ya?ml|json)$/i.test(file.name);
    if (!ok) {
      toast.error("Unsupported file", { description: "Use .yaml, .yml, or .json" });
      return;
    }
    setPolicyFile(file);
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  };

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Policy" subtitle="Sign & Verify" onBack={() => navigate("/settings")} />

      {/* Tab Switcher */}
      <div className="mx-auto w-full max-w-2xl px-4 md:px-6 pt-4">
        <div className="flex p-1 rounded-lg" style={{ backgroundColor: "var(--muted)", borderRadius: "var(--radius-card)" }}>
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className="flex-1 flex items-center justify-center gap-1.5 transition-all"
              style={{
                height: "38px",
                borderRadius: "var(--radius)",
                backgroundColor: activeTab === id ? "var(--card)" : "transparent",
                color: activeTab === id ? "var(--foreground)" : "var(--muted-foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: activeTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                border: activeTab === id ? "1px solid var(--border)" : "none",
                cursor: "pointer",
              }}
            >
              <Icon size={14} />
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">
        {/* Policies Tab — with Active / Backup / Signed Policies categories */}
        {activeTab === "policies" && (
          <>
            {/* Category Switcher */}
            <div className="flex p-1 rounded-lg" style={{ backgroundColor: "var(--muted)", borderRadius: "var(--radius-card)" }}>
              {categories.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => { setPolicyCategory(id); if (id === "backup" && !backupYaml && !backupLoading) loadBackup(); }}
                  className="flex-1 flex items-center justify-center gap-1.5 transition-all"
                  style={{
                    height: "34px",
                    borderRadius: "var(--radius)",
                    backgroundColor: policyCategory === id ? "var(--card)" : "transparent",
                    color: policyCategory === id ? "var(--foreground)" : "var(--muted-foreground)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: policyCategory === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                    border: policyCategory === id ? "1px solid var(--border)" : "none",
                    cursor: "pointer",
                  }}
                >
                  <Icon size={13} />
                  {label}
                </button>
              ))}
            </div>

            {/* Active Category — list of policies, click to preview/edit/save/sign */}
            {policyCategory === "active" && (
              <>
                <div className="rounded-lg border p-4 flex items-start gap-3" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}>
                  <Info size={18} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
                  <div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", marginBottom: "4px" }}>
                      Edit & Deploy Active Policy
                    </p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", lineHeight: 1.5 }}>
                      Click a policy to preview its YAML, edit, save, then sign &amp; deploy to produce <code>policy.sig</code>.
                    </p>
                  </div>
                </div>

                {activePolicies.length === 0 ? (
                  <div
                    className="rounded-lg border flex flex-col items-center justify-center text-center"
                    style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", padding: "48px 24px", minHeight: 220 }}
                  >
                    <FileText size={28} style={{ color: "var(--muted-foreground)", marginBottom: 12 }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: 4 }}>
                      No active policy
                    </p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      Sign a policy file in the Sign tab — it will become the Active policy.
                    </p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-3">
                    {activePolicies.map((policy) => {
                      const isOpen = selectedActiveId === policy.id;
                      const formatDate = (dateStr: string) => {
                        const d = new Date(dateStr);
                        return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
                      };
                      return (
                        <div
                          key={policy.id}
                          className="rounded-lg border overflow-hidden"
                          style={{ backgroundColor: "var(--card)", borderColor: isOpen ? "var(--primary)" : "var(--border)" }}
                        >
                          <button
                            onClick={() => handleToggleActiveRow(policy.id)}
                            className="w-full flex items-center gap-3 p-4 text-left"
                            style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
                          >
                            <div
                              className="flex items-center justify-center rounded-lg flex-shrink-0"
                              style={{
                                width: "40px",
                                height: "40px",
                                backgroundColor: policy.verified
                                  ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
                                  : "color-mix(in srgb, var(--chart-5) 15%, transparent)",
                              }}
                            >
                              {policy.verified ? (
                                <FileCheck size={20} style={{ color: "var(--chart-2)" }} />
                              ) : (
                                <FileX size={20} style={{ color: "var(--chart-5)" }} />
                              )}
                            </div>
                            <div className="flex-1 min-w-0">
                              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "2px" }}>
                                {policy.name}
                              </p>
                              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                                Signed {formatDate(policy.signedAt)}
                              </p>
                            </div>
                            <VerifiedBadge verified={policy.verified} />
                          </button>

                          {isOpen && (
                            <div className="border-t" style={{ borderColor: "var(--border)" }}>
                              <div className="flex items-center justify-between gap-3 px-4 py-3 border-b" style={{ borderColor: "var(--border)" }}>
                                <div className="min-w-0">
                                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                                    Policy YAML
                                  </p>
                                  <p style={{
                                    fontFamily: "JetBrains Mono, monospace",
                                    fontSize: "10px",
                                    color: "var(--muted-foreground)",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}>
                                    {currentLoading
                                      ? "Loading current policy…"
                                      : currentLoadError
                                        ? `Error: ${currentLoadError}`
                                        : currentPath || policy.path || "GET /api/v1/policy/current"}
                                  </p>
                                </div>
                                <div className="flex items-center gap-2 flex-shrink-0">
                                  {/* View mode toggle: Rendered | Code | Edit */}
                                  <div className="flex p-0.5 rounded gap-0.5" style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
                                    {([
                                      { id: "rendered" as const, label: "Rendered", icon: LayoutList },
                                      { id: "code" as const, label: "Code", icon: FileCode },
                                      { id: "edit" as const, label: "Edit", icon: Pen },
                                    ]).map(({ id, label, icon: Icon }) => (
                                      <button
                                        key={id}
                                        onClick={() => setActivePreviewMode(id)}
                                        disabled={currentLoading}
                                        className="flex items-center gap-1 px-2 py-1 rounded"
                                        style={{
                                          backgroundColor: activePreviewMode === id ? "var(--card)" : "transparent",
                                          border: activePreviewMode === id ? "1px solid var(--border)" : "1px solid transparent",
                                          color: activePreviewMode === id ? "var(--foreground)" : "var(--muted-foreground)",
                                          cursor: currentLoading ? "not-allowed" : "pointer",
                                          fontFamily: "Inter, sans-serif",
                                          fontSize: "var(--text-xs)",
                                          fontWeight: activePreviewMode === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                                          whiteSpace: "nowrap",
                                          opacity: currentLoading ? 0.6 : 1,
                                        }}
                                      >
                                        <Icon size={11} />
                                        {label}
                                      </button>
                                    ))}
                                  </div>
                                  <button
                                    onClick={loadCurrent}
                                    disabled={currentLoading}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded transition-opacity active:opacity-80"
                                    style={{
                                      backgroundColor: "var(--muted)",
                                      color: "var(--foreground)",
                                      border: "1px solid var(--border)",
                                      cursor: currentLoading ? "not-allowed" : "pointer",
                                      fontFamily: "Inter, sans-serif",
                                      fontSize: "var(--text-xs)",
                                      fontWeight: "var(--font-weight-medium)",
                                      opacity: currentLoading ? 0.6 : 1,
                                    }}
                                  >
                                    <RotateCcw size={12} className={currentLoading ? "animate-spin" : ""} />
                                    Reload
                                  </button>
                                </div>
                              </div>

                              {currentLoading ? (
                                <div
                                  className="flex items-center gap-2 px-4 py-6"
                                  style={{ background: "var(--background)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
                                >
                                  <Loader2 size={14} className="animate-spin" /> Loading…
                                </div>
                              ) : activePreviewMode === "rendered" ? (
                                <YamlRenderedView yaml={currentYaml} />
                              ) : activePreviewMode === "code" ? (
                                currentYaml.trim() ? (
                                  <YamlCodeView yaml={currentYaml} />
                                ) : (
                                  <div
                                    className="px-4 py-6"
                                    style={{ background: "var(--background)", fontFamily: "JetBrains Mono, monospace", fontSize: "12px", color: "var(--muted-foreground)" }}
                                  >
                                    # YAML policy will appear here — switch to Edit to author one
                                  </div>
                                )
                              ) : (
                              <textarea
                                value={currentYaml}
                                onChange={(e) => setCurrentYaml(e.target.value)}
                                onPaste={(e) => {
                                  e.preventDefault();
                                  const pasted = e.clipboardData.getData("text");
                                  const lines = pasted.split("\n");
                                  const minIndent = lines
                                    .filter((l) => l.trim().length > 0)
                                    .reduce((min, l) => Math.min(min, l.match(/^(\s*)/)?.[1].length ?? 0), Infinity);
                                  const dedented = lines.map((l) => l.slice(minIndent === Infinity ? 0 : minIndent)).join("\n");
                                  const ta = e.currentTarget;
                                  const start = ta.selectionStart;
                                  const end = ta.selectionEnd;
                                  const next = currentYaml.slice(0, start) + dedented + currentYaml.slice(end);
                                  setCurrentYaml(next);
                                }}
                                spellCheck={false}
                                disabled={currentLoading}
                                placeholder={currentLoading ? "Loading…" : "# YAML policy will appear here"}
                                style={{
                                  width: "100%",
                                  minHeight: 320,
                                  padding: "12px 14px",
                                  background: "var(--background)",
                                  color: "var(--foreground)",
                                  border: "none",
                                  outline: "none",
                                  resize: "vertical",
                                  fontFamily: "JetBrains Mono, monospace",
                                  fontSize: "12px",
                                  lineHeight: 1.55,
                                  whiteSpace: "pre",
                                  overflowWrap: "normal",
                                  overflowX: "auto",
                                }}
                              />
                              )}

                              <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-t" style={{ borderColor: "var(--border)" }}>
                                <div className="flex items-center gap-2 min-w-0">
                                  {dirty ? (
                                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-5)" }}>
                                      Unsaved changes
                                    </span>
                                  ) : currentDigest ? (
                                    <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                      sha256: {currentDigest}
                                    </span>
                                  ) : (
                                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                                      In sync with server
                                    </span>
                                  )}
                                </div>

                                <div className="flex flex-wrap items-center gap-2">
                                  <button
                                    onClick={handleSaveCurrent}
                                    disabled={!dirty || isSavingCurrent || currentLoading}
                                    className="flex items-center gap-1.5 px-3 py-2 rounded transition-opacity active:opacity-80"
                                    style={{
                                      backgroundColor: "var(--muted)",
                                      color: "var(--foreground)",
                                      border: "1px solid var(--border)",
                                      cursor: !dirty || isSavingCurrent || currentLoading ? "not-allowed" : "pointer",
                                      fontFamily: "Inter, sans-serif",
                                      fontSize: "var(--text-xs)",
                                      fontWeight: "var(--font-weight-medium)",
                                      opacity: !dirty || isSavingCurrent || currentLoading ? 0.6 : 1,
                                    }}
                                  >
                                    {isSavingCurrent ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                                    {isSavingCurrent ? "Saving…" : "Save"}
                                  </button>

                                  <button
                                    onClick={handleSignDeployCurrent}
                                    disabled={isDeployingCurrent || dirty || currentLoading}
                                    className="flex items-center gap-1.5 px-3 py-2 rounded transition-opacity active:opacity-80"
                                    style={{
                                      backgroundColor: "var(--primary)",
                                      color: "var(--primary-foreground)",
                                      border: "none",
                                      cursor: isDeployingCurrent || dirty || currentLoading ? "not-allowed" : "pointer",
                                      fontFamily: "Inter, sans-serif",
                                      fontSize: "var(--text-xs)",
                                      fontWeight: "var(--font-weight-semibold)",
                                      opacity: isDeployingCurrent || dirty || currentLoading ? 0.6 : 1,
                                    }}
                                  >
                                    {isDeployingCurrent ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
                                    {isDeployingCurrent ? "Signing…" : "Sign & Deploy"}
                                  </button>

                                  <button
                                    onClick={handleVerifyDeployed}
                                    disabled={isVerifyingDeployed}
                                    className="flex items-center gap-1.5 px-3 py-2 rounded transition-opacity active:opacity-80"
                                    style={{
                                      backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
                                      color: "var(--chart-2)",
                                      border: "1px solid color-mix(in srgb, var(--chart-2) 30%, transparent)",
                                      cursor: isVerifyingDeployed ? "not-allowed" : "pointer",
                                      fontFamily: "Inter, sans-serif",
                                      fontSize: "var(--text-xs)",
                                      fontWeight: "var(--font-weight-semibold)",
                                      opacity: isVerifyingDeployed ? 0.6 : 1,
                                    }}
                                  >
                                    {isVerifyingDeployed ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
                                    {isVerifyingDeployed ? "Verifying…" : "Verify deployed"}
                                  </button>
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}

            {/* Backup Category — previously-active policies (read-only history) */}
            {policyCategory === "backup" && (
              <>
                <div className="rounded-lg border p-4 flex items-start gap-3" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}>
                  <Archive size={18} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
                  <div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", marginBottom: "4px" }}>
                      Backup Policies
                    </p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", lineHeight: 1.5 }}>
                      Snapshots of previously-active policies. Click a row to preview its YAML.
                    </p>
                  </div>
                </div>

                {backupLoading && !backupYaml ? (
                  <div className="rounded-lg border flex flex-col items-center justify-center text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", padding: "48px 24px", minHeight: 220 }}>
                    <Loader2 size={28} className="animate-spin" style={{ color: "var(--primary)", marginBottom: 12 }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Loading backup policy…</p>
                  </div>
                ) : backupLoadError && !backupYaml ? (
                  <div className="rounded-lg border flex flex-col items-center justify-center text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", padding: "48px 24px", minHeight: 220 }}>
                    <Archive size={28} style={{ color: "var(--muted-foreground)", marginBottom: 12 }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: 4 }}>No backup policy</p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Backups appear when a new policy is signed and replaces the current active one.</p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-3">
                    {[{ id: "backup-real", name: "backup_policy.yaml", signedAt: backupUpdatedAt || new Date().toISOString(), verified: false }].map((policy) => {
                      const isOpen = selectedActiveId === policy.id;
                      const formatDate = (dateStr: string) => {
                        const d = new Date(dateStr);
                        return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
                      };
                      return (
                        <div
                          key={policy.id}
                          className="rounded-lg border overflow-hidden"
                          style={{ backgroundColor: "var(--card)", borderColor: isOpen ? "var(--primary)" : "var(--border)" }}
                        >
                          <button
                            onClick={() => handleToggleActiveRow(policy.id)}
                            className="w-full flex items-center gap-3 p-4 text-left"
                            style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
                          >
                            <div
                              className="flex items-center justify-center rounded-lg flex-shrink-0"
                              style={{
                                width: "40px",
                                height: "40px",
                                backgroundColor: "color-mix(in srgb, var(--muted-foreground) 12%, transparent)",
                              }}
                            >
                              <Archive size={20} style={{ color: "var(--muted-foreground)" }} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "2px" }}>
                                {policy.name}
                              </p>
                              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                                Signed {formatDate(policy.signedAt)}
                              </p>
                            </div>
                            <VerifiedBadge verified={policy.verified} archived={true} />
                          </button>

                          {isOpen && (
                            <div className="border-t" style={{ borderColor: "var(--border)" }}>
                              <div className="flex items-center justify-between gap-3 px-4 py-3 border-b" style={{ borderColor: "var(--border)" }}>
                                <div className="min-w-0">
                                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                                    Policy YAML (read-only)
                                  </p>
                                  <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                    {backupLoading ? "Loading backup policy…" : backupLoadError ? `Error: ${backupLoadError}` : backupPath || "/etc/sgx-guardian/policies/backup_policy.yaml"}
                                  </p>
                                </div>
                                <div className="flex items-center gap-2 flex-shrink-0">
                                  {/* View toggle: rendered / YAML / diff */}
                                  <div className="flex p-0.5 rounded gap-0.5" style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
                                    {([
                                      { id: "rendered" as const, label: "Rendered", icon: LayoutList },
                                      { id: "yaml" as const, label: "YAML", icon: FileCode },
                                      { id: "diff" as const, label: "Diff vs Active", icon: GitCompare },
                                    ]).map(({ id, label, icon: Icon }) => (
                                      <button
                                        key={id}
                                        onClick={() => setBackupView(id)}
                                        className="flex items-center gap-1 px-2 py-1 rounded"
                                        style={{
                                          backgroundColor: backupView === id ? "var(--card)" : "transparent",
                                          border: backupView === id ? "1px solid var(--border)" : "1px solid transparent",
                                          color: backupView === id ? "var(--foreground)" : "var(--muted-foreground)",
                                          cursor: "pointer",
                                          fontFamily: "Inter, sans-serif",
                                          fontSize: "var(--text-xs)",
                                          fontWeight: backupView === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                                          whiteSpace: "nowrap",
                                        }}
                                      >
                                        <Icon size={11} />
                                        {label}
                                      </button>
                                    ))}
                                  </div>
                                  <button
                                    onClick={handleCopyBackup}
                                    disabled={!backupYaml}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded transition-opacity active:opacity-80"
                                    style={{ backgroundColor: "var(--muted)", color: backupCopied ? "var(--chart-2)" : "var(--foreground)", border: "1px solid var(--border)", cursor: backupYaml ? "pointer" : "not-allowed", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", opacity: backupYaml ? 1 : 0.6 }}
                                  >
                                    {backupCopied ? <Check size={12} /> : <Copy size={12} />}
                                    {backupCopied ? "Copied" : "Copy"}
                                  </button>
                                  <button
                                    onClick={loadBackup}
                                    disabled={backupLoading}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded transition-opacity active:opacity-80"
                                    style={{ backgroundColor: "var(--muted)", color: "var(--foreground)", border: "1px solid var(--border)", cursor: backupLoading ? "not-allowed" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", opacity: backupLoading ? 0.6 : 1 }}
                                  >
                                    <RotateCcw size={12} className={backupLoading ? "animate-spin" : ""} />
                                    Reload
                                  </button>
                                </div>
                              </div>

                              {backupLoading ? (
                                <div className="flex items-center justify-center gap-2" style={{ minHeight: 220, backgroundColor: "var(--background)" }}>
                                  <Loader2 size={18} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
                                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Loading backup policy…</span>
                                </div>
                              ) : backupLoadError ? (
                                <div className="flex items-center justify-center" style={{ minHeight: 220, backgroundColor: "var(--background)" }}>
                                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--destructive)" }}>{backupLoadError}</span>
                                </div>
                              ) : backupView === "diff" ? (
                                <BackupDiffView backupYaml={backupYaml} activeYaml={savedYaml} />
                              ) : backupView === "yaml" ? (
                                <YamlCodeView yaml={backupYaml} />
                              ) : (
                                <YamlRenderedView yaml={backupYaml} />
                              )}

                              <div className="px-4 py-3 border-t" style={{ borderColor: "var(--border)" }}>
                                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                                  {[
                                    backupUpdatedAt ? `Last updated: ${new Date(backupUpdatedAt).toLocaleString()}` : "Read-only snapshot of previously active policy",
                                    backupYaml ? `${backupYaml.replace(/\n$/, "").split("\n").length} lines · ${new Blob([backupYaml]).size} bytes` : null,
                                  ].filter(Boolean).join("  ·  ")}
                                </span>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}

            {/* Signed Policies Category */}
            {policyCategory === "signed" && (
              <>
                {/* Stats */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <FileText size={14} style={{ color: "var(--primary)" }} />
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                        Total Policies
                      </span>
                    </div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>
                      {policies.length}
                    </p>
                  </div>
                  <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
                    <div className="flex items-center gap-2 mb-1">
                      <CheckCircle2 size={14} style={{ color: "var(--chart-2)" }} />
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                        Verified
                      </span>
                    </div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: "var(--chart-2)" }}>
                      {verifiedCount}/{policies.length}
                    </p>
                  </div>
                </div>

                {/* Policy List */}
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "12px" }}>
                    Signed Policies
                  </p>
                  <div className="flex flex-col gap-3">
                    {policies.map(policy => (
                      <PolicyCard key={policy.id} policy={policy} onVerify={() => handleVerify(policy.id)} />
                    ))}
                  </div>
                </div>
              </>
            )}
          </>
        )}

        {/* Sign Tab */}
        {activeTab === "sign" && (
          <>
            <div className="rounded-lg border p-5" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
              <div className="flex items-center gap-3 mb-4">
                <div
                  className="flex items-center justify-center rounded-lg"
                  style={{ width: "48px", height: "48px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)" }}
                >
                  <Pen size={24} style={{ color: "var(--primary)" }} />
                </div>
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                    Sign Policy
                  </p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                    Sign a UEP policy file with ECDSA-P256
                  </p>
                </div>
              </div>

              {/* Upload Area */}
              <div
                role="button"
                tabIndex={0}
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    fileInputRef.current?.click();
                  }
                }}
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setIsDragging(false);
                  acceptPolicyFile(e.dataTransfer.files?.[0]);
                }}
                className="border-2 border-dashed rounded-lg p-8 flex flex-col items-center justify-center text-center mb-4"
                style={{
                  borderColor: isDragging ? "var(--primary)" : "var(--border)",
                  backgroundColor: isDragging
                    ? "color-mix(in srgb, var(--primary) 8%, transparent)"
                    : "var(--muted)",
                  cursor: "pointer",
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".yaml,.yml,.json,application/json,application/x-yaml,text/yaml"
                  style={{ display: "none" }}
                  onChange={(e) => acceptPolicyFile(e.target.files?.[0])}
                />
                {policyFile ? (
                  <>
                    <FileCheck size={32} style={{ color: "var(--chart-2)", marginBottom: "12px" }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)", marginBottom: "4px", wordBreak: "break-all" }}>
                      {policyFile.name}
                    </p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      {(policyFile.size / 1024).toFixed(1)} KB · click to change
                    </p>
                  </>
                ) : (
                  <>
                    <Upload size={32} style={{ color: "var(--muted-foreground)", marginBottom: "12px" }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)", marginBottom: "4px" }}>
                      Drop policy file here
                    </p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      Supports .yaml and .json files
                    </p>
                  </>
                )}
              </div>

              {/* Key Selection */}
              <div className="mb-4">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "8px" }}>
                  Signing Key
                </p>
                <div className="flex items-center gap-3 p-3 rounded-lg border" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
                  <Key size={16} style={{ color: "var(--primary)" }} />
                  <div className="flex-1">
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
                      {keyStatus?.fingerprint ? `guardian_policy_key` : keyLoading ? "Loading…" : "guardian_policy_key"}
                    </p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      {keyStatus?.algorithm ?? "ECDSA-P256"}
                    </p>
                  </div>
                  <CheckCircle2 size={16} style={{ color: "var(--chart-2)" }} />
                </div>
              </div>

              <button
                onClick={handleSign}
                disabled={isSigning || !policyFile}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
                style={{
                  backgroundColor: "var(--primary)",
                  color: "var(--primary-foreground)",
                  border: "none",
                  cursor: isSigning || !policyFile ? "not-allowed" : "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                  opacity: isSigning || !policyFile ? 0.6 : 1,
                }}
              >
                <Pen size={16} />
                {isSigning ? "Signing..." : "Sign Policy"}
              </button>
            </div>

            <div className="flex items-start gap-3 p-4 rounded-lg" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)" }}>
              <Info size={18} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", lineHeight: 1.5 }}>
                Signing creates a .sig file containing the original policy, SHA-256 digest, and ECDSA signature.
              </p>
            </div>
          </>
        )}

        {/* Keys Tab */}
        {activeTab === "keys" && (
          <>
            <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
              <div className="flex items-center justify-between mb-4">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                  Policy Authority Key
                </p>
                <span
                  className="px-2 py-1 rounded"
                  style={{
                    backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-medium)",
                    color: "var(--chart-2)",
                  }}
                >
                  Active
                </span>
              </div>

              <div className="flex items-center gap-3 mb-4">
                <div
                  className="flex items-center justify-center rounded-lg"
                  style={{ width: "48px", height: "48px", backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)" }}
                >
                  {keyLoading ? <Loader2 size={24} className="animate-spin" style={{ color: "var(--chart-2)" }} /> : <Key size={24} style={{ color: "var(--chart-2)" }} />}
                </div>
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                    guardian_primary
                  </p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                    {keyStatus?.algorithm ?? "ECDSA-P256"}
                  </p>
                </div>
              </div>

              <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
                {[
                  { label: "Public Key", value: keyStatus?.publicKeyPath ?? "Loading…" },
                  { label: "Private Key", value: keyStatus ? (keyStatus.privateKeyExists ? "Available (mode 0600)" : "Not found") : "Loading…" },
                  { label: "Provider", value: keyStatus?.provider ?? "software" },
                  { label: "Fingerprint", value: keyStatus?.fingerprint ?? (keyLoading ? "Loading…" : "Unknown") },
                ].map(({ label, value }, i, arr) => (
                  <div
                    key={label}
                    className="flex items-center justify-between px-4 py-3"
                    style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}
                  >
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      {label}
                    </span>
                    <span
                      style={{
                        fontFamily: label === "Fingerprint" || label === "Public Key" ? "JetBrains Mono, monospace" : "Inter, sans-serif",
                        fontSize: label === "Fingerprint" ? "10px" : "var(--text-xs)",
                        fontWeight: "var(--font-weight-medium)",
                        color: "var(--foreground)",
                      }}
                    >
                      {value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <button
              disabled={isGeneratingKey}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
              style={{
                backgroundColor: keyStatus?.exists
                  ? "color-mix(in srgb, var(--chart-5) 15%, transparent)"
                  : "color-mix(in srgb, var(--chart-2) 15%, transparent)",
                color: keyStatus?.exists ? "var(--chart-5)" : "var(--chart-2)",
                border: `1px solid ${keyStatus?.exists ? "color-mix(in srgb, var(--chart-5) 30%, transparent)" : "color-mix(in srgb, var(--chart-2) 30%, transparent)"}`,
                cursor: isGeneratingKey ? "not-allowed" : "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                opacity: isGeneratingKey ? 0.6 : 1,
              }}
              onClick={() => {
                if (keyStatus?.exists) {
                  if (window.confirm("Keys already exist. Overwrite? Existing keys will be backed up.")) {
                    handleGenerateKey(true);
                  }
                } else {
                  handleGenerateKey(false);
                }
              }}
            >
              {isGeneratingKey ? <Loader2 size={16} className="animate-spin" /> : <Key size={16} />}
              {isGeneratingKey ? "Generating…" : keyStatus?.exists ? "Regenerate Keypair" : "Generate New Keypair"}
            </button>

            <div className="flex items-start gap-3 p-4 rounded-lg" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)" }}>
              <Info size={18} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", lineHeight: 1.5 }}>
                The Policy Authority keypair is used to sign UEP policies. The private key is stored with restricted permissions (mode 0600).
              </p>
            </div>
          </>
        )}
        </div>
      </div>
    </div>
  );
}
