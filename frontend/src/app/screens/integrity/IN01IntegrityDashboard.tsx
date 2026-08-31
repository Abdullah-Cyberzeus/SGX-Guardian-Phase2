import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Clock,
  FileCheck,
  FilePlus,
  RefreshCw,
  ChevronRight,
  Copy,
  Check,
  Info,
  Cpu,
  HardDrive,
  Settings,
  Terminal,
  Layers,
  Loader2,
} from "lucide-react";
import { usePCRStatus, usePCRBaseline, usePCRHistory } from "../../hooks/useApiData";
import { type PCRRegister, type PCRStatus, type PCRVerificationResult } from "../../services/pcrService";
import { pcrService } from "../../services/pcrService";
import { toast } from "sonner";
import { useAuth } from "../../contexts/AuthContext";
import { isAdminRole } from "../../utils/authorization";

type TabId = "status" | "baseline" | "history";

// PCR Register Icons
const PCR_ICONS: Record<number, typeof Cpu> = {
  0: Terminal,      // BIOS/Bootloader
  1: Cpu,           // Firmware/DTB
  2: Layers,        // Kernel
  3: HardDrive,     // RootFS
  4: Settings,      // Configuration
};

// Status Badge
function StatusBadge({ status, size = "default" }: { status: PCRStatus | "pass" | "fail" | string; size?: "default" | "large" }) {
  const config: Record<string, { bg: string; border: string; color: string; label: string; icon: typeof CheckCircle2 }> = {
    match: {
      bg: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
      border: "color-mix(in srgb, var(--chart-2) 30%, transparent)",
      color: "var(--chart-2)",
      label: "Match",
      icon: CheckCircle2,
    },
    pass: {
      bg: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
      border: "color-mix(in srgb, var(--chart-2) 30%, transparent)",
      color: "var(--chart-2)",
      label: "Pass",
      icon: CheckCircle2,
    },
    mismatch: {
      bg: "color-mix(in srgb, var(--destructive) 15%, transparent)",
      border: "color-mix(in srgb, var(--destructive) 30%, transparent)",
      color: "var(--destructive)",
      label: "Mismatch",
      icon: XCircle,
    },
    fail: {
      bg: "color-mix(in srgb, var(--destructive) 15%, transparent)",
      border: "color-mix(in srgb, var(--destructive) 30%, transparent)",
      color: "var(--destructive)",
      label: "Fail",
      icon: XCircle,
    },
    no_baseline: {
      bg: "color-mix(in srgb, var(--chart-5) 15%, transparent)",
      border: "color-mix(in srgb, var(--chart-5) 30%, transparent)",
      color: "var(--chart-5)",
      label: "No Baseline",
      icon: AlertCircle,
    },
    warning: {
      bg: "color-mix(in srgb, var(--chart-5) 15%, transparent)",
      border: "color-mix(in srgb, var(--chart-5) 30%, transparent)",
      color: "var(--chart-5)",
      label: "No Baseline",
      icon: AlertCircle,
    },
  };

  // Default fallback for unknown status values
  const defaultConfig = {
    bg: "color-mix(in srgb, var(--muted-foreground) 15%, transparent)",
    border: "color-mix(in srgb, var(--muted-foreground) 30%, transparent)",
    color: "var(--muted-foreground)",
    label: status || "Unknown",
    icon: AlertCircle,
  };

  const { bg, border, color, label, icon: Icon } = config[status] || defaultConfig;
  const isLarge = size === "large";

  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full"
      style={{
        padding: isLarge ? "6px 14px" : "4px 10px",
        backgroundColor: bg,
        border: `1px solid ${border}`,
        fontFamily: "Inter, sans-serif",
        fontSize: isLarge ? "var(--text-sm)" : "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        color,
      }}
    >
      <Icon size={isLarge ? 16 : 12} />
      {label}
    </span>
  );
}

// Hash Display with Copy
function HashDisplay({ hash, label }: { hash: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(hash).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const truncatedHash = `${hash.slice(0, 16)}...${hash.slice(-8)}`;

  return (
    <div className="flex items-center gap-2">
      {label && (
        <span
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
          }}
        >
          {label}:
        </span>
      )}
      <code
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: "11px",
          color: "var(--foreground)",
          backgroundColor: "var(--muted)",
          padding: "4px 8px",
          borderRadius: "4px",
        }}
      >
        {truncatedHash}
      </code>
      <button
        onClick={handleCopy}
        className="p-1 rounded transition-colors"
        style={{
          backgroundColor: copied ? "color-mix(in srgb, var(--chart-2) 15%, transparent)" : "transparent",
          border: "none",
          cursor: "pointer",
        }}
      >
        {copied ? (
          <Check size={14} style={{ color: "var(--chart-2)" }} />
        ) : (
          <Copy size={14} style={{ color: "var(--muted-foreground)" }} />
        )}
      </button>
    </div>
  );
}

// PCR Register Card
function PCRRegisterCard({
  register,
  showBaseline = false,
}: {
  register: PCRRegister;
  showBaseline?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const Icon = PCR_ICONS[register.index] || Shield;

  return (
    <div
      className="rounded-lg border overflow-hidden"
      style={{
        backgroundColor: "var(--card)",
        borderColor: register.status === "mismatch" ? "var(--destructive)" : "var(--border)",
      }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left transition-colors"
        style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
      >
        <div
          className="flex items-center justify-center rounded-lg flex-shrink-0"
          style={{
            width: "40px",
            height: "40px",
            backgroundColor:
              register.status === "match"
                ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
                : register.status === "mismatch"
                ? "color-mix(in srgb, var(--destructive) 15%, transparent)"
                : "var(--muted)",
          }}
        >
          <Icon
            size={20}
            style={{
              color:
                register.status === "match"
                  ? "var(--chart-2)"
                  : register.status === "mismatch"
                  ? "var(--destructive)"
                  : "var(--muted-foreground)",
            }}
          />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
              }}
            >
              {register.name}
            </p>
            <StatusBadge status={register.status} />
          </div>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            {register.description}
          </p>
        </div>
        <ChevronRight
          size={18}
          style={{
            color: "var(--muted-foreground)",
            transform: expanded ? "rotate(90deg)" : "rotate(0deg)",
            transition: "transform 0.2s ease",
          }}
        />
      </button>

      {expanded && (
        <div
          className="px-4 pb-4 pt-2 border-t flex flex-col gap-3"
          style={{ borderColor: "var(--border)" }}
        >
          <div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
                marginBottom: "6px",
              }}
            >
              Current Value
            </p>
            <code
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "10px",
                color: "var(--foreground)",
                backgroundColor: "var(--muted)",
                padding: "8px 12px",
                borderRadius: "6px",
                display: "block",
                wordBreak: "break-all",
                lineHeight: 1.6,
              }}
            >
              {register.currentValue}
            </code>
          </div>

          {showBaseline && register.baselineValue && (
            <div>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                  marginBottom: "6px",
                }}
              >
                Baseline Value
              </p>
              <code
                style={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: "10px",
                  color: register.status === "match" ? "var(--chart-2)" : "var(--destructive)",
                  backgroundColor:
                    register.status === "match"
                      ? "color-mix(in srgb, var(--chart-2) 10%, transparent)"
                      : "color-mix(in srgb, var(--destructive) 10%, transparent)",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  display: "block",
                  wordBreak: "break-all",
                  lineHeight: 1.6,
                }}
              >
                {register.baselineValue}
              </code>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Verification History Card
function VerificationCard({ result }: { result: PCRVerificationResult }) {
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

  return (
    <div
      className="rounded-lg border p-4"
      style={{
        backgroundColor: "var(--card)",
        borderColor: "var(--border)",
      }}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {result.status === "pass" ? (
            <ShieldCheck size={20} style={{ color: "var(--chart-2)" }} />
          ) : (
            <ShieldX size={20} style={{ color: "var(--destructive)" }} />
          )}
          <div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
              }}
            >
              Integrity Check
            </p>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
              }}
            >
              {formatDate(result.timestamp)}
            </p>
          </div>
        </div>
        <StatusBadge status={result.status} />
      </div>

      <div
        className="flex items-center justify-between p-3 rounded-lg"
        style={{ backgroundColor: "var(--muted)" }}
      >
        <span
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
          }}
        >
          PCR Registers
        </span>
        <span
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-semibold)",
            color: result.status === "pass" ? "var(--chart-2)" : "var(--destructive)",
          }}
        >
          {result.matchCount}/{result.totalCount} Match
        </span>
      </div>

      {result.mismatches.length > 0 && (
        <div className="mt-3 pt-3 border-t" style={{ borderColor: "var(--border)" }}>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--destructive)",
              marginBottom: "8px",
            }}
          >
            Mismatches Detected:
          </p>
          {result.mismatches.map((m) => (
            <div
              key={m.index}
              className="p-2 rounded mb-2"
              style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)" }}
            >
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-medium)",
                  color: "var(--foreground)",
                }}
              >
                {m.name}: {m.expected.slice(0, 12)}... ≠ {m.actual.slice(0, 12)}...
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Confirmation Dialog
function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: "rgba(0, 0, 0, 0.5)" }}
    >
      <div
        className="w-full max-w-sm rounded-xl p-6"
        style={{ backgroundColor: "var(--card)" }}
      >
        <div className="flex items-center gap-3 mb-4">
          <div
            className="flex items-center justify-center rounded-full"
            style={{
              width: "44px",
              height: "44px",
              backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)",
            }}
          >
            <Shield size={22} style={{ color: "var(--primary)" }} />
          </div>
          <h3
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-lg)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
            }}
          >
            {title}
          </h3>
        </div>

        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
            lineHeight: 1.6,
            marginBottom: "24px",
          }}
        >
          {description}
        </p>

        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 px-4 py-2.5 rounded-lg transition-opacity active:opacity-80"
            style={{
              backgroundColor: "var(--muted)",
              color: "var(--foreground)",
              border: "none",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-medium)",
            }}
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 px-4 py-2.5 rounded-lg transition-opacity active:opacity-80"
            style={{
              backgroundColor: "var(--primary)",
              color: "white",
              border: "none",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
            }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

// Main Component
export function IN01IntegrityDashboard() {
  const navigate = useNavigate();
  const location = useLocation();
  const { session } = useAuth();
  const isAdmin = isAdminRole(session?.user.role);
  const [activeTab, setActiveTab] = useState<TabId>("status");
  const [showCreateBaselineDialog, setShowCreateBaselineDialog] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);

  // Fetch data from backend API
  const { data: pcrData, loading, error, source, refetch } = usePCRStatus();
  const { data: baselineData } = usePCRBaseline();
  const { data: historyData } = usePCRHistory();
  const pcrRegisters = useMemo(() => {
    if (!pcrData || !pcrData.registers || !Array.isArray(pcrData.registers)) {
      return [];
    }
    return pcrData.registers;
  }, [pcrData]);
  const pcrMetadata = useMemo(() => {
    const defaults = { integrityStatus: 'UNKNOWN', dkpVersion: 0, compositeDigest: 'N/A', baselineExists: false };
    if (!pcrData) return defaults;
    return { ...defaults, ...pcrData };
  }, [pcrData]);

  const tabs: { id: TabId; label: string; icon: typeof Shield }[] = [
    { id: "status", label: "PCR Status", icon: Shield },
    { id: "baseline", label: "Baseline", icon: FileCheck },
    { id: "history", label: "History", icon: Clock },
  ];

  useEffect(() => {
    const tab = new URLSearchParams(location.search).get("tab") as TabId | null;
    if (tab && tabs.some((entry) => entry.id === tab)) {
      setActiveTab(tab);
    }
  }, [location.search]);

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

  const handleCreateBaseline = async () => {
    try {
      const res = await pcrService.updateBaseline();
      console.log("[PCR Baseline Create] POST /pcr/baseline/update →", res);
      setShowCreateBaselineDialog(false);
      if (res.success) {
        const verifiedAt = res.timestamp ? new Date(res.timestamp) : new Date();
        const diffMs = Math.max(0, Date.now() - verifiedAt.getTime());
        const minutes = Math.floor(diffMs / 60000);
        const hours = Math.floor(minutes / 60);
        const lastVerified = hours >= 1 ? `${hours} hour${hours === 1 ? "" : "s"} ago` : `${Math.max(1, minutes)} min ago`;
        toast.success("Device Integrity Verified.", {
          description: (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <span>All firmware and kernel measurements match trusted baseline.</span>
              <span>Last verified: {lastVerified}</span>
            </div>
          ),
          action: isAdmin
            ? {
                label: "View Details",
                onClick: () => {
                  setActiveTab("baseline");
                  navigate("/settings/integrity?tab=baseline");
                },
              }
            : undefined,
        });
      } else {
        toast.error(res.message || "Baseline creation failed", {
          description: res.stderr || res.stdout || "Check logs for details",
        });
      }
      await refetch();
    } catch (err) {
      toast.error("Baseline creation failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const res = await pcrService.verify();
      console.log("[PCR Verify] POST /pcr/verify →", res);
      if (res.success) {
        toast.success(res.message || "Integrity verified", {
          description: res.stdout || `All ${pcrRegisters.length} PCR registers verified`,
        });
      } else {
        toast.error(res.message || "Verification found issues", {
          description: res.stderr || res.stdout || "Check PCR registers for details",
        });
      }
      await refetch();
    } catch (err) {
      toast.error("Verification failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsVerifying(false);
    }
  };

  // Trust the backend's overall integrity verdict over the per-register
  // status. Backends that report PASS at the device level may leave
  // per-register status unset, which previously made the page show a
  // "warning" pill even after a successful baseline verification.
  const status = String(pcrMetadata.integrityStatus || '').toUpperCase();
  const allMatch = status === 'PASS' || status === 'HEALTHY';
  const noBaseline = !pcrMetadata.baselineExists
    || status === 'NO_BASELINE'
    || status === 'UNKNOWN'
    || (!status && pcrRegisters.every((r: PCRRegister) => r.status === 'no_baseline'));

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center" style={{ minHeight: "100dvh" }}>
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Integrity" subtitle="PCR Measurements" onBack={() => navigate("/settings")} />

      {/* Overall Status Banner */}
      <div className="mx-auto w-full max-w-2xl px-4 md:px-6 mt-4">
      <div
        className="flex items-center gap-3 p-4 rounded-lg"
        style={{
          backgroundColor: allMatch
            ? "color-mix(in srgb, var(--chart-2) 10%, transparent)"
            : noBaseline
              ? "color-mix(in srgb, var(--chart-5) 10%, transparent)"
              : "color-mix(in srgb, var(--destructive) 10%, transparent)",
          border: `1px solid ${
            allMatch
              ? "color-mix(in srgb, var(--chart-2) 25%, transparent)"
              : noBaseline
                ? "color-mix(in srgb, var(--chart-5) 25%, transparent)"
                : "color-mix(in srgb, var(--destructive) 25%, transparent)"
          }`,
        }}
      >
        {allMatch ? (
          <ShieldCheck size={24} style={{ color: "var(--chart-2)" }} />
        ) : (
          <ShieldAlert size={24} style={{ color: noBaseline ? "var(--chart-5)" : "var(--destructive)" }} />
        )}
        <div className="flex-1">
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              color: allMatch ? "var(--chart-2)" : noBaseline ? "var(--chart-5)" : "var(--destructive)",
            }}
          >
            {allMatch ? "Device Integrity Verified" : noBaseline ? "No Baseline Established" : "Integrity Check Failed"}
          </p>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: allMatch ? "var(--chart-2)" : noBaseline ? "var(--chart-5)" : "var(--destructive)",
              opacity: 0.85,
            }}
          >
            {allMatch
              ? "All PCR measurements match golden baseline"
              : noBaseline
                ? "Create a golden baseline to enable integrity verification"
                : "One or more PCR registers do not match baseline"}
          </p>
        </div>
        <StatusBadge status={allMatch ? "pass" : noBaseline ? "warning" : "fail"} size="large" />
      </div>
      </div>

      {/* Tab Switcher */}
      <div className="mx-auto w-full max-w-2xl px-4 md:px-6 pt-4">
        <div
          className="flex p-1 rounded-lg"
          style={{
            backgroundColor: "var(--muted)",
            borderRadius: "var(--radius-card)",
          }}
        >
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
                boxShadow: activeTab === id ? "var(--elevation-sm)" : "none",
              }}
            >
              <Icon size={14} />
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6">
        {/* PCR Status Tab */}
        {activeTab === "status" && (
          <div className="flex flex-col gap-4">
            {/* Summary Card */}
            <div
              className="rounded-lg border p-4"
              style={{
                backgroundColor: "var(--card)",
                borderColor: "var(--border)",
              }}
            >
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div
                  className="p-3 rounded-lg"
                  style={{ backgroundColor: "var(--muted)" }}
                >
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                      marginBottom: "4px",
                    }}
                  >
                    Integrity Status
                  </p>
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      fontWeight: "var(--font-weight-bold)",
                      color: allMatch ? "var(--chart-2)" : "var(--destructive)",
                    }}
                  >
                    {pcrMetadata.integrityStatus}
                  </p>
                </div>
                <div
                  className="p-3 rounded-lg"
                  style={{ backgroundColor: "var(--muted)" }}
                >
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                      marginBottom: "4px",
                    }}
                  >
                    DKP Version
                  </p>
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      fontWeight: "var(--font-weight-bold)",
                      color: "var(--foreground)",
                    }}
                  >
                    v{pcrMetadata.dkpVersion}
                  </p>
                </div>
              </div>

              <div className="mb-4">
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    color: "var(--muted-foreground)",
                    marginBottom: "6px",
                  }}
                >
                  Composite Digest
                </p>
                <HashDisplay hash={pcrMetadata.compositeDigest} />
              </div>

              <button
                onClick={handleVerify}
                disabled={isVerifying}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
                style={{
                  backgroundColor: "var(--primary)",
                  color: "var(--primary-foreground)",
                  border: "none",
                  cursor: isVerifying ? "not-allowed" : "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                  opacity: isVerifying ? 0.7 : 1,
                }}
              >
                <RefreshCw
                  size={16}
                  style={{
                    animation: isVerifying ? "spin 1s linear infinite" : "none",
                  }}
                />
                {isVerifying ? "Verifying..." : "Verify Against Baseline"}
              </button>
            </div>

            {/* PCR Registers */}
            <div>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-semibold)",
                  color: "var(--muted-foreground)",
                  letterSpacing: "0.08em",
                  marginBottom: "12px",
                }}
              >
                PCR Registers ({pcrRegisters.length})
              </p>
              <div className="flex flex-col gap-3">
                {pcrRegisters.map((register: PCRRegister) => (
                  <PCRRegisterCard
                    key={register.index}
                    register={register}
                    showBaseline={pcrMetadata.baselineExists}
                  />
                ))}
              </div>
            </div>

            {/* Info */}
            <div
              className="flex items-start gap-3 p-4 rounded-lg"
              style={{
                backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)",
                border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)",
              }}
            >
              <Info size={18} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--primary)",
                  lineHeight: 1.5,
                }}
              >
                PCR values are cryptographic measurements of the boot chain, firmware, kernel, rootfs, and configuration. They form the integrity fingerprint of the device.
              </p>
            </div>
          </div>
        )}

        {/* Baseline Tab */}
        {activeTab === "baseline" && (
          <div className="flex flex-col gap-4">
            {pcrMetadata.baselineExists ? (
              <>
                {/* Current Baseline */}
                <div
                  className="rounded-lg border p-4"
                  style={{
                    backgroundColor: "var(--card)",
                    borderColor: "var(--border)",
                  }}
                >
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div
                        className="flex items-center justify-center rounded-lg"
                        style={{
                          width: "44px",
                          height: "44px",
                          backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
                        }}
                      >
                        <FileCheck size={22} style={{ color: "var(--chart-2)" }} />
                      </div>
                      <div>
                        <p
                          style={{
                            fontFamily: "Inter, sans-serif",
                            fontSize: "var(--text-base)",
                            fontWeight: "var(--font-weight-semibold)",
                            color: "var(--foreground)",
                          }}
                        >
                          Golden Baseline
                        </p>
                        <p
                          style={{
                            fontFamily: "Inter, sans-serif",
                            fontSize: "var(--text-xs)",
                            color: "var(--muted-foreground)",
                          }}
                        >
                          {baselineData?.version ? `Version: ${baselineData.version}` : "Golden Baseline"}
                        </p>
                      </div>
                    </div>
                    <StatusBadge status={pcrMetadata.integrityStatus === 'PASS' ? 'match' : pcrMetadata.integrityStatus === 'DEGRADED' ? 'mismatch' : 'unknown'} />
                  </div>

                  <div
                    className="rounded-lg border overflow-hidden"
                    style={{
                      backgroundColor: "var(--background)",
                      borderColor: "var(--border)",
                    }}
                  >
                    {[
                      { label: "Created", value: baselineData?.createdAt ? formatDate(baselineData.createdAt) : "—" },
                      { label: "Version", value: baselineData?.version ?? "—" },
                      { label: "Registers", value: baselineData?.registers ? `${baselineData.registers.length} PCRs` : "—" },
                    ].map(({ label, value }, i, arr) => (
                      <div
                        key={label}
                        className="flex items-center justify-between px-4 py-3"
                        style={{
                          borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined,
                        }}
                      >
                        <span
                          style={{
                            fontFamily: "Inter, sans-serif",
                            fontSize: "var(--text-xs)",
                            color: "var(--muted-foreground)",
                          }}
                        >
                          {label}
                        </span>
                        <span
                          style={{
                            fontFamily: "Inter, sans-serif",
                            fontSize: "var(--text-xs)",
                            fontWeight: "var(--font-weight-medium)",
                            color: "var(--foreground)",
                          }}
                        >
                          {value}
                        </span>
                      </div>
                    ))}
                  </div>

                  <div className="mt-4">
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-xs)",
                        color: "var(--muted-foreground)",
                        marginBottom: "6px",
                      }}
                    >
                      Composite Digest
                    </p>
                    <HashDisplay hash={baselineData?.hash ?? pcrData?.compositeDigest ?? "—"} />
                  </div>
                </div>

                {/* Baseline PCR Values */}
                <div>
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      fontWeight: "var(--font-weight-semibold)",
                      color: "var(--muted-foreground)",
                      letterSpacing: "0.08em",
                      marginBottom: "12px",
                    }}
                  >
                    Baseline Values
                  </p>
                  <div
                    className="rounded-lg border overflow-hidden"
                    style={{
                      backgroundColor: "var(--card)",
                      borderColor: "var(--border)",
                    }}
                  >
                    {(baselineData?.registers ?? pcrRegisters.map(r => ({ index: r.index, value: r.currentValue, description: r.description }))).map((reg, i, arr) => {
                      const pcrInfo = pcrRegisters.find((r) => r.index === reg.index);
                      return (
                        <div
                          key={reg.index}
                          className="px-4 py-3"
                          style={{
                            borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined,
                          }}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span
                              style={{
                                fontFamily: "Inter, sans-serif",
                                fontSize: "var(--text-xs)",
                                fontWeight: "var(--font-weight-semibold)",
                                color: "var(--foreground)",
                              }}
                            >
                              PCR{reg.index}
                            </span>
                            <span
                              style={{
                                fontFamily: "Inter, sans-serif",
                                fontSize: "var(--text-xs)",
                                color: "var(--muted-foreground)",
                              }}
                            >
                              {pcrInfo?.description}
                            </span>
                          </div>
                          <code
                            style={{
                              fontFamily: "JetBrains Mono, monospace",
                              fontSize: "10px",
                              color: "var(--muted-foreground)",
                              wordBreak: "break-all",
                            }}
                          >
                            {reg.value.slice(0, 32)}...
                          </code>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Re-create Baseline */}
                <button
                  onClick={() => setShowCreateBaselineDialog(true)}
                  className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
                  style={{
                    backgroundColor: "color-mix(in srgb, var(--chart-5) 15%, transparent)",
                    color: "var(--chart-5)",
                    border: "1px solid color-mix(in srgb, var(--chart-5) 30%, transparent)",
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-semibold)",
                  }}
                >
                  <FilePlus size={16} />
                  Create New Baseline
                </button>
              </>
            ) : (
              /* No Baseline State */
              <div
                className="rounded-lg border p-8 flex flex-col items-center justify-center text-center"
                style={{
                  backgroundColor: "var(--card)",
                  borderColor: "var(--border)",
                }}
              >
                <div
                  className="flex items-center justify-center rounded-full mb-4"
                  style={{
                    width: "64px",
                    height: "64px",
                    backgroundColor: "color-mix(in srgb, var(--chart-5) 15%, transparent)",
                  }}
                >
                  <FileCheck size={32} style={{ color: "var(--chart-5)" }} />
                </div>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-base)",
                    fontWeight: "var(--font-weight-semibold)",
                    color: "var(--foreground)",
                    marginBottom: "8px",
                  }}
                >
                  No Baseline Created
                </p>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    color: "var(--muted-foreground)",
                    lineHeight: 1.6,
                    maxWidth: "280px",
                    marginBottom: "24px",
                  }}
                >
                  Create a golden baseline from the current PCR snapshot to enable integrity verification.
                </p>
                <button
                  onClick={() => setShowCreateBaselineDialog(true)}
                  className="flex items-center gap-2 px-6 py-3 rounded-lg transition-opacity active:opacity-80"
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
                  <FilePlus size={16} />
                  Create Golden Baseline
                </button>
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === "history" && (
          <div className="flex flex-col gap-4">
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.08em",
              }}
            >
              Verification History ({historyData?.length ?? 0})
            </p>

            {historyData && historyData.length > 0 ? (
              <div className="flex flex-col gap-3">
                {historyData.map((result) => (
                  <VerificationCard key={result.id} result={result as any} />
                ))}
              </div>
            ) : (
              <div
                className="rounded-lg border p-8 flex flex-col items-center justify-center text-center"
                style={{
                  backgroundColor: "var(--card)",
                  borderColor: "var(--border)",
                }}
              >
                <Clock
                  size={32}
                  style={{ color: "var(--muted-foreground)", marginBottom: "12px" }}
                />
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    color: "var(--muted-foreground)",
                  }}
                >
                  No verification history yet
                </p>
              </div>
            )}
          </div>
        )}
        </div>
      </div>

      {/* Create Baseline Dialog */}
      <ConfirmDialog
        open={showCreateBaselineDialog}
        title="Create Golden Baseline?"
        description="This will capture the current PCR measurements as the known-good state. Future verifications will compare against this baseline. The baseline will be signed by the active DKP key."
        confirmLabel="Create Baseline"
        onConfirm={handleCreateBaseline}
        onCancel={() => setShowCreateBaselineDialog(false)}
      />

      {/* CSS for spin animation */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
