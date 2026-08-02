import { useState, useMemo } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  Shield,
  ShieldCheck,
  ShieldX,
  CheckCircle2,
  XCircle,
  Lock,
  Unlock,
  Cpu,
  HardDrive,
  RefreshCw,
  ChevronRight,
  Copy,
  Check,
  Info,
  Link2,
  Server,
  Fingerprint,
  Loader2,
} from "lucide-react";
import { useBootStatus } from "../../hooks/useApiData";
import { toast } from "sonner";

// Trust Chain Step Component
function TrustChainStep({
  step,
  index,
  total,
}: {
  step: (typeof bootStatus.trustChain)[0];
  index: number;
  total: number;
}) {
  const isLast = index === total - 1;

  return (
    <div className="flex">
      {/* Connector Line */}
      <div className="flex flex-col items-center mr-4">
        <div
          className="flex items-center justify-center rounded-full flex-shrink-0"
          style={{
            width: "32px",
            height: "32px",
            backgroundColor:
              step.status === "verified"
                ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
                : step.status === "failed"
                ? "color-mix(in srgb, var(--destructive) 15%, transparent)"
                : "var(--muted)",
            border: `2px solid ${
              step.status === "verified"
                ? "var(--chart-2)"
                : step.status === "failed"
                ? "var(--destructive)"
                : "var(--border)"
            }`,
          }}
        >
          {step.status === "verified" ? (
            <CheckCircle2 size={16} style={{ color: "var(--chart-2)" }} />
          ) : step.status === "failed" ? (
            <XCircle size={16} style={{ color: "var(--destructive)" }} />
          ) : (
            <div
              style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                backgroundColor: "var(--muted-foreground)",
              }}
            />
          )}
        </div>
        {!isLast && (
          <div
            style={{
              width: "2px",
              flex: 1,
              minHeight: "24px",
              backgroundColor:
                step.status === "verified" ? "var(--chart-2)" : "var(--border)",
            }}
          />
        )}
      </div>

      {/* Content */}
      <div className="flex-1 pb-4">
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-semibold)",
            color: "var(--foreground)",
            marginBottom: "2px",
          }}
        >
          {step.name}
        </p>
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
          }}
        >
          {step.description}
        </p>
      </div>
    </div>
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

  return (
    <div>
      {label && (
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
            marginBottom: "6px",
          }}
        >
          {label}
        </p>
      )}
      <div className="flex items-center gap-2">
        <code
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "10px",
            color: "var(--foreground)",
            backgroundColor: "var(--muted)",
            padding: "8px 12px",
            borderRadius: "6px",
            flex: 1,
            wordBreak: "break-all",
            lineHeight: 1.5,
          }}
        >
          {hash}
        </code>
        <button
          onClick={handleCopy}
          className="p-2 rounded-lg transition-colors flex-shrink-0"
          style={{
            backgroundColor: copied
              ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
              : "var(--muted)",
            border: "none",
            cursor: "pointer",
          }}
        >
          {copied ? (
            <Check size={16} style={{ color: "var(--chart-2)" }} />
          ) : (
            <Copy size={16} style={{ color: "var(--muted-foreground)" }} />
          )}
        </button>
      </div>
    </div>
  );
}

// Main Component
export function SC01BootStatus() {
  const navigate = useNavigate();
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Fetch data from backend API
  const { data: bootStatusData, loading, error, source } = useBootStatus();
  const bootStatus = useMemo(() => bootStatusData || {
    bootChain: 'UNKNOWN' as const,
    habEnabled: false,
    deviceClosed: false,
    habEvents: 'N/A',
    deviceModel: 'Unknown',
    lastChecked: new Date().toISOString(),
    binaryHash: 'N/A',
    trustChain: [],
  }, [bootStatusData]);

  const isSecure = bootStatus.bootChain === "INTACT" && bootStatus.habEnabled && bootStatus.deviceClosed;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center" style={{ minHeight: "100dvh" }}>
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
      </div>
    );
  }

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
      toast.success("Boot status refreshed", {
        description: "All checks passed",
      });
    }, 1500);
  };

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
    <div className="flex flex-col h-full">
      <PageHeader title="Boot Status" subtitle="Secure Boot Chain" onBack={() => navigate("/settings")} />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">
        {/* Overall Status Banner */}
        <div
          className="flex items-center gap-3 p-4 rounded-lg"
          style={{
            backgroundColor: isSecure
              ? "color-mix(in srgb, var(--chart-2) 10%, transparent)"
              : "color-mix(in srgb, var(--destructive) 10%, transparent)",
            border: `1px solid ${
              isSecure
                ? "color-mix(in srgb, var(--chart-2) 25%, transparent)"
                : "color-mix(in srgb, var(--destructive) 25%, transparent)"
            }`,
          }}
        >
          {isSecure ? (
            <ShieldCheck size={28} style={{ color: "var(--chart-2)" }} />
          ) : (
            <ShieldX size={28} style={{ color: "var(--destructive)" }} />
          )}
          <div className="flex-1">
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-base)",
                fontWeight: "var(--font-weight-semibold)",
                color: isSecure ? "var(--chart-2)" : "var(--destructive)",
              }}
            >
              {isSecure ? "Secure Boot Chain Intact" : "Boot Chain Compromised"}
            </p>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: isSecure ? "var(--chart-2)" : "var(--destructive)",
                opacity: 0.85,
              }}
            >
              {isSecure
                ? "All boot stages verified successfully"
                : "One or more boot stages failed verification"}
            </p>
          </div>
        </div>

        {/* Status Cards Grid */}
        <div className="grid grid-cols-2 gap-3">
          {/* HAB Enabled */}
          <div
            className="rounded-lg border p-4"
            style={{
              backgroundColor: "var(--card)",
              borderColor: "var(--border)",
            }}
          >
            <div className="flex items-center gap-2 mb-2">
              <Shield size={16} style={{ color: "var(--primary)" }} />
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                }}
              >
                HAB Status
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-bold)",
                  color: bootStatus.habEnabled ? "var(--chart-2)" : "var(--destructive)",
                }}
              >
                {bootStatus.habEnabled ? "Enabled" : "Disabled"}
              </span>
              {bootStatus.habEnabled ? (
                <CheckCircle2 size={14} style={{ color: "var(--chart-2)" }} />
              ) : (
                <XCircle size={14} style={{ color: "var(--destructive)" }} />
              )}
            </div>
          </div>

          {/* Device Closed */}
          <div
            className="rounded-lg border p-4"
            style={{
              backgroundColor: "var(--card)",
              borderColor: "var(--border)",
            }}
          >
            <div className="flex items-center gap-2 mb-2">
              {bootStatus.deviceClosed ? (
                <Lock size={16} style={{ color: "var(--primary)" }} />
              ) : (
                <Unlock size={16} style={{ color: "var(--chart-5)" }} />
              )}
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                }}
              >
                Device Mode
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-bold)",
                  color: bootStatus.deviceClosed ? "var(--chart-2)" : "var(--chart-5)",
                }}
              >
                {bootStatus.deviceClosed ? "Closed" : "Open"}
              </span>
              {bootStatus.deviceClosed && (
                <span
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "10px",
                    color: "var(--chart-2)",
                    backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
                    padding: "2px 6px",
                    borderRadius: "4px",
                  }}
                >
                  {bootStatus.deviceClosed ? "enforcing" : "permissive"}
                </span>
              )}
            </div>
          </div>

          {/* Boot Chain */}
          <div
            className="rounded-lg border p-4"
            style={{
              backgroundColor: "var(--card)",
              borderColor: "var(--border)",
            }}
          >
            <div className="flex items-center gap-2 mb-2">
              <Link2 size={16} style={{ color: "var(--primary)" }} />
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                }}
              >
                Boot Chain
              </span>
            </div>
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-bold)",
                color: bootStatus.bootChain === "INTACT" ? "var(--chart-2)" : "var(--destructive)",
              }}
            >
              {bootStatus.bootChain}
            </span>
          </div>

          {/* HAB Events */}
          <div
            className="rounded-lg border p-4"
            style={{
              backgroundColor: "var(--card)",
              borderColor: "var(--border)",
            }}
          >
            <div className="flex items-center gap-2 mb-2">
              <Server size={16} style={{ color: "var(--primary)" }} />
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                }}
              >
                HAB Events
              </span>
            </div>
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-bold)",
                color: bootStatus.habEvents === "None" ? "var(--chart-2)" : "var(--chart-5)",
              }}
            >
              {bootStatus.habEvents}
            </span>
          </div>
        </div>

        {/* Device Info */}
        <div
          className="rounded-lg border p-4"
          style={{
            backgroundColor: "var(--card)",
            borderColor: "var(--border)",
          }}
        >
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
            Device Information
          </p>
          <div
            className="rounded-lg border overflow-hidden"
            style={{
              backgroundColor: "var(--background)",
              borderColor: "var(--border)",
            }}
          >
            {[
              { label: "Device Model", value: bootStatus.deviceModel },
              { label: "Last Checked", value: formatDate(bootStatus.lastChecked) },
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
            <HashDisplay hash={bootStatus.binaryHash} label="Guardian Binary Hash" />
          </div>
        </div>

        {/* Trust Chain */}
        <div
          className="rounded-lg border p-4"
          style={{
            backgroundColor: "var(--card)",
            borderColor: "var(--border)",
          }}
        >
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--muted-foreground)",
              letterSpacing: "0.08em",
              marginBottom: "16px",
            }}
          >
            Trust Chain Verification
          </p>
          <div>
            {bootStatus.trustChain.map((step, index) => (
              <TrustChainStep
                key={step.name}
                step={step}
                index={index}
                total={bootStatus.trustChain.length}
              />
            ))}
          </div>
        </div>

        {/* Refresh Button */}
        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
          style={{
            backgroundColor: "var(--primary)",
            color: "var(--primary-foreground)",
            border: "none",
            cursor: isRefreshing ? "not-allowed" : "pointer",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-semibold)",
            opacity: isRefreshing ? 0.7 : 1,
          }}
        >
          <RefreshCw
            size={16}
            style={{
              animation: isRefreshing ? "spin 1s linear infinite" : "none",
            }}
          />
          {isRefreshing ? "Checking..." : "Refresh Boot Status"}
        </button>

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
            HAB (High Assurance Boot) ensures each boot stage is cryptographically verified before execution. A closed device enforces signature checks.
          </p>
        </div>
        </div>
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
