import { useState, useMemo, useEffect } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { useDaemonRestart } from "../../contexts/DaemonRestartContext";
import {
  Key,
  Shield,
  RotateCcw,
  AlertTriangle,
  Check,
  X,
  ChevronRight,
  Clock,
  Cpu,
  Ban,
  Zap,
  Info,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
} from "lucide-react";
import {
  mockDKPKeys,
  mockDKPMetadata,
  type DKPKeyVersion,
  type DKPKeyStatus,
} from "../../data/mockData";
import { useDKPStatus } from "../../hooks/useApiData";
import { dkpService } from "../../services/dkpService";
import { toast } from "sonner";

type TabId = "status" | "history" | "revoke" | "emergency";

// Status badge component
function StatusBadge({ status }: { status: DKPKeyStatus }) {
  const config: Record<string, { bg: string; border: string; color: string; label: string; icon: typeof CheckCircle2 }> = {
    active: {
      bg: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
      border: "color-mix(in srgb, var(--chart-2) 30%, transparent)",
      color: "var(--chart-2)",
      label: "Active",
      icon: CheckCircle2,
    },
    deprecated: {
      bg: "color-mix(in srgb, var(--chart-5) 15%, transparent)",
      border: "color-mix(in srgb, var(--chart-5) 30%, transparent)",
      color: "var(--chart-5)",
      label: "Deprecated",
      icon: AlertCircle,
    },
    revoked: {
      bg: "color-mix(in srgb, var(--destructive) 15%, transparent)",
      border: "color-mix(in srgb, var(--destructive) 30%, transparent)",
      color: "var(--destructive)",
      label: "Revoked",
      icon: XCircle,
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

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full"
      style={{
        backgroundColor: bg,
        border: `1px solid ${border}`,
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        color,
      }}
    >
      <Icon size={12} />
      {label}
    </span>
  );
}

// Key Version Card
function KeyVersionCard({
  keyVersion,
  isSelected,
  onClick,
}: {
  keyVersion: DKPKeyVersion;
  isSelected: boolean;
  onClick: () => void;
}) {
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
    <button
      onClick={onClick}
      className="w-full text-left rounded-lg border transition-all"
      style={{
        backgroundColor: isSelected
          ? "color-mix(in srgb, var(--primary) 8%, transparent)"
          : "var(--card)",
        borderColor: isSelected ? "var(--primary)" : "var(--border)",
        padding: "16px",
        cursor: "pointer",
      }}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <div
            className="flex items-center justify-center rounded-lg"
            style={{
              width: "36px",
              height: "36px",
              backgroundColor:
                keyVersion.status === "active"
                  ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
                  : "var(--muted)",
            }}
          >
            <Key
              size={18}
              style={{
                color:
                  keyVersion.status === "active"
                    ? "var(--chart-2)"
                    : "var(--muted-foreground)",
              }}
            />
          </div>
          <div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
              }}
            >
              Version {keyVersion.version}
            </p>
            <p
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "11px",
                color: "var(--muted-foreground)",
              }}
            >
              {keyVersion.keyId}
            </p>
          </div>
        </div>
        <StatusBadge status={keyVersion.status} />
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5">
          <Cpu size={12} style={{ color: "var(--muted-foreground)" }} />
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            {keyVersion.algorithm}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <Clock size={12} style={{ color: "var(--muted-foreground)" }} />
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            {formatDate(keyVersion.created)}
          </span>
        </div>
      </div>

      {keyVersion.revokeReason && (
        <div
          className="mt-3 pt-3 border-t"
          style={{ borderColor: "var(--border)" }}
        >
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--destructive)",
            }}
          >
            Revoked: {keyVersion.revokeReason}
          </p>
        </div>
      )}
    </button>
  );
}

// Key Detail Panel
function KeyDetailPanel({
  keyVersion,
  onClose,
  onRotate,
  onRevoke,
}: {
  keyVersion: DKPKeyVersion;
  onClose: () => void;
  onRotate: () => void;
  onRevoke: () => void;
}) {
  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString("en-US", {
      month: "long",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const details = [
    { label: "Key ID", value: keyVersion.keyId },
    { label: "Algorithm", value: keyVersion.algorithm },
    { label: "Created", value: formatDate(keyVersion.created) },
    ...(keyVersion.rotatedFrom
      ? [{ label: "Rotated From", value: keyVersion.rotatedFrom }]
      : []),
    ...(keyVersion.revokedAt
      ? [{ label: "Revoked At", value: formatDate(keyVersion.revokedAt) }]
      : []),
    ...(keyVersion.revokeReason
      ? [{ label: "Revoke Reason", value: keyVersion.revokeReason }]
      : []),
  ];

  return (
    <div
      className="flex flex-col h-full overflow-hidden rounded-lg border"
      style={{
        backgroundColor: "var(--card)",
        borderColor: "var(--border)",
      }}
    >
      {/* Header */}
      <div
        className="flex items-start justify-between px-5 pt-5 pb-4 border-b"
        style={{ borderColor: "var(--border)" }}
      >
        <div className="flex items-center gap-3">
          <div
            className="flex items-center justify-center rounded-lg"
            style={{
              width: "44px",
              height: "44px",
              backgroundColor:
                keyVersion.status === "active"
                  ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
                  : "var(--muted)",
            }}
          >
            <Key
              size={22}
              style={{
                color:
                  keyVersion.status === "active"
                    ? "var(--chart-2)"
                    : "var(--muted-foreground)",
              }}
            />
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
              DKP Version {keyVersion.version}
            </p>
            <StatusBadge status={keyVersion.status} />
          </div>
        </div>
        <button
          onClick={onClose}
          style={{
            background: "none",
            border: "none",
            cursor: "pointer",
            padding: "8px",
          }}
        >
          <X size={18} style={{ color: "var(--muted-foreground)" }} />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">
        {/* Details */}
        <div>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--muted-foreground)",
              letterSpacing: "0.08em",
              marginBottom: "10px",
            }}
          >
            Key Details
          </p>
          <div
            className="rounded-lg border overflow-hidden"
            style={{
              backgroundColor: "var(--background)",
              borderColor: "var(--border)",
            }}
          >
            {details.map(({ label, value }, i) => (
              <div
                key={label}
                className="flex items-center justify-between px-4 py-3"
                style={{
                  borderBottom:
                    i < details.length - 1
                      ? "1px solid var(--border)"
                      : undefined,
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
                    fontFamily:
                      label === "Key ID" || label === "Rotated From"
                        ? "JetBrains Mono, monospace"
                        : "Inter, sans-serif",
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
        </div>

        {/* SE050 Hardware Info */}
        {keyVersion.status === "active" && (
          <div
            className="flex items-center gap-3 p-4 rounded-lg"
            style={{
              backgroundColor: "color-mix(in srgb, var(--chart-2) 10%, transparent)",
              border: "1px solid color-mix(in srgb, var(--chart-2) 25%, transparent)",
            }}
          >
            <Shield size={20} style={{ color: "var(--chart-2)" }} />
            <div>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                  color: "var(--chart-2)",
                }}
              >
                Hardware Protected
              </p>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--chart-2)",
                  opacity: 0.85,
                }}
              >
                Private key stored in SE050 secure element
              </p>
            </div>
          </div>
        )}

        {/* Actions */}
        {keyVersion.status === "active" && (
          <div className="flex flex-col gap-2 pt-2">
            <button
              onClick={onRotate}
              className="flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
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
              <RotateCcw size={16} />
              Rotate to New Version
            </button>
          </div>
        )}

        {keyVersion.status === "deprecated" && (
          <div className="flex flex-col gap-2 pt-2">
            <button
              onClick={onRevoke}
              className="flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
              style={{
                backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)",
                color: "var(--destructive)",
                border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
                cursor: "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
              }}
            >
              <Ban size={16} />
              Revoke This Key
            </button>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
                textAlign: "center",
              }}
            >
              30-day grace period for signature verification
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// Emergency Rotation Card
function EmergencyRotationCard({
  log,
}: {
  log: import("../../data/mockData").EmergencyRotationLog;
}) {
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
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <div
            className="flex items-center justify-center rounded-lg"
            style={{
              width: "36px",
              height: "36px",
              backgroundColor: "color-mix(in srgb, var(--chart-5) 15%, transparent)",
            }}
          >
            <Zap size={18} style={{ color: "var(--chart-5)" }} />
          </div>
          <div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
              }}
            >
              Emergency Rotation
            </p>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
              }}
            >
              {formatDate(log.timestamp)}
            </p>
          </div>
        </div>
        <span
          className="px-2.5 py-1 rounded-full"
          style={{
            backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
            border: "1px solid color-mix(in srgb, var(--chart-2) 30%, transparent)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            fontWeight: "var(--font-weight-medium)",
            color: "var(--chart-2)",
          }}
        >
          {log.keysRotated}/{log.keysRotated + log.keysFailed} Success
        </span>
      </div>

      <div className="flex flex-col gap-2 mb-3">
        {Object.entries(log.details).map(([key, status]) => (
          <div key={key} className="flex items-center justify-between">
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
                textTransform: "capitalize",
              }}
            >
              {key.replace(/([A-Z])/g, " $1").trim()}
            </span>
            <span
              className="flex items-center gap-1"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-medium)",
                color: status === "success" ? "var(--chart-2)" : "var(--destructive)",
              }}
            >
              {status === "success" ? <Check size={12} /> : <X size={12} />}
              {status}
            </span>
          </div>
        ))}
      </div>

      {log.reason && (
        <div
          className="pt-3 border-t"
          style={{ borderColor: "var(--border)" }}
        >
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            <span style={{ fontWeight: "var(--font-weight-medium)" }}>Reason:</span>{" "}
            {log.reason}
          </p>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
              marginTop: "4px",
            }}
          >
            <span style={{ fontWeight: "var(--font-weight-medium)" }}>By:</span>{" "}
            {log.triggeredBy}
          </p>
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
  confirmVariant = "primary",
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  confirmVariant?: "primary" | "destructive";
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
              backgroundColor:
                confirmVariant === "destructive"
                  ? "color-mix(in srgb, var(--destructive) 15%, transparent)"
                  : "color-mix(in srgb, var(--primary) 15%, transparent)",
            }}
          >
            <AlertTriangle
              size={22}
              style={{
                color:
                  confirmVariant === "destructive"
                    ? "var(--destructive)"
                    : "var(--primary)",
              }}
            />
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
              backgroundColor:
                confirmVariant === "destructive"
                  ? "var(--destructive)"
                  : "var(--primary)",
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
export function KM01KeyManagement() {
  const navigate = useNavigate();
  const { triggerRestart } = useDaemonRestart();
  const [activeTab, setActiveTab] = useState<TabId>("status");
  const [selectedKey, setSelectedKey] = useState<DKPKeyVersion | null>(null);
  const [showRotateDialog, setShowRotateDialog] = useState(false);
  const [showRevokeDialog, setShowRevokeDialog] = useState(false);
  const [showEmergencyDialog, setShowEmergencyDialog] = useState(false);
  const [emergencyRotationHistory, setEmergencyRotationHistory] = useState<import("../../data/mockData").EmergencyRotationLog[]>([]);
  const [revokeTargetKey, setRevokeTargetKey] = useState<DKPKeyVersion | null>(null);
  const [revokeReason, setRevokeReason] = useState("");
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);

  // Fetch data from backend API
  const { data: dkpData, loading, error, refetch } = useDKPStatus();
  const initialKeys = useMemo(() => {
    const dataWithKeys = dkpData as { keys?: DKPKeyVersion[] } | null;
    if (!dataWithKeys || !dataWithKeys.keys) return [];
    return dataWithKeys.keys;
  }, [dkpData]);
  const [dkpKeys, setDkpKeys] = useState<DKPKeyVersion[]>(initialKeys);

  // Sync state when API data arrives
  useEffect(() => {
    if (initialKeys.length > 0) {
      setDkpKeys(initialKeys);
    }
  }, [initialKeys]);

  // Get metadata from API
  const dkpMetadata = useMemo(() => {
    const defaults = { se050Available: false, totalVersions: 0, activeVersion: null };
    if (!dkpData) return defaults;
    return { ...defaults, ...dkpData };
  }, [dkpData]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center" style={{ minHeight: "100dvh" }}>
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
      </div>
    );
  }

  const tabs: { id: TabId; label: string; icon: typeof Key }[] = [
    { id: "status", label: "DKP Status", icon: Key },
    { id: "history", label: "History", icon: Clock },
    { id: "revoke", label: "Revoke", icon: Ban },
    { id: "emergency", label: "Emergency", icon: AlertTriangle },
  ];

  const activeKey = dkpKeys.find((k) => k.status === "active");

  const handleRotate = async () => {
    if (!activeKey) return;
    try {
      const res = await dkpService.rotate();
      console.log("[DKP Rotate] POST /dkp/rotate →", res);
      setShowRotateDialog(false);
      toast.success(res.message || "DKP key rotated successfully");
      triggerRestart(`DKP key rotated. Guardian daemon restart required to apply new keys.`);
      await refetch();
    } catch (err) {
      toast.error("Rotation failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  const handleRevoke = async () => {
    if (!selectedKey || selectedKey.status !== "deprecated") return;
    try {
      const res = await dkpService.revoke(selectedKey.version, "Admin revocation");
      console.log("[DKP Revoke] POST /dkp/revoke →", res);
      setShowRevokeDialog(false);
      toast.success(res.message || `Key v${selectedKey.version} revoked`, {
        description: "30-day grace period for signature verification",
      });
      await refetch();
    } catch (err) {
      toast.error("Revoke failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  const handleRevokeFromTab = async () => {
    if (!revokeTargetKey || revokeTargetKey.status !== "deprecated") return;
    const reason = revokeReason.trim() || "Admin revocation";
    try {
      const res = await dkpService.revoke(revokeTargetKey.version, reason);
      console.log("[DKP Revoke Tab] POST /dkp/revoke →", res);
      setShowRevokeConfirm(false);
      setRevokeTargetKey(null);
      setRevokeReason("");
      toast.success(res.message || `Key v${revokeTargetKey.version} revoked`, {
        description: `Reason: ${reason}. 30-day grace period for signature verification.`,
      });
      await refetch();
    } catch (err) {
      toast.error("Revoke failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  const handleEmergencyRotate = async () => {
    try {
      const res = await dkpService.emergencyRotate("Emergency key compromise");
      console.log("[DKP Emergency Rotate] POST /dkp/emergency-rotate →", res);
      setShowEmergencyDialog(false);
      setEmergencyRotationHistory((prev) => [
        {
          id: res.newKeyId || `emr_${Date.now()}`,
          timestamp: res.rotatedAt || new Date().toISOString(),
          mode: "software" as const,
          keysRotated: res.requiresReAttestation ? 3 : 1,
          keysFailed: res.success ? 0 : 1,
          details: { dkp: res.success ? "success" : "failed", softwareKey: res.success ? "success" : "failed", tlsCertificate: res.success ? "success" : "failed" },
          triggeredBy: "Admin",
          reason: res.reason,
        },
        ...prev,
      ]);
      toast.success(res.message || "Emergency rotation complete");
      triggerRestart("Emergency rotation completed. Guardian daemon restart required immediately.");
      await refetch();
    } catch (err) {
      toast.error("Emergency rotation failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  return (
    <div className="flex flex-col" style={{ minHeight: "100dvh" }}>
      <PageHeader title="Key Management" subtitle="DKP & Security Keys" onBack={() => navigate("/settings")} />

      {/* Hardware Mode Banner */}
      {dkpMetadata.se050Available && (
        <div
          className="mx-4 mt-4 flex items-center gap-3 p-3 rounded-lg"
          style={{
            backgroundColor: "color-mix(in srgb, var(--chart-2) 10%, transparent)",
            border: "1px solid color-mix(in srgb, var(--chart-2) 25%, transparent)",
          }}
        >
          <Shield size={18} style={{ color: "var(--chart-2)" }} />
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--chart-2)",
              fontWeight: "var(--font-weight-medium)",
            }}
          >
            Hardware Mode: SE050 Secure Element detected
          </p>
        </div>
      )}

      {/* Tab Switcher */}
      <div className="px-4 pt-4">
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
      <div className="flex-1 overflow-y-auto p-4">
        {/* DKP Status Tab */}
        {activeTab === "status" && (
          <div className="flex flex-col gap-4">
            {/* Active Key Summary */}
            {activeKey && (
              <div
                className="rounded-lg border p-4"
                style={{
                  backgroundColor: "var(--card)",
                  borderColor: "var(--border)",
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      fontWeight: "var(--font-weight-semibold)",
                      color: "var(--muted-foreground)",
                      letterSpacing: "0.08em",
                    }}
                  >
                    Active Key
                  </p>
                  <StatusBadge status="active" />
                </div>

                <div className="flex items-center gap-3 mb-4">
                  <div
                    className="flex items-center justify-center rounded-lg"
                    style={{
                      width: "48px",
                      height: "48px",
                      backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
                    }}
                  >
                    <Key size={24} style={{ color: "var(--chart-2)" }} />
                  </div>
                  <div>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-lg)",
                        fontWeight: "var(--font-weight-bold)",
                        color: "var(--foreground)",
                      }}
                    >
                      Version {activeKey.version}
                    </p>
                    <p
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: "var(--text-xs)",
                        color: "var(--muted-foreground)",
                      }}
                    >
                      {activeKey.keyId}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
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
                      Algorithm
                    </p>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-sm)",
                        fontWeight: "var(--font-weight-semibold)",
                        color: "var(--foreground)",
                      }}
                    >
                      {activeKey.algorithm}
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
                      Total Versions
                    </p>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-sm)",
                        fontWeight: "var(--font-weight-semibold)",
                        color: "var(--foreground)",
                      }}
                    >
                      {dkpKeys.length}
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => setShowRotateDialog(true)}
                  className="w-full flex items-center justify-center gap-2 mt-4 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
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
                  <RotateCcw size={16} />
                  Rotate Key
                </button>
              </div>
            )}

            {/* Info Banner */}
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
                DKP (Device Key Pair) is generated inside the SE050 secure element. The private key never leaves the chip.
              </p>
            </div>
          </div>
        )}

        {/* History Tab */}
        {activeTab === "history" && (
          <div className="flex flex-col lg:flex-row gap-4">
            {/* Key List */}
            <div className="flex-1 flex flex-col gap-3">
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-semibold)",
                  color: "var(--muted-foreground)",
                  letterSpacing: "0.08em",
                }}
              >
                All Key Versions ({dkpKeys.length})
              </p>
              {dkpKeys.map((key) => (
                <KeyVersionCard
                  key={key.version}
                  keyVersion={key}
                  isSelected={selectedKey?.version === key.version}
                  onClick={() => setSelectedKey(key)}
                />
              ))}
            </div>

            {/* Detail Panel (Desktop) */}
            {selectedKey && (
              <div className="hidden lg:block" style={{ width: "360px" }}>
                <KeyDetailPanel
                  keyVersion={selectedKey}
                  onClose={() => setSelectedKey(null)}
                  onRotate={() => setShowRotateDialog(true)}
                  onRevoke={() => setShowRevokeDialog(true)}
                />
              </div>
            )}
          </div>
        )}

        {/* Revoke Tab */}
        {activeTab === "revoke" && (
          <div className="flex flex-col gap-4">
            {/* Warning banner */}
            <div
              className="flex items-start gap-3 p-4 rounded-lg"
              style={{
                backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
              }}
            >
              <AlertTriangle size={18} style={{ color: "var(--destructive)", flexShrink: 0, marginTop: "2px" }} />
              <div>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-semibold)",
                    color: "var(--destructive)",
                    marginBottom: "4px",
                  }}
                >
                  Revocation is permanent
                </p>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    color: "var(--destructive)",
                    opacity: 0.85,
                    lineHeight: 1.5,
                  }}
                >
                  Only deprecated keys can be revoked. Active keys must be rotated first. A 30-day grace period is provided for old signature verification.
                </p>
              </div>
            </div>

            {/* Revocable keys list */}
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
                Select Key to Revoke
              </p>

              {dkpKeys.filter((k) => k.status === "deprecated").length === 0 ? (
                <div
                  className="rounded-lg border p-8 flex flex-col items-center justify-center"
                  style={{
                    backgroundColor: "var(--card)",
                    borderColor: "var(--border)",
                  }}
                >
                  <CheckCircle2
                    size={36}
                    style={{ color: "var(--chart-2)", marginBottom: "12px" }}
                  />
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      fontWeight: "var(--font-weight-semibold)",
                      color: "var(--foreground)",
                      marginBottom: "4px",
                    }}
                  >
                    No keys available for revocation
                  </p>
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                      textAlign: "center",
                      maxWidth: "260px",
                      lineHeight: 1.5,
                    }}
                  >
                    All deprecated keys have already been revoked, or the only key is currently active.
                  </p>
                </div>
              ) : (
                <div className="flex flex-col gap-3">
                  {dkpKeys
                    .filter((k) => k.status === "deprecated")
                    .map((key) => (
                      <button
                        key={key.version}
                        onClick={() => setRevokeTargetKey(revokeTargetKey?.version === key.version ? null : key)}
                        className="w-full text-left rounded-lg border transition-all"
                        style={{
                          backgroundColor:
                            revokeTargetKey?.version === key.version
                              ? "color-mix(in srgb, var(--destructive) 8%, transparent)"
                              : "var(--card)",
                          borderColor:
                            revokeTargetKey?.version === key.version
                              ? "var(--destructive)"
                              : "var(--border)",
                          padding: "16px",
                          cursor: "pointer",
                        }}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            {/* Radio-style selector */}
                            <div
                              className="flex items-center justify-center rounded-full flex-shrink-0"
                              style={{
                                width: "20px",
                                height: "20px",
                                border: `2px solid ${
                                  revokeTargetKey?.version === key.version
                                    ? "var(--destructive)"
                                    : "var(--muted-foreground)"
                                }`,
                              }}
                            >
                              {revokeTargetKey?.version === key.version && (
                                <div
                                  className="rounded-full"
                                  style={{
                                    width: "10px",
                                    height: "10px",
                                    backgroundColor: "var(--destructive)",
                                  }}
                                />
                              )}
                            </div>

                            <div className="flex items-center gap-2">
                              <Key
                                size={18}
                                style={{ color: "var(--muted-foreground)" }}
                              />
                              <div>
                                <p
                                  style={{
                                    fontFamily: "Inter, sans-serif",
                                    fontSize: "var(--text-sm)",
                                    fontWeight: "var(--font-weight-semibold)",
                                    color: "var(--foreground)",
                                  }}
                                >
                                  Version {key.version}
                                </p>
                                <p
                                  style={{
                                    fontFamily: "JetBrains Mono, monospace",
                                    fontSize: "11px",
                                    color: "var(--muted-foreground)",
                                  }}
                                >
                                  {key.keyId}
                                </p>
                              </div>
                            </div>
                          </div>
                          <StatusBadge status={key.status} />
                        </div>

                        <div className="flex items-center gap-4 mt-3 ml-8">
                          <div className="flex items-center gap-1.5">
                            <Cpu size={12} style={{ color: "var(--muted-foreground)" }} />
                            <span
                              style={{
                                fontFamily: "Inter, sans-serif",
                                fontSize: "var(--text-xs)",
                                color: "var(--muted-foreground)",
                              }}
                            >
                              {key.algorithm}
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <Clock size={12} style={{ color: "var(--muted-foreground)" }} />
                            <span
                              style={{
                                fontFamily: "Inter, sans-serif",
                                fontSize: "var(--text-xs)",
                                color: "var(--muted-foreground)",
                              }}
                            >
                              {new Date(key.created).toLocaleDateString("en-US", {
                                month: "short",
                                day: "numeric",
                                year: "numeric",
                              })}
                            </span>
                          </div>
                        </div>
                      </button>
                    ))}
                </div>
              )}
            </div>

            {/* Reason input + Revoke button (shown when a key is selected) */}
            {revokeTargetKey && (
              <div className="flex flex-col gap-3">
                <div>
                  <label
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      fontWeight: "var(--font-weight-semibold)",
                      color: "var(--muted-foreground)",
                      letterSpacing: "0.08em",
                      display: "block",
                      marginBottom: "8px",
                    }}
                  >
                    Revocation Reason
                  </label>
                  <input
                    type="text"
                    value={revokeReason}
                    onChange={(e) => setRevokeReason(e.target.value)}
                    placeholder="e.g., compromised key, policy change..."
                    style={{
                      width: "100%",
                      height: "44px",
                      padding: "0 14px",
                      borderRadius: "var(--radius)",
                      backgroundColor: "var(--card)",
                      border: "1px solid var(--border)",
                      color: "var(--foreground)",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      outline: "none",
                    }}
                  />
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                      marginTop: "6px",
                    }}
                  >
                    Default: "Admin revocation" if left blank
                  </p>
                </div>

                {/* Selected key summary */}
                <div
                  className="flex items-center gap-3 p-4 rounded-lg"
                  style={{
                    backgroundColor: "var(--muted)",
                  }}
                >
                  <Ban size={18} style={{ color: "var(--destructive)" }} />
                  <div className="flex-1">
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-sm)",
                        fontWeight: "var(--font-weight-medium)",
                        color: "var(--foreground)",
                      }}
                    >
                      Revoking Version {revokeTargetKey.version} ({revokeTargetKey.keyId})
                    </p>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-xs)",
                        color: "var(--muted-foreground)",
                      }}
                    >
                      This action is irreversible
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => setShowRevokeConfirm(true)}
                  className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
                  style={{
                    backgroundColor: "var(--destructive)",
                    color: "white",
                    border: "none",
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-semibold)",
                  }}
                >
                  <Ban size={16} />
                  Revoke Key v{revokeTargetKey.version}
                </button>
              </div>
            )}

            {/* Already revoked keys */}
            {dkpKeys.filter((k) => k.status === "revoked").length > 0 && (
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
                  Revoked Keys
                </p>
                <div className="flex flex-col gap-3">
                  {dkpKeys
                    .filter((k) => k.status === "revoked")
                    .map((key) => (
                      <div
                        key={key.version}
                        className="rounded-lg border p-4"
                        style={{
                          backgroundColor: "var(--card)",
                          borderColor: "var(--border)",
                          opacity: 0.7,
                        }}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Key size={16} style={{ color: "var(--muted-foreground)" }} />
                            <p
                              style={{
                                fontFamily: "Inter, sans-serif",
                                fontSize: "var(--text-sm)",
                                fontWeight: "var(--font-weight-semibold)",
                                color: "var(--foreground)",
                              }}
                            >
                              Version {key.version}
                            </p>
                            <p
                              style={{
                                fontFamily: "JetBrains Mono, monospace",
                                fontSize: "11px",
                                color: "var(--muted-foreground)",
                              }}
                            >
                              {key.keyId}
                            </p>
                          </div>
                          <StatusBadge status="revoked" />
                        </div>
                        {key.revokeReason && (
                          <p
                            style={{
                              fontFamily: "Inter, sans-serif",
                              fontSize: "var(--text-xs)",
                              color: "var(--destructive)",
                            }}
                          >
                            Reason: {key.revokeReason}
                          </p>
                        )}
                        {key.revokedAt && (
                          <p
                            style={{
                              fontFamily: "Inter, sans-serif",
                              fontSize: "var(--text-xs)",
                              color: "var(--muted-foreground)",
                              marginTop: "2px",
                            }}
                          >
                            Revoked: {new Date(key.revokedAt).toLocaleDateString("en-US", {
                              month: "short",
                              day: "numeric",
                              year: "numeric",
                              hour: "2-digit",
                              minute: "2-digit",
                            })}
                          </p>
                        )}
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Emergency Tab */}
        {activeTab === "emergency" && (
          <div className="flex flex-col gap-4">
            {/* Emergency Rotate Card */}
            <div
              className="rounded-lg border p-5"
              style={{
                backgroundColor: "var(--card)",
                borderColor: "var(--border)",
              }}
            >
              <div className="flex items-center gap-3 mb-4">
                <div
                  className="flex items-center justify-center rounded-lg"
                  style={{
                    width: "48px",
                    height: "48px",
                    backgroundColor: "color-mix(in srgb, var(--destructive) 15%, transparent)",
                  }}
                >
                  <Zap size={24} style={{ color: "var(--destructive)" }} />
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
                    Emergency Key Rotation
                  </p>
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                    }}
                  >
                    Rotate ALL critical keys simultaneously
                  </p>
                </div>
              </div>

              <div
                className="p-4 rounded-lg mb-4"
                style={{ backgroundColor: "var(--muted)" }}
              >
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-semibold)",
                    color: "var(--foreground)",
                    marginBottom: "8px",
                  }}
                >
                  Keys that will be rotated:
                </p>
                <ul className="flex flex-col gap-1.5">
                  {(dkpKeys.length > 0
                    ? dkpKeys.filter(k => k.status === "active").map(k => `DKP v${k.version} (${k.algorithm || "ECDSA-P256"})`)
                    : ["DKP (Device Key Pair)", "TLS Certificate"]
                  ).map((item) => (
                      <li
                        key={item}
                        className="flex items-center gap-2"
                        style={{
                          fontFamily: "Inter, sans-serif",
                          fontSize: "var(--text-xs)",
                          color: "var(--muted-foreground)",
                        }}
                      >
                        <ChevronRight size={12} />
                        {item}
                      </li>
                    )
                  )}
                </ul>
              </div>

              <button
                onClick={() => setShowEmergencyDialog(true)}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
                style={{
                  backgroundColor: "var(--destructive)",
                  color: "white",
                  border: "none",
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                }}
              >
                <AlertTriangle size={16} />
                Initiate Emergency Rotation
              </button>
            </div>

            {/* Rotation History */}
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
                Rotation History
              </p>
              {emergencyRotationHistory.length > 0 ? (
                <div className="flex flex-col gap-3">
                  {emergencyRotationHistory.map((log) => (
                    <EmergencyRotationCard key={log.id} log={log} />
                  ))}
                </div>
              ) : (
                <div
                  className="rounded-lg border p-6 flex flex-col items-center justify-center"
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
                    No emergency rotations yet
                  </p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Mobile Detail Sheet */}
      {selectedKey && activeTab === "history" && (
        <div
          className="lg:hidden fixed inset-x-0 bottom-0 z-40"
          style={{
            maxHeight: "70vh",
            backgroundColor: "var(--card)",
            borderTopLeftRadius: "20px",
            borderTopRightRadius: "20px",
            boxShadow: "0 -4px 20px rgba(0,0,0,0.15)",
          }}
        >
          <div
            className="w-10 h-1 rounded-full mx-auto mt-3 mb-2"
            style={{ backgroundColor: "var(--border)" }}
          />
          <div style={{ maxHeight: "calc(70vh - 20px)", overflowY: "auto" }}>
            <KeyDetailPanel
              keyVersion={selectedKey}
              onClose={() => setSelectedKey(null)}
              onRotate={() => setShowRotateDialog(true)}
              onRevoke={() => setShowRevokeDialog(true)}
            />
          </div>
        </div>
      )}

      {/* Dialogs */}
      <ConfirmDialog
        open={showRotateDialog}
        title="Rotate DKP Key?"
        description="This will generate a new key version and deprecate the current active key. The daemon must be restarted to apply the new key."
        confirmLabel="Rotate Key"
        confirmVariant="primary"
        onConfirm={handleRotate}
        onCancel={() => setShowRotateDialog(false)}
      />

      <ConfirmDialog
        open={showRevokeDialog}
        title="Revoke Key?"
        description="This action is permanent. A 30-day grace period will be provided for old signature verification. This key cannot be used for signing after revocation."
        confirmLabel="Revoke Key"
        confirmVariant="destructive"
        onConfirm={handleRevoke}
        onCancel={() => setShowRevokeDialog(false)}
      />

      <ConfirmDialog
        open={showRevokeConfirm}
        title={`Revoke Key v${revokeTargetKey?.version}?`}
        description={`This will permanently revoke key ${revokeTargetKey?.keyId || ""}. Reason: "${revokeReason.trim() || "Admin revocation"}". A 30-day grace period will be provided for old signature verification. This action cannot be undone.`}
        confirmLabel="Revoke Permanently"
        confirmVariant="destructive"
        onConfirm={handleRevokeFromTab}
        onCancel={() => setShowRevokeConfirm(false)}
      />

      <ConfirmDialog
        open={showEmergencyDialog}
        title="Emergency Rotation"
        description="This will rotate ALL critical keys (DKP, Software Attestation Key, TLS Certificate) simultaneously. Use only in incident response when compromise is suspected. The daemon must be restarted."
        confirmLabel="Rotate All Keys"
        confirmVariant="destructive"
        onConfirm={handleEmergencyRotate}
        onCancel={() => setShowEmergencyDialog(false)}
      />
    </div>
  );
}
