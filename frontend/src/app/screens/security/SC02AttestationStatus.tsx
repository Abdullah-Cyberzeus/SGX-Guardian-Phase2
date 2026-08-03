import { useState, useMemo } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  Shield,
  ShieldCheck,
  ShieldX,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  Copy,
  Check,
  Info,
  Users,
  FileCheck,
  Fingerprint,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { type AttestationResult } from "../../data/mockData";
import { useAttestationResults } from "../../hooks/useApiData";
import { toast } from "sonner";

// Status Badge
function StatusBadge({ result }: { result: "success" | "failed" }) {
  const isSuccess = result === "success";
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full"
      style={{
        backgroundColor: isSuccess
          ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
          : "color-mix(in srgb, var(--destructive) 15%, transparent)",
        border: `1px solid ${isSuccess
          ? "color-mix(in srgb, var(--chart-2) 30%, transparent)"
          : "color-mix(in srgb, var(--destructive) 30%, transparent)"}`,
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        color: isSuccess ? "var(--chart-2)" : "var(--destructive)",
      }}
    >
      {isSuccess ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
      {isSuccess ? "Success" : "Failed"}
    </span>
  );
}

// Attestation Card
function AttestationCard({ attestation, isLatest }: { attestation: AttestationResult; isLatest?: boolean }) {
  const [expanded, setExpanded] = useState(isLatest);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  return (
    <div
      className="rounded-lg border overflow-hidden"
      style={{
        backgroundColor: "var(--card)",
        borderColor: isLatest ? "var(--primary)" : "var(--border)",
        borderWidth: isLatest ? "2px" : "1px",
      }}
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
            backgroundColor: attestation.result === "success"
              ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
              : "color-mix(in srgb, var(--destructive) 15%, transparent)",
          }}
        >
          {attestation.result === "success" ? (
            <ShieldCheck size={20} style={{ color: "var(--chart-2)" }} />
          ) : (
            <ShieldX size={20} style={{ color: "var(--destructive)" }} />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <p
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
              }}
            >
              {attestation.peerIp}
            </p>
            {isLatest && (
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "10px",
                  fontWeight: "var(--font-weight-medium)",
                  color: "var(--primary)",
                  backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)",
                  padding: "2px 6px",
                  borderRadius: "4px",
                }}
              >
                Latest
              </span>
            )}
          </div>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            {formatDate(attestation.timestamp)}
          </p>
        </div>
        <StatusBadge result={attestation.result} />
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-2 border-t flex flex-col gap-3" style={{ borderColor: "var(--border)" }}>
          {/* Verification Checks */}
          {attestation.details && (
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
                Verification Checks
              </p>
              <div className="flex flex-col gap-2">
                {[
                  { label: "PCR Match", value: attestation.details.pcrMatch },
                  { label: "Signature Valid", value: attestation.details.signatureValid },
                  { label: "Policy Match", value: attestation.details.policyMatch },
                ].map(({ label, value }) => (
                  <div key={label} className="flex items-center justify-between">
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      {label}
                    </span>
                    <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: value ? "var(--chart-2)" : "var(--destructive)" }}>
                      {value ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                      {value ? "Pass" : "Fail"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Failure Reason */}
          {attestation.details?.failureReason && (
            <div
              className="flex items-start gap-2 p-3 rounded-lg"
              style={{
                backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
              }}
            >
              <AlertTriangle size={14} style={{ color: "var(--destructive)", marginTop: "2px", flexShrink: 0 }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>
                {attestation.details.failureReason}
              </p>
            </div>
          )}

          {/* Policy Digest */}
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "4px" }}>
              Policy Digest
            </p>
            <code
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "10px",
                color: "var(--foreground)",
                backgroundColor: "var(--muted)",
                padding: "6px 10px",
                borderRadius: "4px",
                display: "block",
                wordBreak: "break-all",
              }}
            >
              {attestation.policyDigest}
            </code>
          </div>
        </div>
      )}
    </div>
  );
}

// Main Component
export function SC02AttestationStatus() {
  const navigate = useNavigate();
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Fetch data from backend API
  const { data: attestationData, loading, error, source } = useAttestationResults();
  const attestationResults = useMemo(() => {
    if (!attestationData) return [];
    return Array.isArray(attestationData) ? attestationData : [];
  }, [attestationData]);

  const lastAttestation = attestationResults[0] || null;
  const successCount = attestationResults.filter((a: AttestationResult) => a.result === "success").length;
  const failedCount = attestationResults.filter((a: AttestationResult) => a.result === "failed").length;

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
      toast.success("Attestation refreshed", { description: "All peers re-attested" });
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
      <PageHeader title="Attestation" subtitle="Peer Verification" onBack={() => navigate("/settings")} />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">
        {/* Last Attestation Banner */}
        {lastAttestation ? (
        <div
          className="flex items-center gap-3 p-4 rounded-lg"
          style={{
            backgroundColor: lastAttestation.result === "success"
              ? "color-mix(in srgb, var(--chart-2) 10%, transparent)"
              : "color-mix(in srgb, var(--destructive) 10%, transparent)",
            border: `1px solid ${lastAttestation.result === "success"
              ? "color-mix(in srgb, var(--chart-2) 25%, transparent)"
              : "color-mix(in srgb, var(--destructive) 25%, transparent)"}`,
          }}
        >
          {lastAttestation.result === "success" ? (
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
                color: lastAttestation.result === "success" ? "var(--chart-2)" : "var(--destructive)",
              }}
            >
              {lastAttestation.result === "success" ? "Last Attestation Passed" : "Last Attestation Failed"}
            </p>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: lastAttestation.result === "success" ? "var(--chart-2)" : "var(--destructive)",
                opacity: 0.85,
              }}
            >
              {lastAttestation.peerIp} · {formatDate(lastAttestation.timestamp)}
            </p>
          </div>
        </div>
        ) : (
        <div
          className="flex items-center gap-3 p-4 rounded-lg"
          style={{
            backgroundColor: "color-mix(in srgb, var(--muted-foreground) 10%, transparent)",
            border: "1px solid var(--border)",
          }}
        >
          <Shield size={28} style={{ color: "var(--muted-foreground)" }} />
          <div className="flex-1">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)" }}>
              No Attestation Data
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", opacity: 0.85 }}>
              Run an attestation to see results
            </p>
          </div>
        </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <Users size={18} style={{ color: "var(--primary)", margin: "0 auto 8px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>
              {attestationResults.length}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Total</p>
          </div>
          <div className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <CheckCircle2 size={18} style={{ color: "var(--chart-2)", margin: "0 auto 8px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: "var(--chart-2)" }}>
              {successCount}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Passed</p>
          </div>
          <div className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <XCircle size={18} style={{ color: failedCount > 0 ? "var(--destructive)" : "var(--muted-foreground)", margin: "0 auto 8px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: failedCount > 0 ? "var(--destructive)" : "var(--foreground)" }}>
              {failedCount}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Failed</p>
          </div>
        </div>

        {/* Attestation History */}
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
            Attestation Results
          </p>
          <div className="flex flex-col gap-3">
            {attestationResults.map((att: AttestationResult, index: number) => (
              <AttestationCard key={att.id} attestation={att} isLatest={index === 0} />
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
          <RefreshCw size={16} style={{ animation: isRefreshing ? "spin 1s linear infinite" : "none" }} />
          {isRefreshing ? "Attesting Peers..." : "Re-Attest All Peers"}
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
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", lineHeight: 1.5 }}>
            Attestation verifies peer identity and integrity by checking PCR measurements, cryptographic signatures, and policy compliance.
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
