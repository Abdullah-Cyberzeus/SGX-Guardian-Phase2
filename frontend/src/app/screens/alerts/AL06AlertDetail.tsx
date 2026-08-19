import { useState, useMemo } from "react";
import { useParams, useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { SeverityBadge } from "../../components/SeverityBadge";
import { Monitor, Cpu, Brain, ChevronRight, Archive, Ban, Scan, X, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { useAlerts } from "../../hooks/useApiData";

const remediation = [
  { icon: Archive, label: "Archive Event", description: "Mark as reviewed and move to archive", variant: "secondary" },
  { icon: Ban, label: "Block Device from Network", description: "Immediately revoke network access for affected device", variant: "warning" },
  { icon: Scan, label: "Run Security Scan", description: "Launch a full security scan on the affected device", variant: "default" },
  { icon: Monitor, label: "View Affected Device", description: "Navigate to full device details", variant: "ghost" },
];

export function AL06AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [sheetOpen, setSheetOpen] = useState(false);

  // Fetch alerts from API with fallback to mock data
  const { data: alertsData, loading } = useAlerts();

  const alerts = useMemo(() => {
    return alertsData?.alerts ?? [];
  }, [alertsData]);

  const alert = useMemo(() => {
    return alerts.find((a: any) => a.id === id);
  }, [alerts, id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center" style={{ minHeight: "100dvh" }}>
        <Loader2 className="w-8 h-8 animate-spin" style={{ color: "var(--primary)" }} />
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="flex flex-col items-center justify-center flex-1 p-6">
        <p style={{ fontFamily: "Inter, sans-serif", color: "var(--muted-foreground)" }}>Alert not found</p>
      </div>
    );
  }

  return (
    <>
      <div className="flex flex-col" style={{ minHeight: "100dvh" }}>
        {/* Severity-aware top accent bar (UX-02) */}
        {alert.severity === "HIGH" && (
          <div style={{ height: "4px", backgroundColor: "var(--destructive)", flexShrink: 0 }} />
        )}
        {alert.severity === "MEDIUM" && (
          <div style={{ height: "4px", backgroundColor: "var(--chart-5)", flexShrink: 0 }} />
        )}
        <PageHeader
          title={alert.severity + " Severity Alert"}
          right={
            <span style={{ animation: alert.severity === "HIGH" ? "severityPulse 1s ease-in-out 3" : undefined }}>
              <SeverityBadge severity={alert.severity} size="md" />
            </span>
          }
        />

        {/* HIGH severity tinted header section (UX-02) */}
        {alert.severity === "HIGH" && (
          <div style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 6%, var(--background))", borderBottom: "1px solid color-mix(in srgb, var(--destructive) 20%, transparent)", padding: "10px 16px" }}>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)", fontWeight: "var(--font-weight-semibold)", letterSpacing: "0.08em" }}>
              ⚠ Active threat — immediate action required
            </p>
          </div>
        )}

        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-2xl">
          <div className="p-4 flex flex-col gap-1">
            {/* Title */}
            <h2
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xl)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
                lineHeight: 1.3,
                marginBottom: "6px",
              }}
            >
              {alert.title}
            </h2>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                color: "var(--muted-foreground)",
                lineHeight: 1.6,
                marginBottom: "4px",
              }}
            >
              {alert.description}
            </p>
            <div className="flex items-center gap-3 mb-2">
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                {alert.eventType} · {alert.timestamp} · {alert.date}
              </span>
            </div>
          </div>

          <div className="h-px mx-4" style={{ backgroundColor: "var(--border)" }} />

          {/* Affected Device */}
          <div className="p-4">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
              Affected Device
            </p>
            <div
              className="rounded-lg border border-border p-4"
              style={{ backgroundColor: "var(--card)" }}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <Cpu size={14} style={{ color: "var(--muted-foreground)" }} />
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                      {alert.device}
                    </span>
                  </div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                    {alert.deviceIp}
                  </p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
                    {alert.os}
                  </p>
                </div>
              </div>
              <button
                className="flex items-center gap-1 mt-3 transition-opacity active:opacity-70"
                style={{ background: "none", border: "none", cursor: "pointer" }}
              >
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--primary)", fontWeight: "var(--font-weight-medium)" }}>
                  View Device
                </span>
                <ChevronRight size={14} style={{ color: "var(--primary)" }} />
              </button>
            </div>
          </div>

          <div className="h-px mx-4" style={{ backgroundColor: "var(--border)" }} />

          {/* AI Recommendation */}
          <div className="p-4">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
              AI Recommendation
            </p>
            <div
              className="rounded-lg border p-4"
              style={{
                backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))",
                borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)",
              }}
            >
              <div className="flex items-center gap-2 mb-3">
                <Brain size={14} style={{ color: "var(--primary)" }} />
                <span
                  style={{
                    fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-semibold)", color: "var(--primary)",
                    letterSpacing: "0.06em",
                  }}
                >
                  AI Analysis
                </span>
              </div>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  color: "var(--foreground)",
                  lineHeight: 1.65,
                  fontStyle: "italic",
                  marginBottom: "10px",
                }}
              >
                "{alert.aiSummary}"
              </p>
              <button
                onClick={() => navigate(`/alerts/${id}/ai`)}
                className="flex items-center gap-1 transition-opacity active:opacity-70"
                style={{ background: "none", border: "none", cursor: "pointer" }}
              >
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--primary)", fontWeight: "var(--font-weight-medium)" }}>
                  View Full Analysis
                </span>
                <ChevronRight size={14} style={{ color: "var(--primary)" }} />
              </button>
            </div>
          </div>

          {/* Take action button */}
          <div className="p-4 pb-8">
            <button
              onClick={() => setSheetOpen(true)}
              className="w-full flex items-center justify-center rounded-md transition-opacity active:opacity-80"
              style={{
                height: "52px",
                backgroundColor: "var(--primary)",
                color: "var(--primary-foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-base)",
                fontWeight: "var(--font-weight-semibold)",
                borderRadius: "var(--radius)",
                border: "none",
                cursor: "pointer",
              }}
            >
              Take Action
            </button>
          </div>
          </div>
        </div>
      </div>

      {/* AL-08 Remediation Actions Sheet */}
      {sheetOpen && (
        <div
          className="fixed inset-0 z-50 flex items-end md:items-center justify-center cursor-pointer"
          style={{ backgroundColor: "rgba(0,0,0,0.6)" }}
          onClick={() => setSheetOpen(false)}
        >
          <div
            className="w-full rounded-t-xl md:rounded-xl border-t md:border border-border cursor-default"
            style={{ backgroundColor: "var(--card)", maxWidth: "440px" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 pt-5 pb-4">
              <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Take Action
              </h3>
              <button onClick={() => setSheetOpen(false)} style={{ background: "none", border: "none", cursor: "pointer" }}>
                <X size={20} style={{ color: "var(--muted-foreground)" }} />
              </button>
            </div>
            <div className="flex flex-col gap-3 px-5 pb-8">
              {remediation.map(({ icon: Icon, label, description, variant }) => {
                const isWarning = variant === "warning";
                const isGhost = variant === "ghost";
                return (
                  <button
                    key={label}
                    className="w-full flex items-center gap-3 p-4 rounded-lg border transition-opacity active:opacity-70 text-left"
                    style={{
                      backgroundColor: isWarning
                        ? "color-mix(in srgb, var(--chart-5) 10%, var(--card))"
                        : isGhost ? "transparent" : "var(--secondary)",
                      borderColor: isWarning
                        ? "color-mix(in srgb, var(--chart-5) 30%, transparent)"
                        : "var(--border)",
                      cursor: "pointer",
                      borderRadius: "var(--radius)",
                    }}
                    onClick={() => {
                      setSheetOpen(false);
                      toast.success(`${label} — action initiated`);
                    }}
                  >
                    <Icon size={20} style={{ color: isWarning ? "var(--chart-5)" : "var(--foreground)", flexShrink: 0 }} />
                    <div>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: isWarning ? "var(--chart-5)" : "var(--foreground)" }}>
                        {label}
                      </p>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
                        {description}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}
      <style>{`
        @keyframes severityPulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.7; transform: scale(1.06); }
        }
      `}</style>
    </>
  );
}