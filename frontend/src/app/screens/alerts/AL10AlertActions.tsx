import { useMemo } from "react";
import { useNavigate, useParams } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { SeverityBadge } from "../../components/SeverityBadge";
import { mockAlerts } from "../../data/mockData";
import { useAlerts } from "../../hooks/useApiData";
import { guardianAlertHeading } from "../../services/alertService";
import { toast } from "sonner";
import { Archive, Ban, ChevronRight, Cpu, Scan, Sparkles } from "lucide-react";

export function AL10AlertActions() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: alertsData } = useAlerts();

  const alerts = useMemo(() => (alertsData?.alerts?.length ? alertsData.alerts : mockAlerts), [alertsData]);
  const alert = useMemo(() => alerts.find((a) => a.id === id), [alerts, id]);
  const detail = (alert as any)?.aiDetail as { whatHappened?: string; whyItMatters?: string; actions?: string[] } | undefined;

  if (!alert) {
    return (
      <div className="flex flex-col" style={{ minHeight: "100dvh" }}>
        <PageHeader title="Take Action" />
        <div className="flex-1 flex items-center justify-center p-6">
          <p style={{ fontFamily: "Inter, sans-serif", color: "var(--muted-foreground)" }}>Alert not found</p>
        </div>
      </div>
    );
  }

  const deviceTarget = encodeURIComponent(alert.deviceIp || alert.device || alert.id);
  const actions = detail?.actions ?? [
    "Review the alert evidence.",
    "Confirm device ownership and scope.",
    "Escalate after triage.",
  ];

  return (
    <div className="flex flex-col" style={{ minHeight: "100dvh" }}>
      <PageHeader
        title="Take Action"
        right={<SeverityBadge severity={alert.severity} size="md" />}
      />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5">
          <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-2">
                  <SeverityBadge severity={alert.severity} />
                  <span className="rounded-md px-2 py-1" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: 600 }}>
                    {alert.eventType}
                  </span>
                </div>
                <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.3 }}>
                  {guardianAlertHeading(alert.title)}
                </h2>
                <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.65 }}>
                  {alert.description}
                </p>
              </div>
              <button
                onClick={() => navigate(`/alerts/${alert.id}`)}
                className="flex items-center gap-2 rounded-md px-3 py-2"
                style={{ backgroundColor: "var(--secondary)", color: "var(--foreground)", border: "1px solid var(--border)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
              >
                Back to Alert
              </button>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <button
              onClick={() => navigate(`/devices/${deviceTarget}`, { state: { alertId: alert.id, deviceName: alert.device, deviceIp: alert.deviceIp, os: alert.os } })}
              className="rounded-lg border p-4 text-left"
              style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
            >
              <div className="flex items-center gap-2">
                <Cpu size={14} style={{ color: "var(--primary)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em" }}>
                  VIEW DEVICE
                </span>
              </div>
              <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                Open the affected host and inspect device status, ports, and controls.
              </p>
            </button>

            <button
              onClick={() => navigate(`/devices/${deviceTarget}/scan`, { state: { alertId: alert.id } })}
              className="rounded-lg border p-4 text-left"
              style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
            >
              <div className="flex items-center gap-2">
                <Scan size={14} style={{ color: "var(--chart-2)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--chart-2)", letterSpacing: "0.08em" }}>
                  RUN SCAN
                </span>
              </div>
              <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                Start a security scan for the device and collect current findings.
              </p>
            </button>

            <button
              onClick={() => toast.success("Alert archived")}
              className="rounded-lg border p-4 text-left"
              style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
            >
              <div className="flex items-center gap-2">
                <Archive size={14} style={{ color: "var(--muted-foreground)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                  ARCHIVE
                </span>
              </div>
              <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                Mark the alert as reviewed and move it out of the active queue.
              </p>
            </button>

            <button
              onClick={() => toast.success("Device blocked")}
              className="rounded-lg border p-4 text-left"
              style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
            >
              <div className="flex items-center gap-2">
                <Ban size={14} style={{ color: "var(--destructive)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--destructive)", letterSpacing: "0.08em" }}>
                  BLOCK DEVICE
                </span>
              </div>
              <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                Temporarily deny network access for the affected host.
              </p>
            </button>
          </div>

          <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
            <div className="flex items-center gap-2 mb-3">
              <Sparkles size={14} style={{ color: "var(--primary)" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em" }}>
                AI RESPONSE PLAN
              </span>
            </div>
            <ol className="flex flex-col gap-3">
              {actions.map((action, index) => (
                <li key={index} className="flex items-start gap-3">
                  <span className="rounded flex items-center justify-center flex-shrink-0 mt-0.5" style={{ width: "22px", height: "22px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", borderRadius: "var(--radius-sm)" }}>
                    {index + 1}
                  </span>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                    {action}
                  </p>
                </li>
              ))}
            </ol>
            {detail?.whyItMatters && (
              <div className="mt-4 rounded-md border border-border p-3" style={{ backgroundColor: "var(--background)" }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "6px" }}>
                  WHY IT MATTERS
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                  {detail.whyItMatters}
                </p>
              </div>
            )}
            <button
              onClick={() => navigate(`/alerts/${alert.id}/ai`)}
              className="mt-4 flex items-center gap-1"
              style={{ background: "none", border: "none", padding: 0, cursor: "pointer", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
            >
              View Full Analysis
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
