import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { SeverityBadge } from "../../components/SeverityBadge";
import { Brain, ChevronRight, Cpu, Scan, ShieldAlert } from "lucide-react";
import { useAlerts } from "../../hooks/useApiData";
import { guardianAlertHeading } from "../../services/alertService";
import { managedDeviceService } from "../../services/managedDeviceService";
import { toast } from "sonner";

export function AL06AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: alertsData, loading } = useAlerts();
  const [deviceBusy, setDeviceBusy] = useState<"open" | "scan" | null>(null);

  const alerts = useMemo(() => alertsData?.alerts ?? [], [alertsData]);
  const alert = useMemo(() => alerts.find((a) => a.id === id), [alerts, id]);
  const detail = (alert as any)?.aiDetail as { whatHappened?: string; whyItMatters?: string; actions?: string[] } | undefined;

  if (loading && !alert) {
    return (
      <div className="flex flex-col items-center justify-center" style={{ minHeight: "100dvh" }}>
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-current border-t-transparent" style={{ color: "var(--primary)" }} />
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

  const resolveDevice = async () => {
    const targets = new Set([alert.deviceIp, alert.srcIp, alert.dstIp].filter(Boolean));
    const device = (await managedDeviceService.list()).find((candidate) => candidate.ip && targets.has(candidate.ip));
    if (!device) throw new Error("This alert is not linked to a managed device.");
    return device;
  };

  const openDevice = async () => {
    setDeviceBusy("open");
    try {
      const device = await resolveDevice();
      navigate(`/devices/${encodeURIComponent(device.device_id)}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to find the affected device");
    } finally {
      setDeviceBusy(null);
    }
  };

  const runScan = async () => {
    setDeviceBusy("scan");
    try {
      const device = await resolveDevice();
      const scan = await managedDeviceService.startScan(device.device_id);
      toast.success("Security scan started", { description: scan.scan_id });
      navigate(`/devices/${encodeURIComponent(device.device_id)}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to start security scan");
    } finally {
      setDeviceBusy(null);
    }
  };
  const evidenceLines = [
    alert.originalEvidence,
    alert.signature ? `Signature: ${alert.signature}` : null,
    alert.signatureId ? `Signature ID: ${alert.signatureId}` : null,
    alert.rawTimestamp ? `Detected: ${alert.rawTimestamp}` : null,
  ].filter(Boolean) as string[];
  const actions = detail?.actions ?? [];

  return (
    <div className="flex flex-col" style={{ minHeight: "100dvh" }}>
      <PageHeader
        title="Alert Details"
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
                onClick={() => navigate(`/alerts/${alert.id}/actions`)}
                className="flex items-center gap-2 rounded-md px-3 py-2"
                style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
              >
                Take Action
                <ChevronRight size={16} />
              </button>
            </div>
            <div className="mt-3 flex items-center gap-2 flex-wrap" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              <span>{alert.timestamp}</span>
              <span>·</span>
              <span>{alert.date}</span>
              <span>·</span>
              <span>{alert.status}</span>
            </div>
          </div>

          {alert.severity === "HIGH" && (
            <div className="rounded-lg border px-4 py-3" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 7%, transparent)", borderColor: "color-mix(in srgb, var(--destructive) 20%, transparent)" }}>
              <div className="flex items-center gap-2">
                <ShieldAlert size={14} style={{ color: "var(--destructive)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)", fontWeight: "var(--font-weight-semibold)" }}>
                  Active threat - immediate review recommended
                </span>
              </div>
            </div>
          )}

          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
                Affected Device
              </p>
              <div className="flex items-start gap-3">
                <div className="rounded-md flex items-center justify-center" style={{ width: 36, height: 36, backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)" }}>
                  <Cpu size={16} style={{ color: "var(--primary)" }} />
                </div>
                <div className="min-w-0 flex-1">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                    {alert.device}
                  </p>
                  <p className="mt-1" style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                    {alert.deviceIp}
                  </p>
                  <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                    {alert.os}
                  </p>
                </div>
              </div>
              <div className="mt-4 flex flex-col gap-2">
                <button
                  onClick={() => void openDevice()}
                  disabled={deviceBusy !== null}
                  className="flex items-center justify-between rounded-md px-3 py-2 text-left"
                  style={{ backgroundColor: "var(--secondary)", border: "1px solid var(--border)", color: "var(--foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" }}
                >
                  {deviceBusy === "open" ? "Opening Device…" : "View Device"}
                  <ChevronRight size={16} />
                </button>
                <button
                  onClick={() => void runScan()}
                  disabled={deviceBusy !== null}
                  className="flex items-center justify-between rounded-md px-3 py-2 text-left"
                  style={{ backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 18%, transparent)", color: "var(--primary)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" }}
                >
                  {deviceBusy === "scan" ? "Starting Scan…" : "Run Security Scan"}
                  <Scan size={16} />
                </button>
              </div>
            </div>

            <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
                Alert Snapshot
              </p>
              <div className="flex items-center gap-2 mb-3">
                <Brain size={14} style={{ color: "var(--primary)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.06em" }}>
                  ALERT SUMMARY
                </span>
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.7 }}>
                {alert.aiSummary}
              </p>
              <div className="mt-4">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>
                  Recommended Actions
                </p>
                {actions.length === 0 ? (
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>No response plan has been generated for this alert.</p>
                ) : <ol className="flex flex-col gap-2">
                  {actions.slice(0, 4).map((action, index) => (
                    <li key={index} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.5 }}>
                      {index + 1}. {action}
                    </li>
                  ))}
                </ol>}
              </div>
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

          <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
              Original Evidence
            </p>
            <div className="flex flex-col gap-1.5">
              {evidenceLines.map((line) => (
                <p key={line} style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6, wordBreak: "break-word" }}>
                  {line}
                </p>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
