import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { SeverityBadge } from "../../components/SeverityBadge";
import { useAlerts } from "../../hooks/useApiData";
import { alertService, guardianAlertHeading } from "../../services/alertService";
import { managedDeviceService } from "../../services/managedDeviceService";
import { threatService } from "../../services/threatService";
import { toast } from "sonner";
import { Archive, Ban, ChevronRight, Cpu, Scan, Sparkles } from "lucide-react";

export function AL10AlertActions() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: alertsData, loading, refetch } = useAlerts();
  const [busy, setBusy] = useState<"archive" | "block" | "scan" | "device" | null>(null);
  const [blockedIp, setBlockedIp] = useState(false);

  const alerts = useMemo(() => alertsData?.alerts ?? [], [alertsData]);
  const alert = useMemo(() => alerts.find((a) => a.id === id), [alerts, id]);
  const detail = (alert as any)?.aiDetail as { whatHappened?: string; whyItMatters?: string; actions?: string[] } | undefined;

  if (loading && !alert) {
    return <div className="flex items-center justify-center" style={{ minHeight: "100dvh" }}>Loading alert…</div>;
  }

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

  const actions = detail?.actions ?? [];

  const resolveDevice = async () => {
    const targets = new Set([alert.deviceIp, alert.srcIp, alert.dstIp].filter(Boolean));
    const device = (await managedDeviceService.list()).find((candidate) => candidate.ip && targets.has(candidate.ip));
    if (!device) throw new Error("This alert is not linked to a managed device.");
    return device;
  };

  const openDevice = async () => {
    setBusy("device");
    try {
      const device = await resolveDevice();
      navigate(`/devices/${encodeURIComponent(device.device_id)}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to find the affected device");
    } finally {
      setBusy(null);
    }
  };

  const runScan = async () => {
    setBusy("scan");
    try {
      const device = await resolveDevice();
      const scan = await managedDeviceService.startScan(device.device_id);
      toast.success("Security scan started", { description: scan.scan_id });
      navigate(`/devices/${encodeURIComponent(device.device_id)}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to start security scan");
    } finally {
      setBusy(null);
    }
  };

  const archive = async () => {
    setBusy("archive");
    try {
      if (alert.archived) {
        await alertService.restore(alert.id);
        toast.success("Alert restored to the active queue");
      } else {
        await alertService.archive(alert.id);
        toast.success("Alert archived");
      }
      await refetch();
      navigate("/alerts");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to update alert");
    } finally {
      setBusy(null);
    }
  };

  const block = async () => {
    const ip = alert.deviceIp || alert.srcIp;
    if (!ip) {
      toast.error("This alert has no source IP address to block");
      return;
    }
    setBusy("block");
    try {
      const result = await threatService.block(ip);
      if (!result.success) throw new Error(result.stderr || "Threat service did not block the address");
      setBlockedIp(true);
      toast.success("IP address blocked", { description: ip });
      await refetch();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to block IP address");
    } finally {
      setBusy(null);
    }
  };

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
              onClick={() => void openDevice()}
              disabled={busy !== null}
              className="rounded-lg border p-4 text-left"
              style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
            >
              <div className="flex items-center gap-2">
                <Cpu size={14} style={{ color: "var(--primary)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em" }}>
                  {busy === "device" ? "OPENING DEVICE…" : "VIEW DEVICE"}
                </span>
              </div>
              <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                Open the affected host and inspect device status, ports, and controls.
              </p>
            </button>

            <button
              onClick={() => void runScan()}
              disabled={busy !== null}
              className="rounded-lg border p-4 text-left"
              style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
            >
              <div className="flex items-center gap-2">
                <Scan size={14} style={{ color: "var(--chart-2)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--chart-2)", letterSpacing: "0.08em" }}>
                  {busy === "scan" ? "STARTING SCAN…" : "RUN SCAN"}
                </span>
              </div>
              <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                Start a security scan for the device and collect current findings.
              </p>
            </button>

            <button
              onClick={() => void archive()}
              disabled={busy !== null}
              className="rounded-lg border p-4 text-left"
              style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
            >
              <div className="flex items-center gap-2">
                <Archive size={14} style={{ color: "var(--muted-foreground)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                  {busy === "archive" ? "UPDATING…" : alert.archived ? "RESTORE" : "ARCHIVE"}
                </span>
              </div>
              <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                Mark the alert as reviewed and move it out of the active queue.
              </p>
            </button>

            <button
              onClick={() => void block()}
              disabled={busy !== null || alert.blocked || blockedIp}
              className="rounded-lg border p-4 text-left"
              style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
            >
              <div className="flex items-center gap-2">
                <Ban size={14} style={{ color: "var(--destructive)" }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--destructive)", letterSpacing: "0.08em" }}>
                  {alert.blocked || blockedIp ? "IP BLOCKED" : busy === "block" ? "BLOCKING…" : "BLOCK IP"}
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
            {actions.length === 0 ? (
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>No AI response plan has been generated for this alert.</p>
            ) : <ol className="flex flex-col gap-3">
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
            </ol>}
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
