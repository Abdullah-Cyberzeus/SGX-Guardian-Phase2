import { useMemo } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { SeverityBadge } from "../../components/SeverityBadge";
import { mockAlerts, mockDevices } from "../../data/mockData";
import { guardianAlertHeading } from "../../services/alertService";
import { toast } from "sonner";
import { AlertTriangle, Ban, ChevronRight, Scan, Shield, Wifi } from "lucide-react";

type DeviceRouteState = {
  alertId?: string;
  deviceName?: string;
  deviceIp?: string;
  os?: string;
};

function matchDevice(param: string | undefined, state: DeviceRouteState | null | undefined) {
  if (!param) return null;
  const decoded = decodeURIComponent(param);
  return mockDevices.find((device) =>
    device.id === decoded ||
    device.ip === decoded ||
    device.name === decoded ||
    device.name === state?.deviceName ||
    device.ip === state?.deviceIp,
  ) ?? null;
}

export function DV03DeviceDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const state = (location.state ?? null) as DeviceRouteState | null;

  const device = useMemo(() => matchDevice(id, state), [id, state]);
  const relatedAlerts = useMemo(() => {
    const ip = device?.ip ?? state?.deviceIp ?? "";
    const name = device?.name ?? state?.deviceName ?? "";
    return mockAlerts.filter((alert) => alert.deviceIp === ip || alert.device === name || alert.deviceId === device?.id);
  }, [device, state]);

  const displayName = device?.name ?? state?.deviceName ?? decodeURIComponent(id ?? "device");
  const displayIp = device?.ip ?? state?.deviceIp ?? decodeURIComponent(id ?? "");
  const displayOs = device?.os ?? state?.os ?? "Unknown";
  const securityScore = device?.securityScore ?? 61;
  const scoreSeverity: "HIGH" | "MEDIUM" | "LOW" = securityScore >= 75 ? "LOW" : securityScore >= 50 ? "MEDIUM" : "HIGH";

  return (
    <div className="flex flex-col" style={{ minHeight: "100dvh" }}>
      <PageHeader
        title={displayName}
        right={
          <SeverityBadge severity={scoreSeverity} size="md" />
        }
      />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-3xl p-4 md:p-6 flex flex-col gap-5">
          <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Shield size={16} style={{ color: "var(--primary)" }} />
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em" }}>
                    DEVICE DETAIL
                  </span>
                </div>
                <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.3 }}>
                  {displayName}
                </h2>
                <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
                  {displayOs} · {displayIp}
                </p>
              </div>
              <div className="rounded-md px-3 py-2" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)" }}>
                <Wifi size={16} style={{ color: "var(--primary)" }} />
              </div>
            </div>

            <div className="mt-4 grid gap-2 md:grid-cols-3">
              <div className="rounded-md border border-border p-3">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textTransform: "uppercase" }}>Security Score</p>
                <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--foreground)" }}>{securityScore}</p>
              </div>
              <div className="rounded-md border border-border p-3">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textTransform: "uppercase" }}>Manufacturer</p>
                <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>{device?.manufacturer ?? "Unknown"}</p>
              </div>
              <div className="rounded-md border border-border p-3">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textTransform: "uppercase" }}>Protocol</p>
                <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>{device?.protocol ?? "Unknown"}</p>
              </div>
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              <button
                onClick={() => navigate(`/devices/${encodeURIComponent(id ?? displayIp)}/scan`)}
                className="flex items-center gap-2 rounded-md px-3 py-2"
                style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
              >
                <Scan size={14} />
                Run Security Scan
              </button>
              <button
                onClick={() => toast.success("Device blocked")}
                className="flex items-center gap-2 rounded-md px-3 py-2"
                style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)", color: "var(--destructive)", border: "1px solid color-mix(in srgb, var(--destructive) 22%, transparent)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
              >
                <Ban size={14} />
                Block Device
              </button>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
                DEVICE INFO
              </p>
              <div className="flex flex-col gap-3">
                {[
                  ["Device ID", device?.id ?? id],
                  ["IP Address", displayIp],
                  ["MAC", device?.mac ?? "Unknown"],
                  ["OS", displayOs],
                  ["Status", device?.status ?? "online"],
                ].map(([label, value]) => (
                  <div key={label} className="flex items-center justify-between gap-3">
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
                    <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-word", textAlign: "right" }}>{String(value ?? "Unknown")}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
                RECENT ALERTS
              </p>
              <div className="flex flex-col gap-2">
                {relatedAlerts.length > 0 ? relatedAlerts.map((alert) => (
                  <button
                    key={alert.id}
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                    className="flex items-start justify-between gap-3 rounded-md border p-3 text-left"
                    style={{ backgroundColor: "var(--background)", borderColor: "var(--border)", cursor: "pointer" }}
                  >
                    <div className="min-w-0">
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", fontWeight: "var(--font-weight-medium)" }}>
                        {guardianAlertHeading(alert.title)}
                      </p>
                      <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                        {alert.description}
                      </p>
                    </div>
                    <ChevronRight size={14} style={{ color: "var(--muted-foreground)", flexShrink: 0, marginTop: 2 }} />
                  </button>
                )) : (
                  <div className="rounded-md border border-border p-3" style={{ backgroundColor: "var(--background)" }}>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                      No matching alerts found for this device.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={14} style={{ color: "var(--chart-5)" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--chart-5)", letterSpacing: "0.08em" }}>
                DEVICE CONTEXT
              </span>
            </div>
            <div className="flex flex-col gap-2">
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                {device?.status === "offline" ? "This device is offline and may need manual validation." : "This device is online and available for scan or containment actions."}
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
                {device?.guardianMonitoring ? "Guardian monitoring is enabled." : "Guardian monitoring is not enabled on this host."}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
