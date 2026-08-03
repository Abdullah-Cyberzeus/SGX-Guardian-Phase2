import { useState, useEffect, useMemo } from "react";
import { useParams, useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { Check, Loader2, Shield, AlertTriangle, ChevronRight } from "lucide-react";
import { mockDevices } from "../../data/mockData";
import { SeverityBadge } from "../../components/SeverityBadge";
import { useDevices } from "../../hooks/useApiData";

const scanSteps = [
  { label: "Checking firmware version", duration: 1400 },
  { label: "Checking open ports", duration: 1600 },
  { label: "Checking encryption status", duration: 1200 },
  { label: "Checking known vulnerabilities", duration: 2000 },
  { label: "Generating security report", duration: 1000 },
];

export function DV06SecurityScan() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  // Fetch devices from API with fallback to mock data
  const { data: devicesData } = useDevices();

  const devices = useMemo(() => {
    if (!devicesData) return mockDevices;
    return devicesData.devices || mockDevices;
  }, [devicesData]);

  const device = useMemo(() => {
    return devices.find((d: any) => d.id === id) || devices[0];
  }, [devices, id]);

  const [completedSteps, setCompletedSteps] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);
  const [progress, setProgress] = useState(0);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let elapsed = 0;
    const totalDuration = scanSteps.reduce((s, step) => s + step.duration, 0);
    let runningTotal = 0;

    scanSteps.forEach((step, i) => {
      setTimeout(() => {
        setCurrentStep(i);
        const start = runningTotal;
        const end = runningTotal + step.duration;
        const startPct = (start / totalDuration) * 100;
        const endPct = (end / totalDuration) * 100;

        const intervalMs = 50;
        const steps = step.duration / intervalMs;
        let s = 0;
        const iv = setInterval(() => {
          s++;
          setProgress(startPct + ((endPct - startPct) * s) / steps);
          if (s >= steps) clearInterval(iv);
        }, intervalMs);

        setTimeout(() => {
          setCompletedSteps(i + 1);
          if (i === scanSteps.length - 1) setTimeout(() => setDone(true), 300);
        }, step.duration);
      }, elapsed);
      elapsed += step.duration + 100;
      runningTotal += step.duration;
    });
  }, []);

  return (
    <div className="flex flex-col h-full">
      <PageHeader title={done ? "Scan Complete" : "Security Scan"} subtitle={device.name} />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6">
        {!done ? (
          <div className="flex flex-col gap-6">
            {/* Progress indicator */}
            <div className="flex flex-col items-center py-6">
              <div
                className="rounded-full flex items-center justify-center mb-4"
                style={{
                  width: "80px", height: "80px",
                  backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)",
                  animation: "pulse 2s ease-in-out infinite",
                }}
              >
                <Loader2 size={32} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "4px" }}>
                Scanning {device.name}
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                This may take a moment...
              </p>
            </div>

            {/* Progress bar */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Scanning...</span>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{Math.round(progress)}%</span>
              </div>
              <div className="rounded-full overflow-hidden" style={{ height: "6px", backgroundColor: "var(--muted)" }}>
                <div className="h-full rounded-full transition-all" style={{ width: `${progress}%`, backgroundColor: "var(--primary)", transitionDuration: "0.15s" }} />
              </div>
            </div>

            {/* Steps */}
            <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
              {scanSteps.map((step, i) => {
                const isComplete = completedSteps > i;
                const isActive = currentStep === i && !isComplete;
                return (
                  <div key={i} className="flex items-center gap-3 px-4 py-4" style={{ borderBottom: i < scanSteps.length - 1 ? "1px solid var(--border)" : undefined }}>
                    <div
                      className="rounded-full flex items-center justify-center flex-shrink-0"
                      style={{
                        width: "28px", height: "28px",
                        backgroundColor: isComplete ? "color-mix(in srgb, var(--chart-2) 20%, transparent)" : isActive ? "color-mix(in srgb, var(--primary) 15%, transparent)" : "var(--muted)",
                        border: `1.5px solid ${isComplete ? "var(--chart-2)" : isActive ? "var(--primary)" : "var(--border)"}`,
                      }}
                    >
                      {isComplete ? <Check size={13} style={{ color: "var(--chart-2)" }} /> :
                       isActive ? <Loader2 size={13} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} /> :
                       <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--border)" }} />}
                    </div>
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: isActive ? "var(--font-weight-medium)" : "var(--font-weight-normal)", color: isComplete ? "var(--chart-2)" : isActive ? "var(--foreground)" : "var(--muted-foreground)" }}>
                      {step.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          /* DV-07 Scan Results */
          <div className="flex flex-col gap-4">
            {/* Summary */}
            <div
              className="rounded-lg p-5 text-center"
              style={{
                backgroundColor: device.vulnerabilities > 0 ? "color-mix(in srgb, var(--destructive) 8%, var(--card))" : "color-mix(in srgb, var(--chart-2) 8%, var(--card))",
                border: `1.5px solid ${device.vulnerabilities > 0 ? "color-mix(in srgb, var(--destructive) 25%, transparent)" : "color-mix(in srgb, var(--chart-2) 25%, transparent)"}`,
              }}
            >
              {device.vulnerabilities > 0 ? (
                <AlertTriangle size={40} style={{ color: "var(--destructive)", margin: "0 auto 12px" }} />
              ) : (
                <Shield size={40} style={{ color: "var(--chart-2)", margin: "0 auto 12px" }} />
              )}
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: 700, color: device.vulnerabilities > 0 ? "var(--destructive)" : "var(--chart-2)", lineHeight: 1, marginBottom: "4px" }}>
                {device.vulnerabilities}
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", fontWeight: "var(--font-weight-semibold)", marginBottom: "8px" }}>
                {device.vulnerabilities > 0 ? "Vulnerabilities Found" : "No Vulnerabilities Found"}
              </p>
              {device.vulnerabilities > 0 && (
                <div className="flex items-center justify-center gap-3">
                  {[{ label: "High", count: device.vulnerabilityList.filter(v => v.severity === "HIGH").length, color: "var(--destructive)" },
                    { label: "Medium", count: device.vulnerabilityList.filter(v => v.severity === "MEDIUM").length, color: "var(--chart-5)" },
                    { label: "Low", count: device.vulnerabilityList.filter(v => v.severity === "LOW").length, color: "var(--muted-foreground)" }
                  ].map(({ label, count, color }) => (
                    <span key={label} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color }}>
                      <strong>{count}</strong> {label}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Recommendations */}
            {device.vulnerabilityList.length > 0 && (
              <div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>Recommendations</p>
                <div className="flex flex-col gap-3">
                  {device.vulnerabilityList.map((v) => (
                    <div key={v.id} className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", flex: 1 }}>{v.title}</p>
                        <SeverityBadge severity={v.severity} />
                      </div>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>{v.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Bottom buttons */}
            <div className="flex gap-3 mt-2 pb-4">
              <button
                onClick={() => navigate(`/devices/${id}`)}
                className="flex-1 flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
                style={{ height: "48px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
              >
                View Device
              </button>
              <button
                onClick={() => navigate("/alerts")}
                className="flex-1 flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
                style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
              >
                View Alerts
              </button>
            </div>
          </div>
        )}
        </div>
      </div>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.06); } }
      `}</style>
    </div>
  );
}
