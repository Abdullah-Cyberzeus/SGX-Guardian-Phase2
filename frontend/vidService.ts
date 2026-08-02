import { PageHeader } from "../../components/PageHeader";

function UsageBar({ used, total }: { used: number; total: number }) {
  const pct = Math.round((used / total) * 100);
  const color = pct > 80 ? "var(--destructive)" : pct > 50 ? "var(--chart-5)" : "var(--chart-2)";
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{used} MB used</span>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{total} MB total</span>
      </div>
      <div className="rounded-full overflow-hidden" style={{ height: "8px", backgroundColor: "var(--muted)" }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color, transition: "width 0.3s" }} />
      </div>
    </div>
  );
}

export function ST04DataUsage() {
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Data Usage" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          Reset period: March 1 – March 31, 2026
        </p>

        {/* App data */}
        <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "12px" }}>App Data</p>
          <UsageBar used={147} total={500} />
          <div className="mt-4 flex flex-col gap-2">
            {[
              { label: "Alert data", value: "42 MB" },
              { label: "Device sync", value: "38 MB" },
              { label: "AI analysis cache", value: "52 MB" },
              { label: "Other", value: "15 MB" },
            ].map(({ label, value }) => (
              <div key={label} className="flex items-center justify-between">
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{label}</span>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Guardian sync data */}
        <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "12px" }}>Guardian Sync Data</p>
          <UsageBar used={280} total={1024} />
          <div className="mt-4 flex flex-col gap-2">
            {[
              { label: "Network traffic logs", value: "138 MB" },
              { label: "Device telemetry", value: "84 MB" },
              { label: "Threat intelligence", value: "58 MB" },
            ].map(({ label, value }) => (
              <div key={label} className="flex items-center justify-between">
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{label}</span>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{value}</span>
              </div>
            ))}
          </div>
        </div>
        </div>
      </div>
    </div>
  );
}
