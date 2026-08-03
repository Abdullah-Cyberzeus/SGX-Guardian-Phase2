import { useMemo } from "react";
import { useParams } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { mockAlerts } from "../../data/mockData";
import { Brain, Loader2 } from "lucide-react";
import { useAlerts } from "../../hooks/useApiData";

export function AL07AIRecommendation() {
  const { id } = useParams<{ id: string }>();

  // Fetch alerts from API with fallback to mock data
  const { data: alertsData, loading } = useAlerts();

  const alerts = useMemo(() => {
    if (!alertsData) return mockAlerts;
    return alertsData.alerts || mockAlerts;
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
      <div className="flex flex-col" style={{ minHeight: "100dvh" }}>
        <PageHeader title="AI Analysis" />
        <p style={{ fontFamily: "Inter, sans-serif", color: "var(--muted-foreground)", padding: "16px" }}>Alert not found</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col" style={{ minHeight: "100dvh" }}>
      <PageHeader title="AI Full Analysis" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5">
        {/* AI badge */}
        <div className="flex items-center gap-2">
          <div
            className="rounded-lg flex items-center gap-1.5 px-3 py-1.5"
            style={{ backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}
          >
            <Brain size={14} style={{ color: "var(--primary)" }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.06em" }}>
              Guardian AI
            </span>
          </div>
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            Analysis for: {alert.title}
          </span>
        </div>

        {/* What Happened */}
        <div
          className="rounded-lg border border-border p-4"
          style={{ backgroundColor: "var(--card)" }}
        >
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em", marginBottom: "10px" }}>
            What Happened
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.7 }}>
            {alert.aiDetail.whatHappened}
          </p>
        </div>

        {/* Why It Matters */}
        <div
          className="rounded-lg border border-border p-4"
          style={{ backgroundColor: "var(--card)" }}
        >
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--chart-5)", letterSpacing: "0.08em", marginBottom: "10px" }}>
            Why It Matters
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.7 }}>
            {alert.aiDetail.whyItMatters}
          </p>
        </div>

        {/* Recommended Actions */}
        <div
          className="rounded-lg border border-border p-4 pb-5"
          style={{ backgroundColor: "var(--card)" }}
        >
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--chart-2)", letterSpacing: "0.08em", marginBottom: "12px" }}>
            Recommended Actions
          </p>
          <ol className="flex flex-col gap-3">
            {alert.aiDetail.actions.map((action, i) => (
              <li key={i} className="flex items-start gap-3">
                <span
                  className="rounded flex items-center justify-center flex-shrink-0 mt-0.5"
                  style={{
                    width: "22px", height: "22px",
                    backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)",
                    color: "var(--primary)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-semibold)",
                    borderRadius: "var(--radius-sm)",
                  }}
                >
                  {i + 1}
                </span>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6, flex: 1 }}>
                  {action}
                </p>
              </li>
            ))}
          </ol>
        </div>

        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center", paddingBottom: "8px" }}>
          Analysis generated by Guardian AI Engine v2.4 · {new Date().toLocaleTimeString()}
        </p>
        </div>
      </div>
    </div>
  );
}
