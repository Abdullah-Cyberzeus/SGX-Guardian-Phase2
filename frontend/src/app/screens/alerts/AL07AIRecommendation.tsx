import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { EmptyState } from "../../components/EmptyState";
import { Brain, Loader2, ShieldAlert } from "lucide-react";
import { useAlerts } from "../../hooks/useApiData";
import { advisoryService, type RemediationRecommendation } from "../../services/advisoryService";
import { ApiError } from "../../services/api";
import { guardianAlertHeading } from "../../services/alertService";
import { mockAlerts } from "../../data/mockData";

type RecommendationState =
  | { status: "loading" }
  | { status: "available"; recommendation: RemediationRecommendation }
  | { status: "fallback"; recommendation: RemediationRecommendation }
  | { status: "unavailable"; message: string };

function buildFallbackRecommendation(alert: any): RemediationRecommendation {
  const actions = Array.isArray(alert?.aiDetail?.actions) && alert.aiDetail.actions.length > 0
    ? alert.aiDetail.actions
    : [
        "Review the full alert context.",
        "Validate the affected device and source host.",
        "Escalate or archive after triage.",
      ];

  return {
    rec_id: `fallback-${alert?.id ?? "alert"}`,
    alert_id: alert?.id ?? "",
    title: `Response plan for ${alert?.title ?? "alert"}`,
    summary: alert?.aiDetail?.whyItMatters || alert?.aiSummary || "A recommended response is available for this alert.",
    severity: String(alert?.severity ?? "medium").toLowerCase(),
    confidence: 78,
    steps: actions.map((action: string, index: number) => ({
      order: index + 1,
      action,
      rationale: index === 0
        ? alert?.aiDetail?.whatHappened || alert?.description || "Start with the alert's immediate evidence."
        : "A normal triage step for this alert type.",
      automatable: index === 2,
    })),
    context: [
      alert?.eventType ? `Event type: ${alert.eventType}` : null,
      alert?.device ? `Device: ${alert.device}` : null,
      alert?.deviceIp ? `Device IP: ${alert.deviceIp}` : null,
      alert?.originalEvidence ? alert.originalEvidence : null,
    ].filter(Boolean) as string[],
    references: [
      alert?.signature ? `Signature: ${alert.signature}` : null,
      alert?.signatureId ? `Signature ID: ${alert.signatureId}` : null,
    ].filter(Boolean) as string[],
    source: "fallback",
    generated_at: alert?.rawTimestamp ?? new Date().toISOString(),
  };
}

export function AL07AIRecommendation() {
  const { id } = useParams<{ id: string }>();

  const { data: alertsData, loading } = useAlerts();
  const alerts = useMemo(() => (alertsData?.alerts?.length ? alertsData.alerts : mockAlerts), [alertsData]);
  const alert = useMemo(() => alerts.find((a) => a.id === id), [alerts, id]);
  const fallbackRecommendation = useMemo(() => buildFallbackRecommendation(alert), [alert]);

  const [state, setState] = useState<RecommendationState>({ status: "fallback", recommendation: fallbackRecommendation });

  useEffect(() => {
    if (!id || !alert) return;
    const controller = new AbortController();
    setState({ status: "fallback", recommendation: fallbackRecommendation });
    advisoryService.getRecommendation(id, controller.signal)
      .then((recommendation) => {
        if (!controller.signal.aborted) setState({ status: "available", recommendation });
      })
      .catch((error) => {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && error.status === 404) {
          setState({ status: "fallback", recommendation: fallbackRecommendation });
          return;
        }
        setState({ status: "unavailable", message: "AI analysis is temporarily unavailable." });
      });
    return () => controller.abort();
  }, [id, alert, fallbackRecommendation]);

  if (loading && !alert) {
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
          <div className="flex items-center gap-2">
            <div className="rounded-lg flex items-center gap-1.5 px-3 py-1.5" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}>
              <Brain size={14} style={{ color: "var(--primary)" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.06em" }}>
                Guardian AI
              </span>
            </div>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Analysis for: {guardianAlertHeading(alert.title)}
            </span>
          </div>

          {state.status === "loading" && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin" style={{ color: "var(--primary)" }} />
            </div>
          )}

          {state.status === "unavailable" && (
            <EmptyState icon={ShieldAlert} heading="No analysis available" subtext={state.message} />
          )}

          {(state.status === "available" || state.status === "fallback") && (
            <>
              <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em", marginBottom: "10px" }}>
                  Summary
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.7 }}>
                  {state.recommendation.summary}
                </p>
              </div>

              {state.recommendation.context.length > 0 && (
                <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--chart-5)", letterSpacing: "0.08em", marginBottom: "10px" }}>
                    Context
                  </p>
                  <ul className="flex flex-col gap-2">
                    {state.recommendation.context.map((line, i) => (
                      <li key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                        {line}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="rounded-lg border border-border p-4 pb-5" style={{ backgroundColor: "var(--card)" }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--chart-2)", letterSpacing: "0.08em", marginBottom: "12px" }}>
                  Recommended Actions
                </p>
                <ol className="flex flex-col gap-3">
                  {state.recommendation.steps.map((step) => (
                    <li key={step.order} className="flex items-start gap-3">
                      <span className="rounded flex items-center justify-center flex-shrink-0 mt-0.5" style={{ width: "22px", height: "22px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", borderRadius: "var(--radius-sm)" }}>
                        {step.order}
                      </span>
                      <div className="flex-1">
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.6 }}>
                          {step.action}
                        </p>
                        {step.rationale && (
                          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5, marginTop: "2px" }}>
                            {step.rationale}
                          </p>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              </div>

              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center", paddingBottom: "8px" }}>
                {state.status === "fallback" ? "Fallback recommendation" : "Generated"} · {new Date(state.recommendation.generated_at).toLocaleString()}
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
