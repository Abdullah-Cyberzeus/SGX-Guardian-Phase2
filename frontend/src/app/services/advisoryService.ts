import api from "./api";

export interface RemediationStep {
  order: number;
  action: string;
  rationale: string;
  automatable: boolean;
}

export interface AnomalyContributor {
  feature: string;
  contribution: number;
  reason: string;
}

export type AnomalyRiskLevel = "below_detection" | "detected" | "high" | "critical";

export interface AnomalySource {
  ip: string;
  alert_count: number;
}

export interface AnomalyTopSignature {
  id: number;
  count: number;
}

export interface AnomalyDecision {
  detected: boolean;
  score: number;
  threshold: number;
  high_threshold: number;
  critical_threshold: number;
  risk_level: AnomalyRiskLevel;
  normalized_score: number;
  confidence?: number | null;
  detector: string;
  source?: AnomalySource | null;
  top_signature?: AnomalyTopSignature | null;
  category?: string | null;
  computed_at?: string | null;
  window_secs?: number | null;
  contributors: AnomalyContributor[];
}

export interface RemediationRecommendation {
  rec_id: string;
  alert_id: string;
  title: string;
  summary: string;
  severity: string;
  confidence: number;
  advisory_confidence: number;
  advisory_basis: string;
  steps: RemediationStep[];
  context: string[];
  references: string[];
  source: "signature-kb" | "anomaly-kb" | "device-cve" | "fallback" | string;
  anomaly?: AnomalyDecision | null;
  generated_at: string;
}

export interface AdvisoryRuleStep {
  action: string;
  rationale: string;
  automatable: boolean;
}

export interface AdvisoryRule {
  id?: string;
  title?: string;
  summary?: string;
  category?: string;
  severity?: string;
  source?: string;
  steps?: AdvisoryRuleStep[];
  references?: string[];
}

export interface AdvisoryRules {
  version?: string;
  rules?: AdvisoryRule[];
  fallback?: AdvisoryRule;
}

export const advisoryService = {
  getRecommendation: (alertId: string, signal?: AbortSignal) =>
    api.request<RemediationRecommendation>(
      `/threat/alerts/${encodeURIComponent(alertId)}/recommendation`,
      { method: "GET", signal, suppressUnauthorizedEvent: true },
    ),

  listRecommendations: (limit = 500, signal?: AbortSignal) =>
    api.request<RemediationRecommendation[]>("/advisory/recommendations", {
      method: "GET",
      params: { limit },
      signal,
    }),

  getRules: (signal?: AbortSignal) =>
    api.request<AdvisoryRules>("/advisory/rules", { method: "GET", signal }),
};

export default advisoryService;
