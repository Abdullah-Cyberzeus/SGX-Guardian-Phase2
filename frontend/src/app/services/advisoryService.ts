import api from "./api";

export interface RemediationStep {
  order: number;
  action: string;
  rationale: string;
  automatable: boolean;
}

export interface RemediationRecommendation {
  rec_id: string;
  alert_id: string;
  title: string;
  summary: string;
  severity: string;
  confidence: number;
  steps: RemediationStep[];
  context: string[];
  references: string[];
  source: "signature-kb" | "anomaly-kb" | "device-cve" | "fallback" | string;
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
