import api from "./api";

export interface ThresholdRange {
  min: number;
  max: number;
}

export interface RecommendedThresholdRanges {
  detection: ThresholdRange;
  high: ThresholdRange;
  critical: ThresholdRange;
  note: string;
}

export interface Task1ThresholdDefaults {
  detection_threshold: number;
  high_threshold: number;
  critical_threshold: number;
}

export interface Task1ThresholdConfig {
  schema_version: number;
  settings_version: number;
  detection_threshold: number;
  high_threshold: number;
  critical_threshold: number;
  defaults: Task1ThresholdDefaults;
  recommended: RecommendedThresholdRanges;
  updated_by: string;
  updated_at: string;
  reason: string;
}

export interface Task1ThresholdUpdate {
  detection_threshold: number;
  high_threshold: number;
  critical_threshold: number;
  reason: string;
}

export const task1AiService = {
  getConfig: (signal?: AbortSignal) =>
    api.request<Task1ThresholdConfig>("/task1-ai/config", { method: "GET", signal }),

  updateConfig: (body: Task1ThresholdUpdate, signal?: AbortSignal) =>
    api.request<Task1ThresholdConfig>("/task1-ai/config", {
      method: "PUT",
      body: JSON.stringify(body),
      signal,
    }),
};

export default task1AiService;
