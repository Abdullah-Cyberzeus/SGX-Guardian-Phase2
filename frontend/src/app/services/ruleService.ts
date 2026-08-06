import api from './api';

export type RuleTrigger =
  | 'ThreatAlert'
  | 'DeviceDiscovered'
  | 'DeviceUnauthorized'
  | 'GeofenceEntry'
  | 'GeofenceExit'
  | 'AttestationFailed'
  | 'CrlRevocation';

export const RULE_TRIGGERS: RuleTrigger[] = [
  'ThreatAlert', 'DeviceDiscovered', 'DeviceUnauthorized',
  'GeofenceEntry', 'GeofenceExit', 'AttestationFailed', 'CrlRevocation',
];

export const SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical'] as const;
export const DEVICE_STATUSES = ['approved', 'unauthorized', 'drifted', 'stale'] as const;
export const SCAN_INTENSITIES = ['stealth', 'standard', 'aggressive'] as const;

// Rust enum with no #[serde(tag)] -> externally tagged: {"Variant": data} for
// tuple/struct variants. Mirrors src/rules/model.rs::Condition exactly.
export type Condition =
  | { SeverityAtLeast: string }
  | { CategoryIs: string }
  | { SignatureIdIn: number[] }
  | { SrcIpInCidr: string }
  | { PortIn: number[] }
  | { DeviceStatusIs: string }
  | { ZoneIs: string }
  | { All: Condition[] }
  | { Any: Condition[] }
  | { Not: Condition };

export const CONDITION_LEAF_TYPES = [
  'SeverityAtLeast', 'CategoryIs', 'SignatureIdIn', 'SrcIpInCidr', 'PortIn', 'DeviceStatusIs', 'ZoneIs',
] as const;
export type ConditionLeafType = (typeof CONDITION_LEAF_TYPES)[number];

// Mirrors src/rules/model.rs::RuleAction. Unit variants (no fields) serialize
// as bare strings; struct variants serialize as {"Variant": {...fields}}.
export type RuleAction =
  | { RaiseAlert: { severity: string } }
  | { Notify: { severity: string } }
  | { BlockIp: { ttl_secs: number | null } }
  | { RunScan: { intensity: string } }
  | 'RevokeDid'
  | 'LockTransport'
  | 'EmergencyKeyRotation';

export type RuleActionType = 'RaiseAlert' | 'Notify' | 'BlockIp' | 'RunScan' | 'RevokeDid' | 'LockTransport' | 'EmergencyKeyRotation';
export const RULE_ACTION_TYPES: RuleActionType[] = ['RaiseAlert', 'Notify', 'BlockIp', 'RunScan', 'RevokeDid', 'LockTransport', 'EmergencyKeyRotation'];
export const DESTRUCTIVE_ACTION_TYPES: RuleActionType[] = ['RevokeDid', 'LockTransport', 'EmergencyKeyRotation'];

export function actionType(action: RuleAction): RuleActionType {
  return typeof action === 'string' ? action : (Object.keys(action)[0] as RuleActionType);
}

export function isDestructiveAction(action: RuleAction): boolean {
  return DESTRUCTIVE_ACTION_TYPES.includes(actionType(action));
}

export interface Rule {
  rule_id: string;
  name: string;
  enabled: boolean;
  trigger: RuleTrigger;
  condition: Condition;
  actions: RuleAction[];
  notify: boolean;
  allow_destructive: boolean;
  cooldown_secs: number;
  max_actions_per_hour: number;
  created_at: string;
  updated_at: string;
}

// Body shape for both POST /rules (create) and PATCH /rules/{id} (partial update) -
// every field is optional server-side (RuleDraft / RulePatch in model.rs).
export interface RuleInput {
  name?: string;
  enabled?: boolean;
  trigger?: RuleTrigger;
  condition?: Condition;
  actions?: RuleAction[];
  notify?: boolean;
  allow_destructive?: boolean;
  cooldown_secs?: number;
  max_actions_per_hour?: number;
}

export interface RuleExecution {
  id: string;
  rule_id: string;
  rule_name: string;
  trigger_summary: string;
  actions: string[];
  outcome: string;
  at: string;
}

export interface RuleTestResult {
  rule_id: string;
  would_fire: boolean;
  dry_run: boolean;
  trigger_summary: string;
  actions: string[];
  outcome: string;
}

const encode = (value: string) => encodeURIComponent(value);

export const ruleService = {
  // GET /api/v1/rules
  getAll: () => api.get<Rule[]>('/rules'),

  // POST /api/v1/rules
  create: (draft: RuleInput) => api.post<Rule>('/rules', draft),

  // GET /api/v1/rules/{id}
  get: (id: string) => api.get<Rule>(`/rules/${encode(id)}`),

  // PATCH /api/v1/rules/{id}
  update: (id: string, patch: RuleInput) => api.patch<Rule>(`/rules/${encode(id)}`, patch),

  // DELETE /api/v1/rules/{id}
  remove: (id: string) => api.delete<{ success: boolean; rule_id: string }>(`/rules/${encode(id)}`),

  // POST /api/v1/rules/{id}/enable
  setEnabled: (id: string, enabled: boolean) => api.post<Rule>(`/rules/${encode(id)}/enable`, { enabled }),

  // POST /api/v1/rules/{id}/test - always dry-run, never executes actions for real
  test: (id: string) => api.post<RuleTestResult>(`/rules/${encode(id)}/test`),

  // GET /api/v1/rules/executions
  getExecutions: (limit?: number) => api.get<RuleExecution[]>('/rules/executions', limit ? { limit } : undefined),
};

export default ruleService;
