import { useState, ReactNode } from "react";
import { toast } from "sonner";
import * as Switch from "@radix-ui/react-switch";
import {
  Plus, Trash2, Pencil, X, Check, Loader2, AlertTriangle,
  History, FlaskConical, Bell, Zap, RefreshCw,
} from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { StatusBadge } from "../../components/SeverityBadge";
import { useRules, useRuleExecutions } from "../../hooks/useApiData";
import {
  ruleService,
  RULE_TRIGGERS, SEVERITY_LEVELS, DEVICE_STATUSES, SCAN_INTENSITIES,
  CONDITION_LEAF_TYPES, RULE_ACTION_TYPES, DESTRUCTIVE_ACTION_TYPES,
  actionType, isDestructiveAction,
  type Rule, type RuleInput, type RuleTrigger, type Condition, type ConditionLeafType,
  type RuleAction, type RuleActionType, type RuleTestResult,
} from "../../services/ruleService";

// ── Labels & formatting ──────────────────────────────────────────────────────

const TRIGGER_LABELS: Record<RuleTrigger, string> = {
  ThreatAlert: "Threat Alert",
  DeviceDiscovered: "Device Discovered",
  DeviceUnauthorized: "Device Unauthorized",
  GeofenceEntry: "Geofence Entry",
  GeofenceExit: "Geofence Exit",
  AttestationFailed: "Attestation Failed",
  CrlRevocation: "CRL Revocation",
};

const LEAF_LABELS: Record<ConditionLeafType, string> = {
  SeverityAtLeast: "Severity at least",
  CategoryIs: "Category is",
  SignatureIdIn: "Signature ID in",
  SrcIpInCidr: "Source IP in CIDR",
  PortIn: "Port in",
  DeviceStatusIs: "Device status is",
  ZoneIs: "Zone is",
};

const ACTION_LABELS: Record<RuleActionType, string> = {
  RaiseAlert: "Raise Alert",
  Notify: "Notify",
  BlockIp: "Block IP",
  RunScan: "Run Scan",
  RevokeDid: "Revoke DID",
  LockTransport: "Lock Transport",
  EmergencyKeyRotation: "Emergency Key Rotation",
};

function actionSummary(action: RuleAction): string {
  const type = actionType(action);
  if (type === "RaiseAlert") return `Raise Alert (${(action as { RaiseAlert: { severity: string } }).RaiseAlert.severity})`;
  if (type === "Notify") return `Notify (${(action as { Notify: { severity: string } }).Notify.severity})`;
  if (type === "BlockIp") {
    const ttl = (action as { BlockIp: { ttl_secs: number | null } }).BlockIp.ttl_secs;
    return ttl ? `Block IP (${ttl}s)` : "Block IP";
  }
  if (type === "RunScan") return `Run Scan (${(action as { RunScan: { intensity: string } }).RunScan.intensity})`;
  return ACTION_LABELS[type];
}

function conditionSummary(condition: Condition): string {
  if ("All" in condition) return condition.All.length === 0 ? "always matches" : condition.All.map(conditionSummary).join(" AND ");
  if ("Any" in condition) return condition.Any.length === 0 ? "always matches" : condition.Any.map(conditionSummary).join(" OR ");
  if ("Not" in condition) return `NOT (${conditionSummary(condition.Not)})`;
  if ("SeverityAtLeast" in condition) return `severity ≥ ${condition.SeverityAtLeast}`;
  if ("CategoryIs" in condition) return `category = ${condition.CategoryIs}`;
  if ("SignatureIdIn" in condition) return `signature ID in [${condition.SignatureIdIn.join(", ")}]`;
  if ("SrcIpInCidr" in condition) return `source IP in ${condition.SrcIpInCidr}`;
  if ("PortIn" in condition) return `port in [${condition.PortIn.join(", ")}]`;
  if ("DeviceStatusIs" in condition) return `device status = ${condition.DeviceStatusIs}`;
  if ("ZoneIs" in condition) return `zone = ${condition.ZoneIs}`;
  return "unknown condition";
}

function outcomeVariant(outcome: string): "success" | "warning" | "danger" | "muted" | "info" {
  if (outcome === "executed") return "success";
  if (outcome === "dry-run") return "info";
  if (outcome === "downgraded" || outcome === "rate-limited") return "warning";
  if (outcome === "failed") return "danger";
  return "muted";
}

function formatDateTime(iso?: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

// ── Condition leaf <-> Condition tree conversion ─────────────────────────────

interface ConditionLeaf {
  type: ConditionLeafType;
  value: string;
}

function leafFromCondition(condition: Condition): ConditionLeaf | null {
  if ("SeverityAtLeast" in condition) return { type: "SeverityAtLeast", value: condition.SeverityAtLeast };
  if ("CategoryIs" in condition) return { type: "CategoryIs", value: condition.CategoryIs };
  if ("SignatureIdIn" in condition) return { type: "SignatureIdIn", value: condition.SignatureIdIn.join(", ") };
  if ("SrcIpInCidr" in condition) return { type: "SrcIpInCidr", value: condition.SrcIpInCidr };
  if ("PortIn" in condition) return { type: "PortIn", value: condition.PortIn.join(", ") };
  if ("DeviceStatusIs" in condition) return { type: "DeviceStatusIs", value: condition.DeviceStatusIs };
  if ("ZoneIs" in condition) return { type: "ZoneIs", value: condition.ZoneIs };
  return null;
}

/** Flattens a {All:[...]}/{Any:[...]} of simple leaves into the builder's shape. Returns null (unflattenable) for Not or nested All/Any/Not among the leaves — those rules stay editable everywhere except the condition, which the form leaves untouched on save. */
function flattenCondition(condition: Condition): { mode: "All" | "Any"; leaves: ConditionLeaf[] } | null {
  const container = "All" in condition ? condition.All : "Any" in condition ? condition.Any : null;
  if (container === null) return null;
  const leaves: ConditionLeaf[] = [];
  for (const item of container) {
    const leaf = leafFromCondition(item);
    if (!leaf) return null;
    leaves.push(leaf);
  }
  return { mode: "All" in condition ? "All" : "Any", leaves };
}

function buildLeafCondition(leaf: ConditionLeaf): Condition {
  switch (leaf.type) {
    case "SeverityAtLeast": return { SeverityAtLeast: leaf.value };
    case "CategoryIs": return { CategoryIs: leaf.value };
    case "SignatureIdIn": return { SignatureIdIn: leaf.value.split(",").map((v) => Number(v.trim())).filter((n) => !Number.isNaN(n)) };
    case "SrcIpInCidr": return { SrcIpInCidr: leaf.value };
    case "PortIn": return { PortIn: leaf.value.split(",").map((v) => Number(v.trim())).filter((n) => !Number.isNaN(n)) };
    case "DeviceStatusIs": return { DeviceStatusIs: leaf.value };
    case "ZoneIs": return { ZoneIs: leaf.value };
  }
}

function defaultLeafValue(type: ConditionLeafType): string {
  if (type === "SeverityAtLeast") return "high";
  if (type === "DeviceStatusIs") return "unauthorized";
  return "";
}

// ── Form state ────────────────────────────────────────────────────────────────

interface ActionsEnabled {
  RaiseAlert: boolean;
  Notify: boolean;
  BlockIp: boolean;
  RunScan: boolean;
  RevokeDid: boolean;
  LockTransport: boolean;
  EmergencyKeyRotation: boolean;
}

interface FormState {
  name: string;
  trigger: RuleTrigger;
  conditionMode: "All" | "Any";
  conditionLeaves: ConditionLeaf[];
  conditionComplex: Condition | null;
  actionsEnabled: ActionsEnabled;
  raiseSeverity: string;
  notifySeverity: string;
  blockTtl: string;
  scanIntensity: string;
  notify: boolean;
  allowDestructive: boolean;
  cooldownSecs: string;
  maxActionsPerHour: string;
}

function defaultForm(): FormState {
  return {
    name: "",
    trigger: "ThreatAlert",
    conditionMode: "All",
    conditionLeaves: [],
    conditionComplex: null,
    actionsEnabled: { RaiseAlert: true, Notify: false, BlockIp: false, RunScan: false, RevokeDid: false, LockTransport: false, EmergencyKeyRotation: false },
    raiseSeverity: "high",
    notifySeverity: "info",
    blockTtl: "300",
    scanIntensity: "standard",
    notify: false,
    allowDestructive: false,
    cooldownSecs: "300",
    maxActionsPerHour: "20",
  };
}

function ruleToForm(rule: Rule): FormState {
  const flattened = flattenCondition(rule.condition);
  const form = defaultForm();
  form.name = rule.name;
  form.trigger = rule.trigger;
  form.conditionMode = flattened?.mode ?? "All";
  form.conditionLeaves = flattened?.leaves ?? [];
  form.conditionComplex = flattened ? null : rule.condition;
  form.actionsEnabled = { RaiseAlert: false, Notify: false, BlockIp: false, RunScan: false, RevokeDid: false, LockTransport: false, EmergencyKeyRotation: false };
  for (const action of rule.actions) {
    const type = actionType(action);
    form.actionsEnabled[type] = true;
    if (type === "RaiseAlert") form.raiseSeverity = (action as { RaiseAlert: { severity: string } }).RaiseAlert.severity;
    if (type === "Notify") form.notifySeverity = (action as { Notify: { severity: string } }).Notify.severity;
    if (type === "BlockIp") {
      const ttl = (action as { BlockIp: { ttl_secs: number | null } }).BlockIp.ttl_secs;
      form.blockTtl = ttl != null ? String(ttl) : "";
    }
    if (type === "RunScan") form.scanIntensity = (action as { RunScan: { intensity: string } }).RunScan.intensity;
  }
  form.notify = rule.notify;
  form.allowDestructive = rule.allow_destructive;
  form.cooldownSecs = String(rule.cooldown_secs);
  form.maxActionsPerHour = String(rule.max_actions_per_hour);
  return form;
}

function buildActions(form: FormState): RuleAction[] {
  const actions: RuleAction[] = [];
  if (form.actionsEnabled.RaiseAlert) actions.push({ RaiseAlert: { severity: form.raiseSeverity } });
  if (form.actionsEnabled.Notify) actions.push({ Notify: { severity: form.notifySeverity } });
  if (form.actionsEnabled.BlockIp) actions.push({ BlockIp: { ttl_secs: form.blockTtl.trim() ? Number(form.blockTtl) : null } });
  if (form.actionsEnabled.RunScan) actions.push({ RunScan: { intensity: form.scanIntensity } });
  if (form.actionsEnabled.RevokeDid) actions.push("RevokeDid");
  if (form.actionsEnabled.LockTransport) actions.push("LockTransport");
  if (form.actionsEnabled.EmergencyKeyRotation) actions.push("EmergencyKeyRotation");
  return actions;
}

// ── Small shared bits ─────────────────────────────────────────────────────────

const labelStyle = { fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" } as const;
const inputStyle = { height: "44px", backgroundColor: "var(--input-background)", border: "1.5px solid var(--border)", borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" } as const;

function FieldLabel({ children }: { children: ReactNode }) {
  return <label style={labelStyle}>{children}</label>;
}

function ActionPill({ action, allowDestructive }: { action: RuleAction; allowDestructive: boolean }) {
  const destructive = isDestructiveAction(action);
  const color = destructive ? (allowDestructive ? "var(--destructive)" : "var(--chart-5)") : "var(--muted-foreground)";
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-2 py-1"
      style={{ fontSize: "10px", fontFamily: "Inter, sans-serif", color, backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 30%, transparent)` }}
      title={destructive ? (allowDestructive ? "Destructive action — will actually execute" : "Destructive action — downgraded to a critical alert unless 'Allow destructive actions' is on") : undefined}
    >
      {destructive && <AlertTriangle size={10} />}
      {actionSummary(action)}
    </span>
  );
}

function SmallSwitch({ checked, onCheckedChange, disabled }: { checked: boolean; onCheckedChange: () => void; disabled?: boolean }) {
  return (
    <Switch.Root
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      style={{ width: "40px", height: "22px", borderRadius: "11px", backgroundColor: checked ? "var(--primary)" : "var(--muted)", border: "none", cursor: disabled ? "wait" : "pointer", position: "relative", transition: "background-color 0.2s", flexShrink: 0, opacity: disabled ? 0.6 : 1 }}
    >
      <Switch.Thumb style={{ display: "block", width: "16px", height: "16px", borderRadius: "50%", backgroundColor: "white", transform: checked ? "translateX(20px)" : "translateX(3px)", transition: "transform 0.2s" }} />
    </Switch.Root>
  );
}

// ── Rule card ─────────────────────────────────────────────────────────────────

function RuleCard({
  rule, busy, testResult, onToggle, onTest, onEdit, onDelete, onDismissTest,
}: {
  rule: Rule;
  busy: "toggle" | "test" | "delete" | null;
  testResult?: RuleTestResult;
  onToggle: () => void;
  onTest: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onDismissTest: () => void;
}) {
  return (
    <div className="rounded-lg border border-border p-4 flex flex-col gap-3" style={{ backgroundColor: "var(--card)" }}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{rule.name}</p>
            <StatusBadge status={rule.enabled ? "Active" : "Disabled"} variant={rule.enabled ? "success" : "muted"} />
          </div>
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--primary)", marginTop: "2px" }}>{TRIGGER_LABELS[rule.trigger]}</p>
        </div>
        {busy === "toggle" ? <Loader2 size={16} className="animate-spin" style={{ flexShrink: 0 }} /> : <SmallSwitch checked={rule.enabled} onCheckedChange={onToggle} />}
      </div>

      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
        If {conditionSummary(rule.condition)}
      </p>

      <div className="flex flex-wrap gap-1.5">
        {rule.actions.map((action, i) => <ActionPill key={i} action={action} allowDestructive={rule.allow_destructive} />)}
        {rule.notify && (
          <span className="inline-flex items-center gap-1 rounded-full px-2 py-1" style={{ fontSize: "10px", fontFamily: "Inter, sans-serif", color: "var(--primary)", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 30%, transparent)" }}>
            <Bell size={10} /> Notify
          </span>
        )}
      </div>

      <div className="flex items-center gap-3">
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Cooldown {rule.cooldown_secs}s</span>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Max {rule.max_actions_per_hour}/hr</span>
      </div>

      {testResult && (
        <div className="rounded-md p-3 flex flex-col gap-1.5" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <FlaskConical size={12} style={{ color: "var(--primary)" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.06em" }}>TEST RESULT (dry-run, nothing executed)</span>
            </div>
            <button onClick={onDismissTest} style={{ background: "none", border: "none", cursor: "pointer" }} aria-label="Dismiss test result">
              <X size={13} style={{ color: "var(--muted-foreground)" }} />
            </button>
          </div>
          <div className="flex items-center gap-2">
            <StatusBadge status={testResult.would_fire ? "Would fire" : "Would not fire"} variant={testResult.would_fire ? "success" : "muted"} />
            <StatusBadge status={testResult.outcome} variant={outcomeVariant(testResult.outcome)} />
          </div>
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)", wordBreak: "break-all" }}>{testResult.trigger_summary}</p>
          {testResult.actions.length > 0 && (
            <ul className="flex flex-col gap-0.5">
              {testResult.actions.map((line, i) => (
                <li key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--foreground)" }}>&bull; {line}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="flex items-center gap-2 pt-2" style={{ borderTop: "1px solid var(--border)" }}>
        <button
          onClick={onTest}
          disabled={busy === "test"}
          className="flex items-center gap-1.5 rounded-md px-2.5 py-1.5 disabled:opacity-50"
          style={{ border: "1px solid var(--border)", background: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--primary)" }}
        >
          {busy === "test" ? <Loader2 size={13} className="animate-spin" /> : <FlaskConical size={13} />} Test
        </button>
        <button
          onClick={onEdit}
          className="flex items-center gap-1.5 rounded-md px-2.5 py-1.5"
          style={{ border: "1px solid var(--border)", background: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}
        >
          <Pencil size={13} /> Edit
        </button>
        <button
          onClick={onDelete}
          disabled={busy === "delete"}
          className="ml-auto flex items-center gap-1.5 rounded-md px-2.5 py-1.5 disabled:opacity-50"
          style={{ border: "1px solid color-mix(in srgb, var(--destructive) 30%, transparent)", background: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--destructive)" }}
        >
          {busy === "delete" ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />} Delete
        </button>
      </div>
    </div>
  );
}

// ── Main screen ─────────────────────────────────────────────────────────────

export function ST12AlertRules() {
  const { data: rules, loading, error, refetch } = useRules();
  const { data: executions, refetch: refetchExecutions } = useRuleExecutions(50);

  const [sheetOpen, setSheetOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [form, setForm] = useState<FormState>(defaultForm());
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [busyKind, setBusyKind] = useState<"toggle" | "test" | "delete" | null>(null);
  const [testResults, setTestResults] = useState<Record<string, RuleTestResult>>({});

  const openCreate = () => { setEditingRule(null); setForm(defaultForm()); setSheetOpen(true); };
  const openEdit = (rule: Rule) => { setEditingRule(rule); setForm(ruleToForm(rule)); setSheetOpen(true); };

  const setBusy = (id: string, kind: "toggle" | "test" | "delete" | null) => { setBusyId(kind ? id : null); setBusyKind(kind); };

  const handleToggle = async (rule: Rule) => {
    setBusy(rule.rule_id, "toggle");
    try {
      await ruleService.setEnabled(rule.rule_id, !rule.enabled);
      await refetch();
    } catch (cause) {
      toast.error("Could not update rule", { description: cause instanceof Error ? cause.message : "Please try again." });
    } finally {
      setBusy(rule.rule_id, null);
    }
  };

  const handleTest = async (rule: Rule) => {
    setBusy(rule.rule_id, "test");
    try {
      const result = await ruleService.test(rule.rule_id);
      setTestResults((prev) => ({ ...prev, [rule.rule_id]: result }));
    } catch (cause) {
      toast.error("Test failed", { description: cause instanceof Error ? cause.message : "Please try again." });
    } finally {
      setBusy(rule.rule_id, null);
    }
  };

  const handleDelete = async (rule: Rule) => {
    if (!window.confirm(`Delete rule "${rule.name}"? This cannot be undone.`)) return;
    setBusy(rule.rule_id, "delete");
    try {
      await ruleService.remove(rule.rule_id);
      toast.success("Rule deleted");
      await refetch();
    } catch (cause) {
      toast.error("Could not delete rule", { description: cause instanceof Error ? cause.message : "Please try again." });
    } finally {
      setBusy(rule.rule_id, null);
    }
  };

  const addLeaf = () => setForm((f) => ({ ...f, conditionLeaves: [...f.conditionLeaves, { type: "SeverityAtLeast", value: defaultLeafValue("SeverityAtLeast") }] }));
  const removeLeaf = (index: number) => setForm((f) => ({ ...f, conditionLeaves: f.conditionLeaves.filter((_, i) => i !== index) }));
  const updateLeaf = (index: number, patch: Partial<ConditionLeaf>) =>
    setForm((f) => ({ ...f, conditionLeaves: f.conditionLeaves.map((leaf, i) => (i === index ? { ...leaf, ...patch } : leaf)) }));

  const toggleAction = (type: RuleActionType) => setForm((f) => ({ ...f, actionsEnabled: { ...f.actionsEnabled, [type]: !f.actionsEnabled[type] } }));

  const hasDestructiveSelected = DESTRUCTIVE_ACTION_TYPES.some((t) => form.actionsEnabled[t]);

  const handleSave = async () => {
    if (!form.name.trim()) { toast.error("Rule name is required"); return; }
    const selected = RULE_ACTION_TYPES.filter((t) => form.actionsEnabled[t]);
    if (selected.length === 0) { toast.error("Select at least one action"); return; }

    const payload: RuleInput = {
      name: form.name.trim(),
      trigger: form.trigger,
      actions: buildActions(form),
      notify: form.notify,
      allow_destructive: form.allowDestructive,
      cooldown_secs: Number(form.cooldownSecs) || 300,
      max_actions_per_hour: Number(form.maxActionsPerHour) || 20,
    };
    // Only touch `condition` if the builder actually represents it (new rule, or a
    // flattenable existing one). For an existing rule whose condition is more complex
    // than this builder supports (Not / nested groups), omitting the field entirely
    // leaves it untouched server-side — PATCH only changes fields that are present.
    if (!(editingRule && form.conditionComplex && form.conditionLeaves.length === 0)) {
      payload.condition = form.conditionMode === "Any"
        ? { Any: form.conditionLeaves.map(buildLeafCondition) }
        : { All: form.conditionLeaves.map(buildLeafCondition) };
    }

    setSaving(true);
    try {
      if (editingRule) {
        await ruleService.update(editingRule.rule_id, payload);
        toast.success("Rule updated");
      } else {
        await ruleService.create(payload);
        toast.success("Rule created");
      }
      setSheetOpen(false);
      await refetch();
    } catch (cause) {
      toast.error(editingRule ? "Could not update rule" : "Could not create rule", { description: cause instanceof Error ? cause.message : "Please try again." });
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <div className="flex flex-col h-full">
        <PageHeader
          title="Alert Rules"
          subtitle={rules ? `${rules.length} rule${rules.length === 1 ? "" : "s"} · ${rules.filter((r) => r.enabled).length} active` : undefined}
          right={
            <button
              onClick={openCreate}
              className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium"
              style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer" }}
            >
              <Plus size={14} /> New Rule
            </button>
          }
        />
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4 pb-8">

            <div className="rounded-lg border p-4" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}>
              <div className="flex items-center gap-1.5" style={{ marginBottom: "4px" }}>
                <Zap size={13} style={{ color: "var(--primary)" }} />
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)" }}>Automation Engine</p>
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
                Event → condition → action rules run on your Guardian, no cloud required. New rules default to dry-run
                for destructive actions (Revoke DID / Lock Transport / Emergency Key Rotation) until you explicitly allow them.
              </p>
            </div>

            {loading && !rules ? (
              <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground"><Loader2 size={18} className="animate-spin" /> Loading rules…</div>
            ) : error || !rules ? (
              <div className="flex flex-col items-center justify-center gap-3 p-6 text-center rounded-lg border border-border">
                <AlertTriangle size={26} className="text-destructive" />
                <p className="text-sm font-semibold">Rules could not be loaded</p>
                <p className="max-w-sm text-xs text-muted-foreground">{error?.message || "The rules registry could not be verified — no rules are currently active."}</p>
                <button onClick={() => void refetch()} className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground">Retry</button>
              </div>
            ) : rules.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-3 p-8 text-center rounded-lg border border-border" style={{ backgroundColor: "var(--card)" }}>
                <Zap size={28} style={{ color: "var(--muted-foreground)" }} />
                <p className="text-sm font-semibold">No rules yet</p>
                <p className="max-w-sm text-xs text-muted-foreground">This Guardian has no automation rules configured. Create one to automatically respond to threats, unauthorized devices, geofence changes, or CRL revocations.</p>
                <button onClick={openCreate} className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground">Create your first rule</button>
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {rules.map((rule) => (
                  <RuleCard
                    key={rule.rule_id}
                    rule={rule}
                    busy={busyId === rule.rule_id ? busyKind : null}
                    testResult={testResults[rule.rule_id]}
                    onToggle={() => void handleToggle(rule)}
                    onTest={() => void handleTest(rule)}
                    onEdit={() => openEdit(rule)}
                    onDelete={() => void handleDelete(rule)}
                    onDismissTest={() => setTestResults((prev) => { const next = { ...prev }; delete next[rule.rule_id]; return next; })}
                  />
                ))}
              </div>
            )}

            {/* API 5 - GET /rules/executions: real firing history (background event bus only, not Test button runs) */}
            <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
              <div className="flex items-center justify-between" style={{ marginBottom: "12px" }}>
                <div className="flex items-center gap-1.5">
                  <History size={13} style={{ color: "var(--primary)" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.08em" }}>EXECUTION HISTORY</p>
                </div>
                <button onClick={() => void refetchExecutions()} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)" }} aria-label="Refresh execution history">
                  <RefreshCw size={13} />
                </button>
              </div>
              {!executions || executions.length === 0 ? (
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                  No executions yet — rules fire automatically when a matching real event occurs (Test button results are not recorded here).
                </p>
              ) : (
                <div className="flex flex-col gap-2">
                  {executions.slice(0, 20).map((execution) => (
                    <div key={execution.id} className="rounded-md p-3" style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}>
                      <div className="flex items-center justify-between gap-2">
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{execution.rule_name}</p>
                        <StatusBadge status={execution.outcome} variant={outcomeVariant(execution.outcome)} />
                      </div>
                      <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "4px", wordBreak: "break-all" }}>{execution.trigger_summary}</p>
                      {execution.actions.length > 0 && (
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--foreground)", marginTop: "4px" }}>{execution.actions.join(" · ")}</p>
                      )}
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "4px" }}>{formatDateTime(execution.at)}</p>
                    </div>
                  ))}
                  {executions.length > 20 && (
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textAlign: "center" }}>Showing latest 20 of {executions.length}</p>
                  )}
                </div>
              )}
            </div>

          </div>
        </div>
      </div>

      {/* Create / Edit Sheet */}
      {sheetOpen && (
        <div
          className="fixed inset-0 z-50 flex items-end md:items-center justify-center cursor-pointer"
          style={{ backgroundColor: "rgba(0,0,0,0.6)" }}
          onClick={() => setSheetOpen(false)}
        >
          <div
            className="w-full rounded-t-xl md:rounded-xl border-t md:border border-border"
            style={{ backgroundColor: "var(--card)", maxWidth: "480px", maxHeight: "92dvh", display: "flex", flexDirection: "column" }}
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-border flex-shrink-0">
              <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                {editingRule ? "Edit Alert Rule" : "Create Alert Rule"}
              </h3>
              <button onClick={() => setSheetOpen(false)} style={{ background: "none", border: "none", cursor: "pointer" }} aria-label="Close">
                <X size={20} style={{ color: "var(--muted-foreground)" }} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
              <div>
                <FieldLabel>Rule Name <span style={{ color: "var(--destructive)" }}>*</span></FieldLabel>
                <input
                  value={form.name}
                  onChange={(event) => setForm((f) => ({ ...f, name: event.target.value }))}
                  placeholder="e.g. Block on critical threat"
                  className="w-full px-4 outline-none"
                  style={inputStyle}
                />
              </div>

              <div>
                <FieldLabel>Trigger — which event this rule reacts to</FieldLabel>
                <select
                  value={form.trigger}
                  onChange={(event) => setForm((f) => ({ ...f, trigger: event.target.value as RuleTrigger }))}
                  className="w-full px-4 outline-none"
                  style={{ ...inputStyle, cursor: "pointer" }}
                >
                  {RULE_TRIGGERS.map((t) => <option key={t} value={t}>{TRIGGER_LABELS[t]}</option>)}
                </select>
              </div>

              {/* Condition builder */}
              <div>
                <FieldLabel>Conditions — when the trigger should match</FieldLabel>
                {form.conditionComplex && form.conditionLeaves.length === 0 && (
                  <div className="rounded-md p-2.5 mb-2" style={{ backgroundColor: "color-mix(in srgb, var(--chart-5) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--chart-5) 30%, transparent)" }}>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--chart-5)", lineHeight: 1.5 }}>
                      Current condition ({conditionSummary(form.conditionComplex)}) is more advanced than this builder supports.
                      It will stay unchanged unless you add conditions below.
                    </p>
                  </div>
                )}
                {form.conditionLeaves.length > 1 && (
                  <div className="flex items-center gap-2 mb-2">
                    <button
                      type="button"
                      onClick={() => setForm((f) => ({ ...f, conditionMode: "All" }))}
                      className="flex-1 rounded-md py-1.5 text-xs font-semibold"
                      style={{ backgroundColor: form.conditionMode === "All" ? "var(--primary)" : "transparent", color: form.conditionMode === "All" ? "var(--primary-foreground)" : "var(--muted-foreground)", border: "1px solid var(--border)", cursor: "pointer" }}
                    >
                      Match ALL
                    </button>
                    <button
                      type="button"
                      onClick={() => setForm((f) => ({ ...f, conditionMode: "Any" }))}
                      className="flex-1 rounded-md py-1.5 text-xs font-semibold"
                      style={{ backgroundColor: form.conditionMode === "Any" ? "var(--primary)" : "transparent", color: form.conditionMode === "Any" ? "var(--primary-foreground)" : "var(--muted-foreground)", border: "1px solid var(--border)", cursor: "pointer" }}
                    >
                      Match ANY
                    </button>
                  </div>
                )}
                <div className="flex flex-col gap-2">
                  {form.conditionLeaves.map((leaf, index) => (
                    <div key={index} className="flex items-center gap-2">
                      <select
                        value={leaf.type}
                        onChange={(event) => updateLeaf(index, { type: event.target.value as ConditionLeafType, value: defaultLeafValue(event.target.value as ConditionLeafType) })}
                        className="px-2 outline-none"
                        style={{ ...inputStyle, height: "40px", width: "42%", fontSize: "var(--text-xs)", cursor: "pointer" }}
                      >
                        {CONDITION_LEAF_TYPES.map((t) => <option key={t} value={t}>{LEAF_LABELS[t]}</option>)}
                      </select>
                      {leaf.type === "SeverityAtLeast" ? (
                        <select value={leaf.value} onChange={(event) => updateLeaf(index, { value: event.target.value })} className="flex-1 px-2 outline-none" style={{ ...inputStyle, height: "40px", fontSize: "var(--text-xs)", cursor: "pointer" }}>
                          {SEVERITY_LEVELS.map((s) => <option key={s} value={s}>{s}</option>)}
                        </select>
                      ) : leaf.type === "DeviceStatusIs" ? (
                        <select value={leaf.value} onChange={(event) => updateLeaf(index, { value: event.target.value })} className="flex-1 px-2 outline-none" style={{ ...inputStyle, height: "40px", fontSize: "var(--text-xs)", cursor: "pointer" }}>
                          {DEVICE_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                        </select>
                      ) : (
                        <input
                          value={leaf.value}
                          onChange={(event) => updateLeaf(index, { value: event.target.value })}
                          placeholder={leaf.type === "SignatureIdIn" || leaf.type === "PortIn" ? "e.g. 9999001, 9999002" : leaf.type === "SrcIpInCidr" ? "e.g. 203.0.113.0/24" : leaf.type === "CategoryIs" ? "e.g. malware" : "e.g. warehouse"}
                          className="flex-1 px-2 outline-none"
                          style={{ ...inputStyle, height: "40px", fontSize: "var(--text-xs)" }}
                        />
                      )}
                      <button type="button" onClick={() => removeLeaf(index)} style={{ background: "none", border: "none", cursor: "pointer", flexShrink: 0 }} aria-label="Remove condition">
                        <X size={15} style={{ color: "var(--muted-foreground)" }} />
                      </button>
                    </div>
                  ))}
                </div>
                <button
                  type="button"
                  onClick={addLeaf}
                  className="flex items-center gap-1.5 mt-2 text-xs font-medium"
                  style={{ background: "none", border: "none", cursor: "pointer", color: "var(--primary)" }}
                >
                  <Plus size={13} /> Add condition
                </button>
                {form.conditionLeaves.length === 0 && !form.conditionComplex && (
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "6px" }}>
                    No conditions — this rule matches every {TRIGGER_LABELS[form.trigger]} event.
                  </p>
                )}
              </div>

              {/* Actions */}
              <div>
                <FieldLabel>Actions — what happens when it matches</FieldLabel>
                <div className="flex flex-col gap-2">
                  {RULE_ACTION_TYPES.map((type) => {
                    const destructive = DESTRUCTIVE_ACTION_TYPES.includes(type);
                    return (
                      <div key={type}>
                        <label className="flex items-center gap-2" style={{ cursor: "pointer" }}>
                          <input type="checkbox" checked={form.actionsEnabled[type]} onChange={() => toggleAction(type)} style={{ width: "16px", height: "16px", accentColor: destructive ? "var(--destructive)" : "var(--primary)" }} />
                          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: destructive ? "var(--destructive)" : "var(--foreground)" }}>{ACTION_LABELS[type]}</span>
                          {destructive && <AlertTriangle size={12} style={{ color: "var(--destructive)" }} />}
                        </label>
                        {type === "RaiseAlert" && form.actionsEnabled.RaiseAlert && (
                          <select value={form.raiseSeverity} onChange={(event) => setForm((f) => ({ ...f, raiseSeverity: event.target.value }))} className="mt-1.5 ml-6 px-2 outline-none" style={{ ...inputStyle, height: "36px", fontSize: "var(--text-xs)", width: "calc(100% - 24px)", cursor: "pointer" }}>
                            {SEVERITY_LEVELS.map((s) => <option key={s} value={s}>{s}</option>)}
                          </select>
                        )}
                        {type === "Notify" && form.actionsEnabled.Notify && (
                          <select value={form.notifySeverity} onChange={(event) => setForm((f) => ({ ...f, notifySeverity: event.target.value }))} className="mt-1.5 ml-6 px-2 outline-none" style={{ ...inputStyle, height: "36px", fontSize: "var(--text-xs)", width: "calc(100% - 24px)", cursor: "pointer" }}>
                            {SEVERITY_LEVELS.map((s) => <option key={s} value={s}>{s}</option>)}
                          </select>
                        )}
                        {type === "BlockIp" && form.actionsEnabled.BlockIp && (
                          <input value={form.blockTtl} onChange={(event) => setForm((f) => ({ ...f, blockTtl: event.target.value.replace(/[^0-9]/g, "") }))} placeholder="TTL seconds (blank = until manually unblocked)" className="mt-1.5 ml-6 px-2 outline-none" style={{ ...inputStyle, height: "36px", fontSize: "var(--text-xs)", width: "calc(100% - 24px)" }} />
                        )}
                        {type === "RunScan" && form.actionsEnabled.RunScan && (
                          <select value={form.scanIntensity} onChange={(event) => setForm((f) => ({ ...f, scanIntensity: event.target.value }))} className="mt-1.5 ml-6 px-2 outline-none" style={{ ...inputStyle, height: "36px", fontSize: "var(--text-xs)", width: "calc(100% - 24px)", cursor: "pointer" }}>
                            {SCAN_INTENSITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                          </select>
                        )}
                      </div>
                    );
                  })}
                </div>
                {hasDestructiveSelected && (
                  <div className="rounded-md p-2.5 mt-2 flex items-start gap-2" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)" }}>
                    <AlertTriangle size={14} style={{ color: "var(--destructive)", flexShrink: 0, marginTop: "1px" }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--destructive)", lineHeight: 1.5 }}>
                      Destructive actions selected. Without "Allow destructive actions" below, they will be downgraded to a critical alert instead of executing.
                    </p>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between rounded-md p-3" style={{ border: "1px solid var(--border)" }}>
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>Also send a notification</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Appends a Notify action automatically if not already selected above</p>
                </div>
                <SmallSwitch checked={form.notify} onCheckedChange={() => setForm((f) => ({ ...f, notify: !f.notify }))} />
              </div>

              <div className="flex items-center justify-between rounded-md p-3" style={{ border: form.allowDestructive ? "1px solid color-mix(in srgb, var(--destructive) 40%, transparent)" : "1px solid var(--border)", backgroundColor: form.allowDestructive ? "color-mix(in srgb, var(--destructive) 6%, transparent)" : "transparent" }}>
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: form.allowDestructive ? "var(--destructive)" : "var(--foreground)" }}>Allow destructive actions</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Required for Revoke DID / Lock Transport / Emergency Key Rotation to actually run</p>
                </div>
                <SmallSwitch checked={form.allowDestructive} onCheckedChange={() => setForm((f) => ({ ...f, allowDestructive: !f.allowDestructive }))} />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel>Cooldown (seconds)</FieldLabel>
                  <input value={form.cooldownSecs} onChange={(event) => setForm((f) => ({ ...f, cooldownSecs: event.target.value.replace(/[^0-9]/g, "") }))} placeholder="300" className="w-full px-4 outline-none" style={inputStyle} />
                </div>
                <div>
                  <FieldLabel>Max actions / hour</FieldLabel>
                  <input value={form.maxActionsPerHour} onChange={(event) => setForm((f) => ({ ...f, maxActionsPerHour: event.target.value.replace(/[^0-9]/g, "") }))} placeholder="20" className="w-full px-4 outline-none" style={inputStyle} />
                </div>
              </div>
            </div>

            <div className="flex gap-3 px-5 py-4 border-t border-border flex-shrink-0">
              <button
                onClick={() => setSheetOpen(false)}
                className="flex-1 flex items-center justify-center rounded-md"
                style={{ height: "46px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
              >
                Cancel
              </button>
              <button
                onClick={() => void handleSave()}
                disabled={saving}
                className="flex-1 flex items-center justify-center gap-2 rounded-md disabled:opacity-60"
                style={{ height: "46px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
              >
                {saving ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />}
                {editingRule ? "Save Changes" : "Create Rule"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
