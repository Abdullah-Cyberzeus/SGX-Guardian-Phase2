import { useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import { mockAlertRules } from "../../data/mockData";
import { Plus, Trash2, X } from "lucide-react";
import * as Switch from "@radix-ui/react-switch";
import { StatusBadge } from "../../components/SeverityBadge";

export function ST12AlertRules() {
  const [rules, setRules] = useState(mockAlertRules);
  const [createOpen, setCreateOpen] = useState(false);
  const [newRule, setNewRule] = useState({
    name: "",
    event: "Authentication Failure",
    condition: "",
    action: "Send Alert",
    notify: "",
  });

  const toggleRule = (id: string) =>
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );

  const deleteRule = (id: string) =>
    setRules((prev) => prev.filter((r) => r.id !== id));

  const handleCreate = () => {
    if (!newRule.name) return;
    setRules((prev) => [
      ...prev,
      {
        id: `rule_${Date.now()}`,
        ...newRule,
        enabled: true,
      },
    ]);
    setCreateOpen(false);
    setNewRule({
      name: "",
      event: "Authentication Failure",
      condition: "",
      action: "Send Alert",
      notify: "",
    });
  };

  const eventOptions = [
    "Authentication Failure",
    "USB Device Connected",
    "Malware Detected",
    "Network Anomaly",
    "New Device Discovered",
    "Firmware Change",
  ];

  const actionOptions = [
    "Send Alert",
    "Block Device",
    "Quarantine Device",
    "Isolate Network Segment",
    "Notify Circle",
  ];

  return (
    <>
      <div className="flex flex-col h-full">
        <PageHeader title="Custom Alert Rules" />
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4 pb-8">
          <div
            className="rounded-lg border p-4"
            style={{
              backgroundColor:
                "color-mix(in srgb, var(--primary) 5%, var(--card))",
              borderColor:
                "color-mix(in srgb, var(--primary) 20%, transparent)",
            }}
          >
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--primary)",
                marginBottom: "4px",
              }}
            >
              Custom Alert Rules
            </p>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
                lineHeight: 1.6,
              }}
            >
              Define automated responses to security events. Rules run on your
              Guardian — no cloud required.
            </p>
          </div>

          <button
            onClick={() => setCreateOpen(true)}
            className="w-full flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
            style={{
              height: "48px",
              backgroundColor: "var(--primary)",
              color: "var(--primary-foreground)",
              border: "none",
              cursor: "pointer",
              borderRadius: "var(--radius)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
            }}
          >
            <Plus size={16} /> Create Rule
          </button>

          <div className="flex flex-col gap-3">
            {rules.map((rule) => (
              <div
                key={rule.id}
                className="rounded-lg border border-border p-4"
                style={{ backgroundColor: "var(--card)" }}
              >
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <p
                        style={{
                          fontFamily: "Inter, sans-serif",
                          fontSize: "var(--text-sm)",
                          fontWeight: "var(--font-weight-semibold)",
                          color: "var(--foreground)",
                        }}
                      >
                        {rule.name}
                      </p>
                      <StatusBadge
                        status={rule.enabled ? "Active" : "Disabled"}
                        variant={rule.enabled ? "success" : "muted"}
                      />
                    </div>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-xs)",
                        color: "var(--muted-foreground)",
                        marginBottom: "2px",
                      }}
                    >
                      When: {rule.event}
                    </p>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-xs)",
                        color: "var(--muted-foreground)",
                        marginBottom: "2px",
                      }}
                    >
                      If: {rule.condition}
                    </p>
                    <p
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-xs)",
                        color: "var(--muted-foreground)",
                      }}
                    >
                      Then: {rule.action} → {rule.notify}
                    </p>
                  </div>
                </div>
                <div
                  className="flex items-center justify-between pt-3"
                  style={{ borderTop: "1px solid var(--border)" }}
                >
                  <Switch.Root
                    checked={rule.enabled}
                    onCheckedChange={() => toggleRule(rule.id)}
                    style={{
                      width: "44px",
                      height: "24px",
                      borderRadius: "12px",
                      backgroundColor: rule.enabled
                        ? "var(--primary)"
                        : "var(--muted)",
                      border: "none",
                      cursor: "pointer",
                      position: "relative",
                      transition: "background-color 0.2s",
                    }}
                  >
                    <Switch.Thumb
                      style={{
                        display: "block",
                        width: "18px",
                        height: "18px",
                        borderRadius: "50%",
                        backgroundColor: "white",
                        transform: rule.enabled
                          ? "translateX(22px)"
                          : "translateX(3px)",
                        transition: "transform 0.2s",
                      }}
                    />
                  </Switch.Root>
                  <button
                    onClick={() => deleteRule(rule.id)}
                    style={{
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      padding: "8px",
                    }}
                  >
                    <Trash2
                      size={16}
                      style={{ color: "var(--muted-foreground)" }}
                    />
                  </button>
                </div>
              </div>
            ))}
          </div>
          </div>
        </div>
      </div>

      {/* Create Rule Sheet */}
      {createOpen && (
        <div
          className="fixed inset-0 z-50 flex items-end md:items-center justify-center cursor-pointer"
          style={{
            backgroundColor: "rgba(0,0,0,0.6)",
            maxWidth: "440px",
            margin: "0 auto",
          }}
          onClick={() => setCreateOpen(false)}
        >
          <div
            className="w-full rounded-t-xl md:rounded-xl border-t md:border border-border"
            style={{
              backgroundColor: "var(--card)",
              maxHeight: "90dvh",
              display: "flex",
              flexDirection: "column",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-border flex-shrink-0">
              <h3
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-base)",
                  fontWeight: "var(--font-weight-semibold)",
                  color: "var(--foreground)",
                }}
              >
                Create Alert Rule
              </h3>
              <button
                onClick={() => setCreateOpen(false)}
                style={{ background: "none", border: "none", cursor: "pointer" }}
              >
                <X size={20} style={{ color: "var(--muted-foreground)" }} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">
              {[{ key: "name", label: "Rule Name", placeholder: "e.g. Block on 5 Failed Logins" }].map(
                ({ key, label, placeholder }) => (
                  <div key={key}>
                    <label
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-xs)",
                        fontWeight: "var(--font-weight-medium)",
                        color: "var(--muted-foreground)",
                        marginBottom: "6px",
                        display: "block",
                      }}
                    >
                      {label} <span style={{ color: "var(--destructive)" }}>*</span>
                    </label>
                    <input
                      value={(newRule as any)[key]}
                      onChange={(e) =>
                        setNewRule((r) => ({ ...r, [key]: e.target.value }))
                      }
                      placeholder={placeholder}
                      className="w-full px-4 outline-none"
                      style={{
                        height: "48px",
                        backgroundColor: "var(--input-background)",
                        border: "1.5px solid var(--border)",
                        borderRadius: "var(--radius)",
                        color: "var(--foreground)",
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-sm)",
                      }}
                    />
                  </div>
                )
              )}
              {[
                {
                  key: "event",
                  label: "Event Trigger",
                  options: eventOptions,
                },
                {
                  key: "action",
                  label: "Action",
                  options: actionOptions,
                },
              ].map(({ key, label, options }) => (
                <div key={key}>
                  <label
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      fontWeight: "var(--font-weight-medium)",
                      color: "var(--muted-foreground)",
                      marginBottom: "6px",
                      display: "block",
                    }}
                  >
                    {label}
                  </label>
                  <select
                    value={(newRule as any)[key]}
                    onChange={(e) =>
                      setNewRule((r) => ({ ...r, [key]: e.target.value }))
                    }
                    className="w-full px-4 outline-none"
                    style={{
                      height: "48px",
                      backgroundColor: "var(--input-background)",
                      border: "1.5px solid var(--border)",
                      borderRadius: "var(--radius)",
                      color: "var(--foreground)",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      cursor: "pointer",
                    }}
                  >
                    {options.map((o) => (
                      <option key={o} value={o}>
                        {o}
                      </option>
                    ))}
                  </select>
                </div>
              ))}
              {[
                {
                  key: "condition",
                  label: "Condition",
                  placeholder: "e.g. count >= 5",
                },
                {
                  key: "notify",
                  label: "Notify",
                  placeholder: "e.g. SOC Team via Push",
                },
              ].map(({ key, label, placeholder }) => (
                <div key={key}>
                  <label
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      fontWeight: "var(--font-weight-medium)",
                      color: "var(--muted-foreground)",
                      marginBottom: "6px",
                      display: "block",
                    }}
                  >
                    {label}
                  </label>
                  <input
                    value={(newRule as any)[key]}
                    onChange={(e) =>
                      setNewRule((r) => ({ ...r, [key]: e.target.value }))
                    }
                    placeholder={placeholder}
                    className="w-full px-4 outline-none"
                    style={{
                      height: "48px",
                      backgroundColor: "var(--input-background)",
                      border: "1.5px solid var(--border)",
                      borderRadius: "var(--radius)",
                      color: "var(--foreground)",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                    }}
                  />
                </div>
              ))}
            </div>
            <div className="flex gap-3 px-5 py-4 border-t border-border flex-shrink-0">
              <button
                onClick={() => setCreateOpen(false)}
                className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80"
                style={{
                  height: "48px",
                  backgroundColor: "var(--secondary)",
                  color: "var(--secondary-foreground)",
                  border: "1px solid var(--border)",
                  cursor: "pointer",
                  borderRadius: "var(--radius)",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80"
                style={{
                  height: "48px",
                  backgroundColor: newRule.name ? "var(--primary)" : "var(--muted)",
                  color: newRule.name
                    ? "var(--primary-foreground)"
                    : "var(--muted-foreground)",
                  border: "none",
                  cursor: "pointer",
                  borderRadius: "var(--radius)",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                }}
              >
                Create Rule
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
