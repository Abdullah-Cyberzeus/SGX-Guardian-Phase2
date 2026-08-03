import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { useNotifications } from "../../contexts/NotificationContext";
import type { NotificationPrefs } from "../../../api/notifications";
import * as Switch from "@radix-ui/react-switch";

type PrefCategory = "alerts" | "devices" | "circles";

interface PrefRow {
  field: string;
  label: string;
  description?: string;
}

const groups: { heading: string; category: PrefCategory; rows: PrefRow[] }[] = [
  {
    heading: "Alerts",
    category: "alerts",
    rows: [
      { field: "high", label: "High-severity alerts", description: "Immediate push when a HIGH alert fires" },
      { field: "medium", label: "Medium-severity alerts" },
      { field: "low", label: "Low-severity alerts" },
    ],
  },
  {
    heading: "Devices",
    category: "devices",
    rows: [
      { field: "new_device", label: "New device discovered" },
      { field: "pending_approval", label: "Device pending approval" },
      { field: "guardian_offline", label: "Guardian offline" },
    ],
  },
  {
    heading: "Circles",
    category: "circles",
    rows: [
      { field: "new_message", label: "New messages" },
      { field: "incoming_call", label: "Incoming calls" },
      { field: "member_joined", label: "Member joined circle" },
    ],
  },
];

export function ST11Notifications() {
  const { prefs, refresh, updatePrefs } = useNotifications();
  const [loading, setLoading] = useState(!prefs);
  const [savingKey, setSavingKey] = useState<string | null>(null);

  useEffect(() => {
    if (prefs) {
      setLoading(false);
      return;
    }
    refresh()
      .catch((e) => toast.error(e instanceof Error ? e.message : "Failed to load notification preferences"))
      .finally(() => setLoading(false));
  }, [prefs, refresh]);

  const toggle = async (category: PrefCategory, field: string) => {
    if (!prefs) return;
    const currentValue = (prefs[category] as Record<string, boolean>)[field];
    const key = `${category}.${field}`;
    setSavingKey(key);
    try {
      await updatePrefs({ [category]: { ...prefs[category], [field]: !currentValue } } as Partial<NotificationPrefs>);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to update preference");
      refresh().catch(() => undefined);
    } finally {
      setSavingKey(null);
    }
  };

  if (loading || !prefs) {
    return (
      <div className="flex flex-col h-full">
        <PageHeader title="Notification Preferences" />
        <div className="flex-1 flex items-center justify-center">
          <Loader2 className="animate-spin" size={24} style={{ color: "var(--primary)" }} />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Notification Preferences" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5 pb-8">
          {groups.map((group) => (
            <div key={group.heading}>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-semibold)",
                  color: "var(--muted-foreground)",
                  letterSpacing: "0.08em",
                  marginBottom: "8px",
                  paddingLeft: "4px",
                }}
              >
                {group.heading}
              </p>
              <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                {group.rows.map(({ field, label, description }, i) => {
                  const checked = Boolean((prefs[group.category] as Record<string, boolean>)[field]);
                  const key = `${group.category}.${field}`;
                  const saving = savingKey === key;
                  return (
                    <div
                      key={field}
                      className="flex items-center justify-between px-4 py-4"
                      style={{ borderBottom: i < group.rows.length - 1 ? "1px solid var(--border)" : undefined }}
                    >
                      <div className="flex-1 pr-4">
                        <p
                          style={{
                            fontFamily: "Inter, sans-serif",
                            fontSize: "var(--text-sm)",
                            color: "var(--foreground)",
                            fontWeight: "var(--font-weight-medium)",
                          }}
                        >
                          {label}
                        </p>
                        {description && (
                          <p
                            style={{
                              fontFamily: "Inter, sans-serif",
                              fontSize: "var(--text-xs)",
                              color: "var(--muted-foreground)",
                              marginTop: "2px",
                            }}
                          >
                            {description}
                          </p>
                        )}
                      </div>
                      <Switch.Root
                        checked={checked}
                        disabled={saving}
                        onCheckedChange={() => toggle(group.category, field)}
                        style={{
                          width: "44px",
                          height: "24px",
                          borderRadius: "12px",
                          backgroundColor: checked ? "var(--primary)" : "var(--muted)",
                          border: "none",
                          cursor: saving ? "wait" : "pointer",
                          opacity: saving ? 0.6 : 1,
                          position: "relative",
                          flexShrink: 0,
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
                            transform: checked ? "translateX(22px)" : "translateX(3px)",
                            transition: "transform 0.2s",
                          }}
                        />
                      </Switch.Root>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
