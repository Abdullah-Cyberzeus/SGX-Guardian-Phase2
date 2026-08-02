import { useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import { mockNotificationPrefs } from "../../data/mockData";
import * as Switch from "@radix-ui/react-switch";

interface PrefRow {
  key: keyof typeof mockNotificationPrefs;
  label: string;
  description?: string;
}

const groups: { heading: string; rows: PrefRow[] }[] = [
  {
    heading: "Alerts",
    rows: [
      { key: "alertHigh", label: "High-severity alerts", description: "Immediate push when a HIGH alert fires" },
      { key: "alertMedium", label: "Medium-severity alerts" },
      { key: "alertLow", label: "Low-severity alerts" },
    ],
  },
  {
    heading: "Devices",
    rows: [
      { key: "deviceNewDiscovered", label: "New device discovered" },
      { key: "devicePendingApproval", label: "Device pending approval" },
      { key: "deviceGuardianOffline", label: "Guardian offline" },
    ],
  },
  {
    heading: "Circles",
    rows: [
      { key: "circleMessages", label: "New messages" },
      { key: "circleCalls", label: "Incoming calls" },
      { key: "circleMemberJoined", label: "Member joined circle" },
    ],
  },
];

export function ST11Notifications() {
  const [prefs, setPrefs] =
    useState<typeof mockNotificationPrefs>(mockNotificationPrefs);

  const toggle = (key: keyof typeof prefs) =>
    setPrefs((p) => ({ ...p, [key]: !p[key] }));

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
            <div
              className="rounded-lg border border-border overflow-hidden"
              style={{ backgroundColor: "var(--card)" }}
            >
              {group.rows.map(({ key, label, description }, i) => (
                <div
                  key={key}
                  className="flex items-center justify-between px-4 py-4"
                  style={{
                    borderBottom:
                      i < group.rows.length - 1
                        ? "1px solid var(--border)"
                        : undefined,
                  }}
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
                    checked={prefs[key]}
                    onCheckedChange={() => toggle(key)}
                    style={{
                      width: "44px",
                      height: "24px",
                      borderRadius: "12px",
                      backgroundColor: prefs[key]
                        ? "var(--primary)"
                        : "var(--muted)",
                      border: "none",
                      cursor: "pointer",
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
                        transform: prefs[key]
                          ? "translateX(22px)"
                          : "translateX(3px)",
                        transition: "transform 0.2s",
                      }}
                    />
                  </Switch.Root>
                </div>
              ))}
            </div>
          </div>
        ))}
        </div>
      </div>
    </div>
  );
}
