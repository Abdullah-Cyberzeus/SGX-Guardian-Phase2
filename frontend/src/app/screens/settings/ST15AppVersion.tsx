import { PageHeader } from "../../components/PageHeader";
import { CervaisLogo } from "../../components/CervaisLogo";
import { Check } from "lucide-react";

const changelog = [
  {
    version: "v2.4.1",
    date: "March 17, 2026",
    current: true,
    changes: [
      "AI threat analysis now includes APT technique mapping",
      "Improved DID verification latency",
      "Fixed: Circle chat history loading on slow networks",
      "Guardian battery reporting precision improved",
    ],
  },
  {
    version: "v2.4.0",
    date: "March 1, 2026",
    current: false,
    changes: [
      "Added Smart Home Integration hub support",
      "Dual Wi-Fi mode is now generally available",
      "Custom Alert Rules engine introduced",
      "New network topology interactive view",
    ],
  },
  {
    version: "v2.3.0",
    date: "February 12, 2026",
    current: false,
    changes: [
      "End-to-end encrypted voice calls in Circles",
      "Geofencing zones now support polygon shapes",
      "Device security score redesigned",
    ],
  },
];

export function ST15AppVersion() {
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="App Version" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5 pb-8">
        {/* Version card */}
        <div
          className="flex flex-col items-center py-6 rounded-lg border border-border"
          style={{ backgroundColor: "var(--card)" }}
        >
          <CervaisLogo width={120} />
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-base)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
              marginTop: "12px",
              marginBottom: "2px",
            }}
          >
            SG-X Guardian
          </p>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            Version 2.4.1 · Build 2026.03.17
          </p>
          <div
            className="flex items-center gap-1.5 mt-3 px-3 py-1.5 rounded-full"
            style={{
              backgroundColor:
                "color-mix(in srgb, var(--chart-2) 15%, transparent)",
              border:
                "1px solid color-mix(in srgb, var(--chart-2) 30%, transparent)",
            }}
          >
            <Check size={12} style={{ color: "var(--chart-2)" }} />
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-medium)",
                color: "var(--chart-2)",
              }}
            >
              Up to date
            </span>
          </div>
        </div>

        {/* Changelog */}
        <div>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--muted-foreground)",
              letterSpacing: "0.08em",
              marginBottom: "10px",
              paddingLeft: "4px",
            }}
          >
            Changelog
          </p>
          <div className="flex flex-col gap-3">
            {changelog.map((entry) => (
              <div
                key={entry.version}
                className="rounded-lg border border-border p-4"
                style={{
                  backgroundColor: entry.current
                    ? "color-mix(in srgb, var(--primary) 5%, var(--card))"
                    : "var(--card)",
                  borderColor: entry.current
                    ? "color-mix(in srgb, var(--primary) 25%, transparent)"
                    : "var(--border)",
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span
                      style={{
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-sm)",
                        fontWeight: "var(--font-weight-semibold)",
                        color: entry.current
                          ? "var(--primary)"
                          : "var(--foreground)",
                      }}
                    >
                      {entry.version}
                    </span>
                    {entry.current && (
                      <span
                        className="px-2 py-0.5 rounded-full"
                        style={{
                          backgroundColor:
                            "color-mix(in srgb, var(--primary) 15%, transparent)",
                          color: "var(--primary)",
                          fontFamily: "Inter, sans-serif",
                          fontSize: "10px",
                          fontWeight: "var(--font-weight-semibold)",
                        }}
                      >
                        Current
                      </span>
                    )}
                  </div>
                  <span
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                    }}
                  >
                    {entry.date}
                  </span>
                </div>
                <div className="flex flex-col gap-1.5">
                  {entry.changes.map((change) => (
                    <div key={change} className="flex items-start gap-2">
                      <div
                        style={{
                          width: "5px",
                          height: "5px",
                          borderRadius: "50%",
                          backgroundColor: entry.current
                            ? "var(--primary)"
                            : "var(--muted-foreground)",
                          marginTop: "6px",
                          flexShrink: 0,
                        }}
                      />
                      <p
                        style={{
                          fontFamily: "Inter, sans-serif",
                          fontSize: "var(--text-xs)",
                          color: "var(--muted-foreground)",
                          lineHeight: 1.5,
                        }}
                      >
                        {change}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Legal */}
        <div className="text-center">
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
              lineHeight: 1.5,
            }}
          >
            © 2026 Cervais Inc. All rights reserved.
            <br />
            Patents pending. SG-X is a trademark of Cervais Inc.
          </p>
        </div>
        </div>
      </div>
    </div>
  );
}