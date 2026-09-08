import { useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import { ChevronDown, ChevronRight } from "lucide-react";

const steps = [
  {
    title: "1. Pair Your Guardian",
    content:
      "Power on your Guardian device. Open the app and tap 'Pair Device'. Scan the QR code on the bottom of the device or enter the serial number manually. Wait for the pairing animation to complete.",
  },
  {
    title: "2. Create Your Account",
    content:
      "Set up your secure account with a strong password. Your password is stored encrypted on your Guardian — Cervais never sees it. You'll be assigned a unique DID (Decentralized Identifier) that acts as your cryptographic identity.",
  },
  {
    title: "3. Create or Join a Circle",
    content:
      "A Circle of Trust is your secure team group. Create one and share the invite code with your teammates. All communication within a Circle is end-to-end encrypted and routed through your Guardian — not Cervais servers.",
  },
  {
    title: "4. Monitor Alerts",
    content:
      "The Alerts tab shows real-time security events from your network. Tap any alert to see the analysis, affected device details, and recommended remediation steps.",
  },
  {
    title: "5. Manage Your Devices",
    content:
      "The Devices tab lists all devices on your network. Tap a device to see its security score, vulnerabilities, and run a full security scan. Approve or reject unknown devices from the Pending Approvals filter.",
  },
  {
    title: "6. Use the Network Topology",
    content:
      "The Network Topology view shows a live visual map of all Guardian peers and connected devices. Tap any node for details. This is especially useful for understanding your exposure surface.",
  },
  {
    title: "7. Set Up Notifications",
    content:
      "Go to Settings → Notifications to configure which events trigger push notifications. We recommend enabling HIGH severity alerts, device pending approval, and Guardian offline at a minimum.",
  },
];

export function ST14QuickStartGuide() {
  const [expanded, setExpanded] = useState<number | null>(0);

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Quick Start Guide" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-3 pb-8">
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
            lineHeight: 1.65,
            marginBottom: "4px",
          }}
        >
          Follow these steps to get your Guardian fully set up and monitoring
          your network.
        </p>
        {steps.map((step, i) => {
          const isExpanded = expanded === i;
          return (
            <div
              key={i}
              className="rounded-lg border border-border overflow-hidden"
              style={{ backgroundColor: "var(--card)" }}
            >
              <button
                onClick={() => setExpanded(isExpanded ? null : i)}
                className="w-full flex items-center justify-between px-4 py-4 text-left transition-opacity active:opacity-70"
                style={{
                  backgroundColor: "transparent",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                <span
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-semibold)",
                    color: isExpanded ? "var(--primary)" : "var(--foreground)",
                  }}
                >
                  {step.title}
                </span>
                {isExpanded ? (
                  <ChevronDown
                    size={16}
                    style={{ color: "var(--muted-foreground)", flexShrink: 0 }}
                  />
                ) : (
                  <ChevronRight
                    size={16}
                    style={{ color: "var(--muted-foreground)", flexShrink: 0 }}
                  />
                )}
              </button>
              {isExpanded && (
                <div
                  className="px-4 pb-4 pt-1"
                  style={{ borderTop: "1px solid var(--border)" }}
                >
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      color: "var(--muted-foreground)",
                      lineHeight: 1.7,
                    }}
                  >
                    {step.content}
                  </p>
                </div>
              )}
            </div>
          );
        })}
        </div>
      </div>
    </div>
  );
}
