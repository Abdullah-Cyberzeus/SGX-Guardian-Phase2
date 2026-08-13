import { WifiOff } from "lucide-react";

interface OfflineBannerProps { lastSeen?: number; }

export function OfflineBanner({ lastSeen }: OfflineBannerProps) {
  const label = lastSeen ? new Date(lastSeen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "unknown";
  return (
    <div
      className="flex items-center gap-2 px-4 py-2"
      style={{
        backgroundColor: "color-mix(in srgb, var(--chart-5) 20%, var(--background))",
        borderBottom: "1px solid color-mix(in srgb, var(--chart-5) 40%, transparent)",
      }}
    >
      <WifiOff size={14} style={{ color: "var(--chart-5)", flexShrink: 0 }} />
      <span
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-medium)",
          color: "var(--chart-5)",
        }}
      >
        Guardian unreachable — cached data only · last reached {label}
      </span>
    </div>
  );
}
