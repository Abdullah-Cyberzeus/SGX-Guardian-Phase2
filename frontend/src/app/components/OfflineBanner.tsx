import { WifiOff } from "lucide-react";

interface OfflineBannerProps {
  lastSeen?: string;
}

export function OfflineBanner({ lastSeen = "2 min ago" }: OfflineBannerProps) {
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
        Guardian offline — last seen {lastSeen}
      </span>
    </div>
  );
}
