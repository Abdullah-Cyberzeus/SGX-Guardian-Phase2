import { Loader2, RotateCw, ShieldAlert, WifiOff } from "lucide-react";

type OfflineBannerStatus = "reconnecting" | "guardian_offline" | "credential_revoked";

interface OfflineBannerProps {
  status: OfflineBannerStatus;
  lastSeen?: number;
  pendingCount: number;
  syncRunning: boolean;
  onRetry: () => void;
}

function lastSeenLabel(lastSeen?: number) {
  if (!lastSeen) return "last reached unknown";
  return `last reached ${new Date(lastSeen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

export function OfflineBanner({ status, lastSeen, pendingCount, syncRunning, onRetry }: OfflineBannerProps) {
  const revoked = status === "credential_revoked";
  const reconnecting = status === "reconnecting";
  const Icon = revoked ? ShieldAlert : reconnecting || syncRunning ? Loader2 : WifiOff;
  const message = revoked
    ? "Guardian credentials revoked"
    : reconnecting
      ? "Reconnecting to Guardian"
      : "Guardian unreachable";
  const detail = revoked
    ? "sign in again"
    : `${lastSeenLabel(lastSeen)}${pendingCount > 0 ? ` · ${pendingCount} pending` : ""}`;

  return (
    <div
      className="flex items-center justify-between gap-3 px-4 py-2"
      style={{
        backgroundColor: "color-mix(in srgb, var(--chart-5) 20%, var(--background))",
        borderBottom: "1px solid color-mix(in srgb, var(--chart-5) 40%, transparent)",
      }}
    >
      <div className="flex min-w-0 items-center gap-2">
        <Icon
          className={reconnecting || syncRunning ? "animate-spin" : undefined}
          size={14}
          style={{ color: "var(--chart-5)", flexShrink: 0 }}
        />
        <span
          className="min-w-0 truncate"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            fontWeight: "var(--font-weight-medium)",
            color: "var(--chart-5)",
          }}
        >
          {message} · {detail}
        </span>
      </div>
      {!revoked && (
        <button
          type="button"
          onClick={onRetry}
          disabled={syncRunning || reconnecting}
          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md"
          aria-label="Retry Guardian connection"
          title="Retry Guardian connection"
          style={{
            color: "var(--chart-5)",
            opacity: syncRunning || reconnecting ? 0.6 : 1,
            border: "1px solid color-mix(in srgb, var(--chart-5) 35%, transparent)",
          }}
        >
          <RotateCw size={14} />
        </button>
      )}
    </div>
  );
}
