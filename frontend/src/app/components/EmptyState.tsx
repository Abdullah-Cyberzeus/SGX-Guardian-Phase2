import { LucideIcon } from "lucide-react";

interface EmptyStateProps {
  icon: LucideIcon;
  heading: string;
  subtext: string;
  ctaLabel?: string;
  ctaAction?: () => void;
}

export function EmptyState({ icon: Icon, heading, subtext, ctaLabel, ctaAction }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center flex-1 px-8 py-16 text-center gap-3">
      <div
        className="rounded-full flex items-center justify-center mb-1"
        style={{
          width: "64px",
          height: "64px",
          backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)",
        }}
      >
        <Icon size={28} style={{ color: "var(--muted-foreground)" }} />
      </div>
      <h3 style={{ color: "var(--foreground)", fontFamily: "Inter, sans-serif" }}>{heading}</h3>
      <p style={{ color: "var(--muted-foreground)", fontFamily: "Inter, sans-serif", maxWidth: "240px" }}>{subtext}</p>
      {ctaLabel && ctaAction && (
        <button
          onClick={ctaAction}
          className="mt-2 px-6 rounded-md transition-opacity active:opacity-80"
          style={{
            height: "44px",
            backgroundColor: "var(--primary)",
            color: "var(--primary-foreground)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-medium)",
            borderRadius: "var(--radius)",
          }}
        >
          {ctaLabel}
        </button>
      )}
    </div>
  );
}
