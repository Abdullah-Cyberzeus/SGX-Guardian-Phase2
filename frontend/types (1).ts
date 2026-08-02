type Severity = "HIGH" | "MEDIUM" | "LOW";

interface SeverityBadgeProps {
  severity: Severity;
  size?: "sm" | "md";
}

const config: Record<Severity, { bg: string; text: string; label: string }> = {
  HIGH: {
    bg: "color-mix(in srgb, var(--destructive) 18%, transparent)",
    text: "var(--destructive)",
    label: "HIGH",
  },
  MEDIUM: {
    bg: "color-mix(in srgb, var(--chart-5) 18%, transparent)",
    text: "var(--chart-5)",
    label: "MED",
  },
  LOW: {
    bg: "color-mix(in srgb, var(--muted-foreground) 15%, transparent)",
    text: "var(--muted-foreground)",
    label: "LOW",
  },
};

export function SeverityBadge({ severity, size = "sm" }: SeverityBadgeProps) {
  const c = config[severity];
  return (
    <span
      className="inline-flex items-center rounded"
      style={{
        backgroundColor: c.bg,
        color: c.text,
        fontFamily: "Inter, sans-serif",
        fontSize: size === "sm" ? "10px" : "var(--text-xs)",
        fontWeight: "var(--font-weight-semibold)",
        letterSpacing: "0.06em",
        padding: size === "sm" ? "2px 6px" : "3px 8px",
        borderRadius: "var(--radius-sm)",
        border: `1px solid color-mix(in srgb, ${c.text} 30%, transparent)`,
        flexShrink: 0,
      }}
    >
      {c.label}
    </span>
  );
}

interface StatusBadgeProps {
  status: string;
  variant?: "success" | "warning" | "danger" | "muted" | "info";
}

export function StatusBadge({ status, variant = "muted" }: StatusBadgeProps) {
  const colors: Record<string, { bg: string; text: string }> = {
    success: { bg: "color-mix(in srgb, var(--chart-2) 15%, transparent)", text: "var(--chart-2)" },
    warning: { bg: "color-mix(in srgb, var(--chart-5) 15%, transparent)", text: "var(--chart-5)" },
    danger: { bg: "color-mix(in srgb, var(--destructive) 15%, transparent)", text: "var(--destructive)" },
    muted: { bg: "color-mix(in srgb, var(--muted-foreground) 12%, transparent)", text: "var(--muted-foreground)" },
    info: { bg: "color-mix(in srgb, var(--primary) 15%, transparent)", text: "var(--primary)" },
  };
  const c = colors[variant];
  return (
    <span
      className="inline-flex items-center rounded"
      style={{
        backgroundColor: c.bg,
        color: c.text,
        fontFamily: "Inter, sans-serif",
        fontSize: "10px",
        fontWeight: "var(--font-weight-semibold)",
        letterSpacing: "0.04em",
        padding: "2px 7px",
        borderRadius: "var(--radius-sm)",
        border: `1px solid color-mix(in srgb, ${c.text} 25%, transparent)`,
        flexShrink: 0,
        whiteSpace: "nowrap",
      }}
    >
      {status}
    </span>
  );
}
