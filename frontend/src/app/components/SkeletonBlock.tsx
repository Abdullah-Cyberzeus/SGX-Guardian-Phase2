interface SkeletonBlockProps {
  height?: number | string;
  width?: number | string;
  rounded?: "sm" | "md" | "lg" | "full";
  className?: string;
}

export function SkeletonBlock({
  height = 16,
  width = "100%",
  rounded = "md",
  className = "",
}: SkeletonBlockProps) {
  const radiusMap = {
    sm: "var(--radius-sm)",
    md: "var(--radius)",
    lg: "var(--radius-card)",
    full: "9999px",
  };
  return (
    <div
      className={`animate-pulse ${className}`}
      style={{
        height: typeof height === "number" ? `${height}px` : height,
        width: typeof width === "number" ? `${width}px` : width,
        borderRadius: radiusMap[rounded],
        backgroundColor: "var(--muted)",
      }}
    />
  );
}

export function SkeletonCard({ lines = 3 }: { lines?: number }) {
  return (
    <div
      className="p-4 rounded-lg border border-border"
      style={{ backgroundColor: "var(--card)" }}
    >
      <SkeletonBlock height={14} width="60%" className="mb-3" />
      {Array.from({ length: lines }).map((_, i) => (
        <SkeletonBlock key={i} height={12} width={i === lines - 1 ? "75%" : "100%"} className="mb-2" />
      ))}
    </div>
  );
}
