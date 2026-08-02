interface ProgressDotsProps {
  total: number;
  current: number; // 1-based
}

export function ProgressDots({ total, current }: ProgressDotsProps) {
  return (
    <div className="flex items-center justify-center gap-2">
      {Array.from({ length: total }, (_, i) => (
        <div
          key={i}
          style={{
            width: i + 1 === current ? "20px" : "6px",
            height: "6px",
            borderRadius: "3px",
            backgroundColor: i + 1 === current ? "var(--primary)" : "var(--border)",
            transition: "all 0.2s ease",
          }}
        />
      ))}
    </div>
  );
}
