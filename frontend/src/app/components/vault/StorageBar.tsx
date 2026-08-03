import { HardDrive } from "lucide-react";
import { Progress } from "../ui/progress";
import { formatBytes } from "./types";

interface StorageBarProps {
  usedBytes: number;
  capacityBytes: number;
}

/** Slim on-device storage meter — pinned to the bottom of the file browser. */
export function StorageBar({ usedBytes, capacityBytes }: StorageBarProps) {
  const pct =
    capacityBytes > 0 ? Math.min(100, (usedBytes / capacityBytes) * 100) : 0;
  const almostFull = pct >= 90;

  return (
    <div className="flex flex-shrink-0 items-center gap-3 border-t border-border px-4 py-2.5">
      <HardDrive size={15} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
      <span
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          color: "var(--muted-foreground)",
          whiteSpace: "nowrap",
        }}
      >
        {formatBytes(usedBytes)} of {formatBytes(capacityBytes)} used
      </span>

      <div style={{ width: "140px" }} className="flex-shrink-0">
        <Progress value={pct} className="h-1.5" />
      </div>

      <span
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-semibold)",
          color: almostFull ? "var(--destructive)" : "var(--muted-foreground)",
          whiteSpace: "nowrap",
        }}
      >
        {Math.round(pct)}%
      </span>
    </div>
  );
}
