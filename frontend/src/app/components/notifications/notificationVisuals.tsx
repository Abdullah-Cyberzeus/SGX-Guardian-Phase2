import { AlertTriangle, ShieldAlert, Cpu, WifiOff, MessageCircle, PhoneIncoming, UserPlus, FileText, Bell } from "lucide-react";
import type { ComponentType } from "react";

export function notificationIcon(kind: string): ComponentType<{ size?: number }> {
  if (kind === "AlertHigh") return ShieldAlert;
  if (kind.startsWith("Alert")) return AlertTriangle;
  if (kind === "DeviceDiscovered" || kind === "DevicePendingApproval") return Cpu;
  if (kind === "GuardianOffline") return WifiOff;
  if (kind === "CircleNewMessage") return MessageCircle;
  if (kind === "CircleIncomingCall") return PhoneIncoming;
  if (kind === "CircleMemberJoined") return UserPlus;
  if (kind === "CircleFileShared") return FileText;
  return Bell;
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "critical":
    case "high":
      return "var(--destructive)";
    case "medium":
      return "var(--chart-5)";
    case "low":
      return "var(--chart-2)";
    default:
      return "var(--primary)";
  }
}

/** Best-effort deep-link for a notification's ref_id; null means "open the panel only". */
export function notificationRoute(kind: string, refId?: string): string | null {
  if (kind === "GuardianOffline") return "/home";
  if (!refId) return null;
  if (kind.startsWith("Alert")) return `/alerts/${refId}`;
  if (kind === "DeviceDiscovered" || kind === "DevicePendingApproval") return `/devices/${refId}`;
  if (kind.startsWith("Circle")) return `/network/${refId}`;
  return null;
}

export function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const diffSec = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (diffSec < 5) return "now";
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}
