import { AlertTriangle, ShieldAlert, Cpu, WifiOff, MessageCircle, PhoneIncoming, UserPlus, FileText, Bell } from "lucide-react";
import type { ComponentType } from "react";

export function notificationIcon(kind: string): ComponentType<{ size?: number }> {
  if (kind === "AlertHigh") return ShieldAlert;
  if (kind.startsWith("Alert")) return AlertTriangle;
  if (kind === "DeviceDiscovered" || kind === "DevicePendingApproval") return Cpu;
  if (kind === "GuardianOffline") return WifiOff;
  if (kind === "CircleNewMessage") return MessageCircle;
  if (kind === "CircleIncomingCall") return PhoneIncoming;
  if (kind === "CircleMemberPendingApproval" || kind === "CircleMemberJoined") return UserPlus;
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
  // Communication notification refIds are object IDs, not universally Circle
  // IDs: messages carry message IDs, calls carry session IDs, and files carry
  // vault IDs. Route those kinds to their owning screens instead of attempting
  // to load a Circle whose ID can never match.
  if (kind === "CircleNewMessage") return "/chats";
  if (kind === "CircleIncomingCall") return "/calls";
  if (kind === "CircleFileShared") return "/storage";
  if (!refId) return null;
  const encodedRef = encodeURIComponent(refId);
  if (kind.startsWith("Alert")) return `/alerts/${encodedRef}`;
  if (kind === "DeviceDiscovered" || kind === "DevicePendingApproval") return `/devices/${encodedRef}`;
  if (kind === "CircleMemberPendingApproval") return `/network/${encodedRef}/manage`;
  if (kind === "CircleMemberJoined") return `/network/${encodedRef}?tab=members`;
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
