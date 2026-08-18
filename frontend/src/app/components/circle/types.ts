// Shared types & helpers for the Circle communications feature
// (voice/video calls, chat attachments, file sharing). Frontend-only.

export type CallMode = "voice" | "video";
export type CallPhase = "connecting" | "ongoing" | "ended";

/** Result handed back to the Circle screen when a call ends. */
export interface CallRecord {
  type: CallMode;
  participant: string;
  duration: string;
}

/** Metadata for a file/image attached to a chat message. */
export interface AttachmentMeta {
  attachmentId?: string;
  name: string;
  sizeBytes: number;
  mime: string;
  kind: "image" | "file";
  /** Object URL (or data URI for seeds) — valid for this session only. */
  url: string;
}

/** A file shared in the chat, surfaced in the Files tab. */
export interface SharedFile {
  attachmentId?: string;
  id: string;
  name: string;
  sizeBytes: number;
  mime: string;
  kind: "image" | "file";
  url: string;
  sharedBy: string;
  sharedAt: string;
}

/** Format a byte count into a short human string, e.g. "1.3 MB". */
export function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / Math.pow(1024, i);
  return `${i === 0 ? value : value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

/** Two-letter uppercase initials from a person's name. */
export function initialsOf(name: string): string {
  return name
    .trim()
    .split(/\s+/)
    .map((p) => p[0] ?? "")
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

/**
 * Pull every attachment out of a chat message list — newest first.
 * The Files tab is purely a view over what was shared in the chat.
 */
export function collectSharedFiles(messages: any[]): SharedFile[] {
  return messages
    .filter((m) => m && m.attachment)
    .map((m) => ({
      id: m.id,
      attachmentId: m.attachment.attachmentId,
      name: m.attachment.name,
      sizeBytes: m.attachment.sizeBytes,
      mime: m.attachment.mime,
      kind: m.attachment.kind,
      url: m.attachment.url,
      sharedBy: m.isMe ? "You" : m.sender,
      sharedAt: m.timestamp,
    }))
    .reverse();
}
