// Shared types & helpers for the All Files feature — a Google Drive / Dropbox
// style file browser backed by the SGX Guardian Vault API.

export type VaultFileKind = "image" | "document" | "media";
export type VaultFolderKind = "root" | "circle" | "system" | "user";

/** The root folder's fixed id. */
export const ROOT_ID = "root";

/** A folder in the file tree. */
export interface VaultFolder {
  id: string;
  name: string;
  /** Parent folder id — null only for the root. */
  parentId: string | null;
  kind: VaultFolderKind;
  /** Set when kind === "circle" — the Circle this folder mirrors. */
  circleId?: string;
  /** Backend namespace needed for folder mutations. */
  namespace?: string;
  createdBy: string;
  createdAt: string;
}

/** A single encrypted file stored on the device. */
export interface VaultFile {
  id: string;
  name: string;
  sizeBytes: number;
  mime: string;
  kind: VaultFileKind;
  /** Id of the folder this file lives in. */
  folderId: string;
  sharedBy: string;
  /** Human-readable timestamp shown in the UI, e.g. "Today 9:18 AM". */
  addedAt: string;
  /** Always true — every file is encrypted at rest on the device. */
  encrypted: boolean;
  starred: boolean;
  /** Object/data URL for preview & download — may be undefined for seed files. */
  url?: string;
  /** Backend path when exposed by the Vault record; usable by Secure XFER. */
  backendPath?: string;
  namespace?: string;
  /** Optional free-text note set at upload time (Files-tab uploads only). */
  description?: string;
  /** DID of the file's owner — drives owner-only controls in the UI. */
  ownerDid?: string;
  /** True once the owner has revoked future access to this file. */
  revoked?: boolean;
  /** RFC3339 expiry timestamp, or undefined if the file never expires. */
  expiresAt?: string;
  /** True once this file's cached bytes are available for offline download. */
  cachedForOffline?: boolean;
}

/** A row in the browser — either a folder or a file. */
export type BrowserEntry =
  | { type: "folder"; folder: VaultFolder; itemCount: number }
  | { type: "file"; file: VaultFile };

/** Format a byte count into a short human string, e.g. "1.3 GB". */
export function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / Math.pow(1024, i);
  return `${i === 0 ? value : value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

/** Classify a file by its MIME type into a category. */
export function vaultKindOf(mime: string): VaultFileKind {
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("video/") || mime.startsWith("audio/")) return "media";
  return "document";
}

/** Human label for a file kind. */
export function kindLabel(kind: VaultFileKind): string {
  if (kind === "image") return "Image";
  if (kind === "media") return "Media";
  return "Document";
}
