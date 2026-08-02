import { FileText, ImageIcon, Film, type LucideIcon } from "lucide-react";
import type { VaultFileKind } from "./types";

/** Maps a Vault file kind to its lucide icon — one consistent glyph per kind. */
export function iconForKind(kind: VaultFileKind): LucideIcon {
  if (kind === "image") return ImageIcon;
  if (kind === "media") return Film;
  return FileText;
}
