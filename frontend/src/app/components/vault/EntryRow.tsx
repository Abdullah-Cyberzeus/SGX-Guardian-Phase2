import type { KeyboardEvent } from "react";
import { Folder, Users, Archive, Star, ChevronRight, MoreVertical } from "lucide-react";
import { iconForKind } from "./FileTypeIcon";
import { formatBytes, type BrowserEntry, type VaultFolder } from "./types";

/** Fixed row height — shared with the virtualizer so geometry stays in sync. */
export const ENTRY_ROW_HEIGHT = 56;

interface EntryRowProps {
  entry: BrowserEntry;
  /** Highlighted as the open file in the desktop split view. */
  active?: boolean;
  onOpen: () => void;
  onToggleStar?: () => void;
  onFolderActions?: () => void;
}

function folderIcon(folder: VaultFolder) {
  if (folder.kind === "circle") return Users;
  if (folder.kind === "system") return Archive;
  return Folder;
}

/** One Drive-style row — a folder or a file. Used inside the virtualized list. */
export function EntryRow({ entry, active, onOpen, onToggleStar, onFolderActions }: EntryRowProps) {
  const isFolder = entry.type === "folder";

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onOpen();
    }
  };

  const Icon = isFolder ? folderIcon(entry.folder) : iconForKind(entry.file.kind);
  const name = isFolder ? entry.folder.name : entry.file.name;
  const owner = isFolder ? entry.folder.createdBy : entry.file.sharedBy;
  const modified = isFolder ? entry.folder.createdAt : entry.file.addedAt;
  const sizeText = isFolder
    ? `${entry.itemCount} ${entry.itemCount === 1 ? "item" : "items"}`
    : formatBytes(entry.file.sizeBytes);
  const showThumb = !isFolder && entry.file.kind === "image" && !!entry.file.url;

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={handleKeyDown}
      className="group flex cursor-pointer items-center gap-3 px-3 transition-colors hover:bg-accent"
      style={{
        height: `${ENTRY_ROW_HEIGHT}px`,
        backgroundColor: active
          ? "color-mix(in srgb, var(--primary) 12%, transparent)"
          : undefined,
        borderBottom: "1px solid var(--border)",
      }}
    >
      {/* Icon / thumbnail */}
      <div
        className="flex flex-shrink-0 items-center justify-center overflow-hidden rounded-lg"
        style={{
          width: "36px",
          height: "36px",
          backgroundColor: isFolder
            ? "color-mix(in srgb, var(--chart-4) 16%, transparent)"
            : "color-mix(in srgb, var(--primary) 12%, transparent)",
        }}
      >
        {showThumb ? (
          <img
            src={entry.file.url}
            alt=""
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
          />
        ) : (
          <Icon
            size={18}
            style={{ color: isFolder ? "var(--chart-4)" : "var(--primary)" }}
          />
        )}
      </div>

      {/* Name (+ compact meta on small screens) */}
      <div className="min-w-0 flex-1">
        <p
          className="truncate"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-medium)",
            color: "var(--foreground)",
          }}
        >
          {name}
        </p>
        <p
          className="truncate md:hidden"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
          }}
        >
          {sizeText} · {modified}
        </p>
      </div>

      {/* Owner — tablet+ */}
      <span
        className="hidden w-28 flex-shrink-0 truncate md:block"
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          color: "var(--muted-foreground)",
        }}
      >
        {owner}
      </span>

      {/* Modified — desktop */}
      <span
        className="hidden w-32 flex-shrink-0 truncate lg:block"
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          color: "var(--muted-foreground)",
        }}
      >
        {modified}
      </span>

      {/* Size / item count — tablet+ */}
      <span
        className="hidden w-24 flex-shrink-0 text-right md:block"
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          color: "var(--muted-foreground)",
        }}
      >
        {sizeText}
      </span>

      {/* Trailing action */}
      {isFolder ? (
        <button
          type="button"
          aria-label={`Actions for ${entry.folder.name}`}
          onClick={(e) => { e.stopPropagation(); onFolderActions?.(); }}
          className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-md hover:bg-muted"
          style={{ background: "none", border: "none", cursor: "pointer" }}
        >
          {onFolderActions
            ? <MoreVertical size={16} style={{ color: "var(--muted-foreground)" }} />
            : <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />}
        </button>
      ) : (
        <button
          type="button"
          aria-label={entry.file.starred ? "Unstar file" : "Star file"}
          aria-pressed={entry.file.starred}
          onClick={(e) => {
            e.stopPropagation();
            onToggleStar?.();
          }}
          className="flex w-9 flex-shrink-0 items-center justify-center rounded-md transition-opacity active:opacity-60"
          style={{ height: "36px", background: "none", border: "none", cursor: "pointer" }}
        >
          <Star
            size={16}
            style={{
              color: entry.file.starred ? "var(--chart-4)" : "var(--muted-foreground)",
              fill: entry.file.starred ? "var(--chart-4)" : "transparent",
            }}
          />
        </button>
      )}
    </div>
  );
}
