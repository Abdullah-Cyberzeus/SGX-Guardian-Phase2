import { useState, type ReactNode } from "react";
import {
  Download,
  Eye,
  Star,
  Trash2,
  ShieldCheck,
  Folder,
  Users,
  Archive,
  ChevronRight,
  Pencil,
  FolderInput,
  Send,
} from "lucide-react";
import { Card } from "../ui/card";
import { Input } from "../ui/input";
import { Button, buttonVariants } from "../ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../ui/alert-dialog";
import { useVault } from "../../contexts/VaultContext";
import { iconForKind } from "./FileTypeIcon";
import { FilePreviewDialog, canPreview } from "./FilePreviewDialog";
import { formatBytes, kindLabel, type VaultFile } from "./types";
import { vaultService } from "../../services/vaultService";
import { toast } from "sonner";
import { useNavigate } from "react-router";

interface FileDetailPanelProps {
  file: VaultFile;
  /** Called after the file is removed — parent navigates / clears selection. */
  onRemoved: () => void;
  /** Open the folder a file lives in. */
  onOpenFolder: (folderId: string) => void;
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5">
      <span
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          color: "var(--muted-foreground)",
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <span
        className="min-w-0 text-right"
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-medium)",
          color: "var(--foreground)",
          wordBreak: "break-word",
        }}
      >
        {children}
      </span>
    </div>
  );
}

/** Full file detail — preview, security, metadata, actions. Shared by the
 *  mobile detail screen and the desktop split-view panel. */
export function FileDetailPanel({ file, onRemoved, onOpenFolder }: FileDetailPanelProps) {
  const navigate = useNavigate();
  const {
    deviceName, encryption, removeFile, renameFile, moveFile, toggleStar, getFolder, folders,
  } = useVault();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [editingName, setEditingName] = useState(false);
  const [name, setName] = useState(file.name);
  const [moving, setMoving] = useState(false);
  const previewable = canPreview(file);
  const Icon = iconForKind(file.kind);

  const folder = getFolder(file.folderId);
  const FolderIcon =
    folder?.kind === "circle" ? Users : folder?.kind === "system" ? Archive : Folder;

  const handleRemove = async () => {
    try {
      await removeFile(file.id);
      setConfirmOpen(false);
      onRemoved();
      toast.success("File deleted", { description: `${file.name} was removed from Vault.` });
    } catch (cause) {
      toast.error("Delete failed", { description: cause instanceof Error ? cause.message : "Try again." });
    }
  };

  const handleDownload = async () => {
    try {
      const blob = await vaultService.download(file.id);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = file.name;
      anchor.click();
      URL.revokeObjectURL(url);
      toast.success("Download started");
    } catch (cause) {
      toast.error("Download failed", { description: cause instanceof Error ? cause.message : "Try again." });
    }
  };

  const handleRename = async () => {
    if (!name.trim() || name.trim() === file.name) {
      setEditingName(false);
      return;
    }
    try {
      await renameFile(file.id, name.trim());
      setEditingName(false);
      toast.success("File renamed");
    } catch (cause) {
      toast.error("Rename failed", { description: cause instanceof Error ? cause.message : "Try again." });
    }
  };

  const handleMove = async (folderId: string) => {
    try {
      await moveFile(file.id, folderId);
      setMoving(false);
      toast.success("File moved");
    } catch (cause) {
      toast.error("Move failed", { description: cause instanceof Error ? cause.message : "Try again." });
    }
  };

  return (
    <div className="flex h-full w-full flex-col gap-4 overflow-y-auto p-4">
      {/* Preview — tap to open the full viewer when there's content to show */}
      {previewable ? (
        <button
          type="button"
          onClick={() => setPreviewOpen(true)}
          aria-label={`Preview ${file.name}`}
          className="relative flex items-center justify-center overflow-hidden rounded-xl border border-border transition-opacity active:opacity-80"
          style={{
            backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)",
            minHeight: "180px",
            cursor: "pointer",
            padding: 0,
          }}
        >
          {file.kind === "image" && file.url ? (
            <img
              src={file.url}
              alt={file.name}
              style={{ width: "100%", maxHeight: "300px", objectFit: "contain" }}
            />
          ) : (
            <Icon size={52} strokeWidth={1.5} style={{ color: "var(--primary)" }} />
          )}
          <span
            className="absolute flex items-center gap-1 rounded-md"
            style={{
              bottom: "8px",
              right: "8px",
              padding: "4px 8px",
              backgroundColor: "color-mix(in srgb, var(--background) 88%, transparent)",
              border: "1px solid var(--border)",
              fontFamily: "Inter, sans-serif",
              fontSize: "11px",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--foreground)",
            }}
          >
            <Eye size={12} /> Preview
          </span>
        </button>
      ) : (
        <div
          className="flex items-center justify-center overflow-hidden rounded-xl border border-border"
          style={{
            backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)",
            minHeight: "180px",
          }}
        >
          {file.kind === "image" && file.url ? (
            <img
              src={file.url}
              alt={file.name}
              style={{ width: "100%", maxHeight: "300px", objectFit: "contain" }}
            />
          ) : (
            <Icon size={52} strokeWidth={1.5} style={{ color: "var(--primary)" }} />
          )}
        </div>
      )}

      {/* Name + size */}
      <div>
        {editingName ? (
          <div className="flex gap-2">
            <Input value={name} onChange={(event) => setName(event.target.value)} autoFocus />
            <Button size="sm" onClick={() => void handleRename()}>Save</Button>
          </div>
        ) : <h3
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-base)",
            fontWeight: "var(--font-weight-semibold)",
            color: "var(--foreground)",
            wordBreak: "break-word",
            lineHeight: 1.4,
          }}
        >
          {file.name}
        </h3>}
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
            marginTop: "2px",
          }}
        >
          {kindLabel(file.kind)} · {formatBytes(file.sizeBytes)}
        </p>
      </div>

      {/* Security assurance */}
      <Card
        className="flex-row items-center gap-3 p-3.5"
        style={{
          backgroundColor: "color-mix(in srgb, var(--chart-2) 10%, transparent)",
          borderColor: "color-mix(in srgb, var(--chart-2) 35%, transparent)",
        }}
      >
        <ShieldCheck size={20} style={{ color: "var(--chart-2)", flexShrink: 0 }} />
        <div className="min-w-0">
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
            }}
          >
            Encrypted · {encryption}
          </p>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "11px",
              color: "var(--muted-foreground)",
            }}
          >
            Stored on {deviceName} — only your network can open it.
          </p>
        </div>
      </Card>

      {/* Metadata */}
      <Card className="gap-0 px-4 py-1">
        <DetailRow label="Type">{file.mime}</DetailRow>
        <div style={{ borderTop: "1px solid var(--border)" }} />
        <DetailRow label="Added">{file.addedAt}</DetailRow>
        <div style={{ borderTop: "1px solid var(--border)" }} />
        <DetailRow label="Shared by">{file.sharedBy}</DetailRow>
        <div style={{ borderTop: "1px solid var(--border)" }} />
        <DetailRow label="Location">
          <button
            type="button"
            onClick={() => onOpenFolder(file.folderId)}
            className="inline-flex items-center gap-1 transition-opacity active:opacity-60"
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              color: "var(--primary)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
            }}
          >
            <FolderIcon size={12} />
            {folder?.name ?? "All Files"}
            <ChevronRight size={12} />
          </button>
        </DetailRow>
      </Card>

      {/* Actions */}
      <div className="mt-auto flex flex-col gap-2 pt-1">
        {file.backendPath && (
          <Button
            onClick={() => navigate(`/storage/transfers?path=${encodeURIComponent(file.backendPath!)}`)}
            className="h-11 w-full gap-2"
          >
            <Send size={16} /> Send to peer
          </Button>
        )}
        {previewable && (
          <Button onClick={() => setPreviewOpen(true)} variant={file.backendPath ? "outline" : "default"} className="h-11 w-full gap-2">
            <Eye size={16} /> Open preview
          </Button>
        )}
        <Button
          onClick={() => void handleDownload()}
          variant={previewable ? "outline" : "default"}
          className="h-11 w-full gap-2"
        >
          <Download size={16} /> Download
        </Button>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => setEditingName((value) => !value)}
            className="h-11 flex-1 gap-2"
          >
            <Pencil size={16} /> Rename
          </Button>
          <Button
            variant="outline"
            onClick={() => setMoving((value) => !value)}
            className="h-11 flex-1 gap-2"
          >
            <FolderInput size={16} /> Move
          </Button>
        </div>
        {moving && (
          <Card className="gap-1 p-2">
            <p className="px-2 py-1 text-xs font-medium text-muted-foreground">Move to folder</p>
            {folders.filter((item) => item.id !== file.folderId).map((item) => (
              <button
                key={item.id}
                onClick={() => void handleMove(item.id)}
                className="rounded-md px-2 py-2 text-left text-xs hover:bg-muted"
              >
                {item.name}
              </button>
            ))}
          </Card>
        )}
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => {
              void toggleStar(file.id).catch((cause) => {
                toast.error("Star update failed", {
                  description: cause instanceof Error ? cause.message : "Please try again.",
                });
              });
            }}
            className="h-11 flex-1 gap-2"
          >
            <Star
              size={16}
              style={{
                color: file.starred ? "var(--chart-4)" : undefined,
                fill: file.starred ? "var(--chart-4)" : "transparent",
              }}
            />
            {file.starred ? "Starred" : "Star"}
          </Button>
          <Button
            variant="outline"
            onClick={() => setConfirmOpen(true)}
            className="h-11 flex-1 gap-2"
          >
            <Trash2 size={16} style={{ color: "var(--destructive)" }} />
            <span style={{ color: "var(--destructive)" }}>Remove</span>
          </Button>
        </div>
      </div>

      {/* Remove confirmation — controlled, so no asChild Button trigger. */}
      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove this file?</AlertDialogTitle>
            <AlertDialogDescription>
              "{file.name}" will be removed from {deviceName}. This can't be
              undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={handleRemove}
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <FilePreviewDialog file={file} open={previewOpen} onOpenChange={setPreviewOpen} />
    </div>
  );
}
