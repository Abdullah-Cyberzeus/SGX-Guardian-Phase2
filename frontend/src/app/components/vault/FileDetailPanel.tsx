import { useEffect, useState, type ReactNode } from "react";
import {
  Download,
  Eye,
  Star,
  Trash2,
  ShieldCheck,
  ShieldOff,
  Folder,
  Users,
  Archive,
  ChevronRight,
  Pencil,
  FolderInput,
  Send,
  Clock,
  History,
  WifiOff,
  X,
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
import { useAuth } from "../../contexts/AuthContext";
import { iconForKind } from "./FileTypeIcon";
import { FilePreviewDialog, canPreview } from "./FilePreviewDialog";
import { formatBytes, kindLabel, type VaultFile } from "./types";
import { vaultService, type VaultDownloadRecord } from "../../services/vaultService";
import { toast } from "sonner";
import { useNavigate } from "react-router";

interface FileDetailPanelProps {
  file: VaultFile;
  /** Members can preview, download, and transfer, but cannot mutate shared Vault metadata. */
  canManage?: boolean;
  /** Called after the file is removed — parent navigates / clears selection. */
  onRemoved: () => void;
  /** Open the folder a file lives in. */
  onOpenFolder: (folderId: string) => void;
  /** Close the desktop split-view panel. */
  onClose?: () => void;
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
export function FileDetailPanel({ file, canManage = true, onRemoved, onOpenFolder, onClose }: FileDetailPanelProps) {
  const navigate = useNavigate();
  const {
    deviceName, encryption, offline, removeFile, renameFile, moveFile, toggleStar,
    revokeFile, setFileExpiry, getFileHistory, getFolder, folders,
  } = useVault();
  const { session } = useAuth();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [revokeConfirmOpen, setRevokeConfirmOpen] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [editingName, setEditingName] = useState(false);
  const [name, setName] = useState(file.name);
  const [moving, setMoving] = useState(false);
  const [settingExpiry, setSettingExpiry] = useState(false);
  const [expiryInput, setExpiryInput] = useState("");
  const [history, setHistory] = useState<VaultDownloadRecord[] | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const previewable = canPreview(file);
  const Icon = iconForKind(file.kind);

  const isExpired = Boolean(file.expiresAt && new Date(file.expiresAt).getTime() <= Date.now());
  const isUnavailable = Boolean(file.revoked) || isExpired;
  // Nothing is cached on-device for offline use today, so being offline
  // always means a download isn't available — the metadata still shows.
  const downloadDisabled = isUnavailable || offline;
  const isOwner = session?.user.role !== "member" || file.ownerDid === session?.browserMemberDid;

  const folder = getFolder(file.folderId);
  const FolderIcon =
    folder?.kind === "circle" ? Users : folder?.kind === "system" ? Archive : Folder;

  useEffect(() => {
    if (!historyOpen || !isOwner) return;
    void getFileHistory(file.id)
      .then(setHistory)
      .catch(() => setHistory([]));
  }, [historyOpen, isOwner, file.id, getFileHistory]);

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
    if (downloadDisabled) return;
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

  const handleRevoke = async () => {
    try {
      await revokeFile(file.id);
      setRevokeConfirmOpen(false);
      toast.success("Access revoked", { description: "New downloads of this file are now blocked." });
    } catch (cause) {
      toast.error("Revoke failed", { description: cause instanceof Error ? cause.message : "Try again." });
    }
  };

  const handleSetExpiry = async () => {
    const trimmed = expiryInput.trim();
    try {
      await setFileExpiry(file.id, trimmed ? new Date(trimmed).toISOString() : null);
      setSettingExpiry(false);
      toast.success(trimmed ? "Expiry set" : "Expiry cleared");
    } catch (cause) {
      toast.error("Expiry update failed", { description: cause instanceof Error ? cause.message : "Try again." });
    }
  };

  return (
    <div className="flex h-full w-full flex-col gap-4 overflow-y-auto p-4">
      {onClose && (
        <div className="flex shrink-0 items-center justify-between">
          <p className="text-sm font-semibold text-foreground">File details</p>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={onClose}
            aria-label="Close file details"
            title="Close file details"
          >
            <X size={18} />
          </Button>
        </div>
      )}

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

      {/* Unavailable banner — revoked, expired, or offline with nothing cached */}
      {(isUnavailable || offline) && (
        <Card
          className="flex-row items-center gap-3 p-3.5"
          style={{
            backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)",
            borderColor: "color-mix(in srgb, var(--destructive) 35%, transparent)",
          }}
        >
          {offline && !isUnavailable ? (
            <WifiOff size={20} style={{ color: "var(--destructive)", flexShrink: 0 }} />
          ) : (
            <ShieldOff size={20} style={{ color: "var(--destructive)", flexShrink: 0 }} />
          )}
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--foreground)",
            }}
          >
            {file.revoked
              ? "This file's access was revoked by its owner."
              : isExpired
                ? "This file has expired and is no longer available."
                : "Unavailable offline — this file hasn't been downloaded to this device yet."}
          </p>
        </Card>
      )}

      {/* Metadata */}
      <Card className="gap-0 px-4 py-1">
        <DetailRow label="Type">{file.mime}</DetailRow>
        <div style={{ borderTop: "1px solid var(--border)" }} />
        <DetailRow label="Added">{file.addedAt}</DetailRow>
        <div style={{ borderTop: "1px solid var(--border)" }} />
        <DetailRow label="Shared by">{file.sharedBy}</DetailRow>
        {file.description && (
          <>
            <div style={{ borderTop: "1px solid var(--border)" }} />
            <DetailRow label="Description">{file.description}</DetailRow>
          </>
        )}
        <div style={{ borderTop: "1px solid var(--border)" }} />
        <DetailRow label="Expiry">
          {file.expiresAt ? new Date(file.expiresAt).toLocaleString() : "Never"}
        </DetailRow>
        <div style={{ borderTop: "1px solid var(--border)" }} />
        <DetailRow label="Availability">
          {file.revoked ? "Revoked" : isExpired ? "Expired" : "Available"}
        </DetailRow>
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
            onClick={() => navigate(`/storage/transfers?vault_id=${encodeURIComponent(file.id)}`)}
            className="h-11 w-full gap-2"
          >
            <Send size={16} /> Send to peer
          </Button>
        )}
        {previewable && (
          <Button
            onClick={() => setPreviewOpen(true)}
            variant={file.backendPath ? "outline" : "default"}
            className="h-11 w-full gap-2"
            disabled={downloadDisabled}
            title={downloadDisabled ? (offline ? "Unavailable offline" : "Access to this file is unavailable") : undefined}
          >
            <Eye size={16} /> Open preview
          </Button>
        )}
        <Button
          onClick={() => void handleDownload()}
          variant={previewable ? "outline" : "default"}
          className="h-11 w-full gap-2"
          disabled={downloadDisabled}
          title={downloadDisabled ? (offline ? "Unavailable offline" : "Access to this file is unavailable") : undefined}
        >
          <Download size={16} /> Download
        </Button>
        {canManage && <div className="flex gap-2">
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
        </div>}
        {canManage && moving && (
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
        {canManage && <div className="flex gap-2">
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
        </div>}

        {/* Owner-only access controls — separate from canManage, since a
            Circle member can own a file without being allowed to manage the
            shared Vault metadata around it. */}
        {isOwner && (
          <div className="flex flex-col gap-2 pt-1" style={{ borderTop: "1px solid var(--border)" }}>
            <div className="flex gap-2 pt-2">
              <Button
                variant="outline"
                onClick={() => setSettingExpiry((value) => !value)}
                className="h-11 flex-1 gap-2"
              >
                <Clock size={16} /> {file.expiresAt ? "Change expiry" : "Set expiry"}
              </Button>
              <Button
                variant="outline"
                onClick={() => setHistoryOpen(true)}
                className="h-11 flex-1 gap-2"
              >
                <History size={16} /> History
              </Button>
            </div>
            {settingExpiry && (
              <Card className="gap-2 p-3">
                <Input
                  type="datetime-local"
                  value={expiryInput}
                  onChange={(event) => setExpiryInput(event.target.value)}
                  aria-label="Expiry date and time"
                />
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => { setExpiryInput(""); void handleSetExpiry(); }}>
                    Clear
                  </Button>
                  <Button size="sm" onClick={() => void handleSetExpiry()} disabled={!expiryInput.trim()}>
                    Save
                  </Button>
                </div>
              </Card>
            )}
            {!file.revoked && (
              <Button
                variant="outline"
                onClick={() => setRevokeConfirmOpen(true)}
                className="h-11 w-full gap-2"
              >
                <ShieldOff size={16} style={{ color: "var(--destructive)" }} />
                <span style={{ color: "var(--destructive)" }}>Revoke access</span>
              </Button>
            )}
          </div>
        )}
      </div>

      {/* Download history — owner-only. */}
      <AlertDialog open={historyOpen} onOpenChange={setHistoryOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Download history</AlertDialogTitle>
            <AlertDialogDescription>Who has downloaded "{file.name}" and when.</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex max-h-64 flex-col gap-2 overflow-y-auto">
            {history === null ? (
              <p className="text-xs text-muted-foreground">Loading…</p>
            ) : history.length === 0 ? (
              <p className="text-xs text-muted-foreground">No downloads yet.</p>
            ) : (
              history.map((entry, index) => (
                <div key={index} className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2 text-xs">
                  <span className="truncate">{entry.downloader_did}</span>
                  <span className="flex-shrink-0 text-muted-foreground">{new Date(entry.downloaded_at).toLocaleString()}</span>
                </div>
              ))
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Close</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Revoke confirmation. */}
      <AlertDialog open={revokeConfirmOpen} onOpenChange={setRevokeConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke access to this file?</AlertDialogTitle>
            <AlertDialogDescription>
              No one will be able to download "{file.name}" after this. The file itself and its
              history are kept — this only blocks future access.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className={buttonVariants({ variant: "destructive" })}
              onClick={handleRevoke}
            >
              Revoke access
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Remove confirmation — controlled, so no asChild Button trigger. */}
      <AlertDialog open={canManage && confirmOpen} onOpenChange={setConfirmOpen}>
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
