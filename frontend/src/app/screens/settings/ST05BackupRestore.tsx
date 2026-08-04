import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import * as Dialog from "@radix-ui/react-dialog";
import * as Switch from "@radix-ui/react-switch";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Download,
  Eye,
  EyeOff,
  Loader2,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  Trash2,
  Undo2,
  UploadCloud,
  X,
} from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { formatBytes } from "../../components/vault/types";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../../components/ui/alert-dialog";
import {
  ALL_BACKUP_COMPONENTS,
  backupService,
  type BackupComponent,
  type BackupRecord,
  type BackupValidateResponse,
  type RestoreApplyResponse,
  type RestoreStatusResponse,
  type RestoreValidateResponse,
} from "../../services/backupService";

type RestoreStep = "form" | "review" | "done";

const COMPONENT_LABELS: Record<string, string> = {
  policy: "Policy",
  config: "Config",
  credentials: "Credentials",
  crl: "CRL",
};

const inputClass =
  "h-11 w-full rounded-lg border border-border bg-input-background px-3 text-sm outline-none transition focus:border-primary focus:ring-2 focus:ring-primary/15";

function formatDate(iso?: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span
      className="rounded-md px-2 py-0.5 text-xs font-medium"
      style={{ backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)" }}
    >
      {children}
    </span>
  );
}

function PassphraseField({
  value,
  onChange,
  visible,
  onToggleVisible,
  placeholder = "Backup passphrase",
  autoFocus,
}: {
  value: string;
  onChange: (value: string) => void;
  visible: boolean;
  onToggleVisible: () => void;
  placeholder?: string;
  autoFocus?: boolean;
}) {
  return (
    <div className="relative">
      <input
        autoFocus={autoFocus}
        type={visible ? "text" : "password"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        autoComplete="new-password"
        className={`${inputClass} pr-11`}
      />
      <button
        type="button"
        onClick={onToggleVisible}
        className="absolute right-3 top-3 text-muted-foreground"
        aria-label={visible ? "Hide passphrase" : "Show passphrase"}
      >
        {visible ? <EyeOff size={17} /> : <Eye size={17} />}
      </button>
    </div>
  );
}

export function ST05BackupRestore() {
  const [history, setHistory] = useState<BackupRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const [restoreStatus, setRestoreStatus] = useState<RestoreStatusResponse | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);

  // Create backup
  const [createPassphrase, setCreatePassphrase] = useState("");
  const [createPassphraseVisible, setCreatePassphraseVisible] = useState(false);
  const [portable, setPortable] = useState(true);
  const [creating, setCreating] = useState(false);

  // Import backup
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPassphrase, setImportPassphrase] = useState("");
  const [importPassphraseVisible, setImportPassphraseVisible] = useState(false);
  const [importing, setImporting] = useState(false);

  // Delete
  const [deleteTarget, setDeleteTarget] = useState<BackupRecord | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Inspect / validate
  const [inspectTarget, setInspectTarget] = useState<BackupRecord | null>(null);
  const [inspectPassphrase, setInspectPassphrase] = useState("");
  const [inspectPassphraseVisible, setInspectPassphraseVisible] = useState(false);
  const [inspecting, setInspecting] = useState(false);
  const [inspectResult, setInspectResult] = useState<BackupValidateResponse | null>(null);

  // Restore flow
  const [restoreTarget, setRestoreTarget] = useState<BackupRecord | null>(null);
  const [restoreStep, setRestoreStep] = useState<RestoreStep>("form");
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const [restorePassphraseVisible, setRestorePassphraseVisible] = useState(false);
  const [restoreComponents, setRestoreComponents] = useState<Set<BackupComponent>>(new Set(ALL_BACKUP_COMPONENTS));
  const [allowPolicyRollback, setAllowPolicyRollback] = useState(false);
  const [restoreValidating, setRestoreValidating] = useState(false);
  const [restoreValidateResult, setRestoreValidateResult] = useState<RestoreValidateResponse | null>(null);
  const [restoreApplying, setRestoreApplying] = useState(false);
  const [restoreApplyResult, setRestoreApplyResult] = useState<RestoreApplyResponse | null>(null);

  // Undo
  const [undoConfirmOpen, setUndoConfirmOpen] = useState(false);
  const [undoing, setUndoing] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const response = await backupService.history();
      setHistory(response.records ?? []);
    } catch (error) {
      setHistoryError(errorMessage(error, "Failed to load backup history"));
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const loadStatus = useCallback(async () => {
    setStatusLoading(true);
    try {
      const response = await backupService.restoreStatus();
      setRestoreStatus(response);
    } catch (error) {
      toast.error("Failed to load restore status", { description: errorMessage(error, "") || undefined });
    } finally {
      setStatusLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHistory();
    loadStatus();
  }, [loadHistory, loadStatus]);

  const handleCreateBackup = async () => {
    if (!createPassphrase.trim() || creating) return;
    setCreating(true);
    try {
      const record = await backupService.create({ passphrase: createPassphrase.trim(), portable });
      toast.success("Backup created", {
        description: `${formatBytes(record.size_bytes ?? 0)} · ${(record.components ?? []).map((c) => COMPONENT_LABELS[c] ?? c).join(", ")}`,
      });
      setCreatePassphrase("");
      await loadHistory();
    } catch (error) {
      toast.error("Backup failed", { description: errorMessage(error, "Could not create a backup") });
    } finally {
      setCreating(false);
    }
  };

  const openImport = () => {
    setImportFile(null);
    setImportPassphrase("");
    setImportPassphraseVisible(false);
    setImportOpen(true);
  };

  const closeImport = () => {
    if (importing) return;
    setImportOpen(false);
  };

  const handleImportBackup = async () => {
    if (!importFile || !importPassphrase.trim() || importing) return;
    setImporting(true);
    try {
      const record = await backupService.importBackup({ file: importFile, passphrase: importPassphrase.trim() });
      toast.success("Backup imported", { description: record?.id || undefined });
      setImportOpen(false);
      setImportFile(null);
      setImportPassphrase("");
      await loadHistory();
    } catch (error) {
      toast.error("Import failed", { description: errorMessage(error, "Could not import the backup") });
    } finally {
      setImporting(false);
    }
  };

  const handleDownload = async (record: BackupRecord) => {
    setDownloadingId(record.id);
    try {
      const blob = await backupService.download(record.id);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${record.id}.sgxbak`;
      anchor.click();
      URL.revokeObjectURL(url);
      toast.success("Download started");
    } catch (error) {
      toast.error("Download failed", { description: errorMessage(error, "Could not download the backup bundle") });
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await backupService.remove(deleteTarget.id);
      toast.success("Backup deleted");
      setDeleteTarget(null);
      await loadHistory();
    } catch (error) {
      toast.error("Delete failed", { description: errorMessage(error, "Could not delete the backup") });
    } finally {
      setDeleting(false);
    }
  };

  const openInspect = (record: BackupRecord) => {
    setInspectTarget(record);
    setInspectPassphrase("");
    setInspectPassphraseVisible(false);
    setInspectResult(null);
  };

  const handleInspect = async () => {
    if (!inspectTarget || !inspectPassphrase.trim()) return;
    setInspecting(true);
    try {
      const result = await backupService.validate({ id: inspectTarget.id, passphrase: inspectPassphrase.trim() });
      setInspectResult(result);
    } catch (error) {
      toast.error("Validation failed", { description: errorMessage(error, "Could not validate this backup bundle") });
    } finally {
      setInspecting(false);
    }
  };

  const openRestore = (record: BackupRecord) => {
    setRestoreTarget(record);
    setRestoreStep("form");
    setRestorePassphrase("");
    setRestorePassphraseVisible(false);
    setRestoreComponents(new Set(ALL_BACKUP_COMPONENTS));
    setAllowPolicyRollback(false);
    setRestoreValidateResult(null);
    setRestoreApplyResult(null);
  };

  const closeRestore = () => {
    if (restoreValidating || restoreApplying) return;
    const shouldRefreshStatus = restoreStep === "done";
    setRestoreTarget(null);
    if (shouldRefreshStatus) loadStatus();
  };

  const toggleRestoreComponent = (component: BackupComponent) => {
    setRestoreComponents((prev) => {
      const next = new Set(prev);
      if (next.has(component)) next.delete(component);
      else next.add(component);
      return next;
    });
  };

  const handleRestoreValidate = async () => {
    if (!restoreTarget || !restorePassphrase.trim() || restoreComponents.size === 0) return;
    setRestoreValidating(true);
    try {
      const result = await backupService.restoreValidate({
        id: restoreTarget.id,
        passphrase: restorePassphrase.trim(),
        components: Array.from(restoreComponents),
        allow_policy_rollback: allowPolicyRollback,
      });
      setRestoreValidateResult(result);
      setRestoreStep("review");
    } catch (error) {
      toast.error("Restore preflight failed", { description: errorMessage(error, "Could not validate the restore plan") });
    } finally {
      setRestoreValidating(false);
    }
  };

  const handleRestoreApply = async () => {
    if (!restoreTarget || !restorePassphrase.trim()) return;
    setRestoreApplying(true);
    try {
      const result = await backupService.restoreApply({
        id: restoreTarget.id,
        passphrase: restorePassphrase.trim(),
        confirm: true,
        components: Array.from(restoreComponents),
        allow_policy_rollback: allowPolicyRollback,
      });
      setRestoreApplyResult(result);
      setRestoreStep("done");
      toast.success(result.status === "committed" ? "Restore complete" : "Restore completed with warnings", {
        description: result.message,
      });
    } catch (error) {
      toast.error("Restore failed", { description: errorMessage(error, "Could not apply the restore") });
    } finally {
      setRestoreApplying(false);
    }
  };

  const handleUndo = async () => {
    setUndoing(true);
    try {
      const result = await backupService.restoreUndo();
      toast.success("Restore undone", { description: result.message });
      setUndoConfirmOpen(false);
      await loadStatus();
    } catch (error) {
      toast.error("Undo failed", { description: errorMessage(error, "Could not undo the last restore") });
    } finally {
      setUndoing(false);
    }
  };

  const journal = restoreStatus?.journal ?? null;
  const canUndo = !!journal?.snapshot_path && (journal.phase === "committed" || journal.phase === "committed_policy_skipped");

  return (
    <>
      <div className="flex flex-col h-full">
        <PageHeader
          title="Backup & Restore"
          right={
            <button
              onClick={() => {
                loadHistory();
                loadStatus();
              }}
              aria-label="Refresh"
              className="flex items-center justify-center rounded-md transition-opacity active:opacity-60"
              style={{ minWidth: "40px", minHeight: "40px" }}
            >
              <RefreshCw size={17} style={{ color: "var(--foreground)" }} className={historyLoading || statusLoading ? "animate-spin" : ""} />
            </button>
          }
        />
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5">
            {/* Create backup */}
            <div className="rounded-lg border border-border p-4 flex flex-col gap-4" style={{ backgroundColor: "var(--card)" }}>
              <div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                  Create Backup
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  Encrypts device configuration, circle data, credentials and CRL state with your passphrase.
                </p>
              </div>

              <PassphraseField
                value={createPassphrase}
                onChange={setCreatePassphrase}
                visible={createPassphraseVisible}
                onToggleVisible={() => setCreatePassphraseVisible((v) => !v)}
              />

              <div className="flex items-center justify-between">
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>Portable backup</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                    Allow this backup to be restored onto a different Guardian device.
                  </p>
                </div>
                <Switch.Root
                  checked={portable}
                  onCheckedChange={setPortable}
                  style={{
                    width: "44px",
                    height: "24px",
                    borderRadius: "12px",
                    backgroundColor: portable ? "var(--primary)" : "var(--muted)",
                    border: "none",
                    cursor: "pointer",
                    position: "relative",
                    flexShrink: 0,
                  }}
                >
                  <Switch.Thumb
                    style={{
                      display: "block",
                      width: "18px",
                      height: "18px",
                      borderRadius: "50%",
                      backgroundColor: "white",
                      transform: portable ? "translateX(22px)" : "translateX(3px)",
                      transition: "transform 0.2s",
                    }}
                  />
                </Switch.Root>
              </div>

              <button
                onClick={handleCreateBackup}
                disabled={!createPassphrase.trim() || creating}
                className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                style={{
                  height: "52px",
                  backgroundColor: creating ? "var(--muted)" : "var(--primary)",
                  color: creating ? "var(--muted-foreground)" : "var(--primary-foreground)",
                  border: "none",
                  cursor: !createPassphrase.trim() || creating ? "default" : "pointer",
                  opacity: !createPassphrase.trim() ? 0.6 : 1,
                  borderRadius: "var(--radius-card)",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-base)",
                  fontWeight: "var(--font-weight-semibold)",
                }}
              >
                {creating ? <Loader2 size={18} className="animate-spin" /> : <Database size={18} />}
                {creating ? "Creating Backup..." : "Create Backup"}
              </button>

              <button
                onClick={openImport}
                className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                style={{
                  height: "46px",
                  backgroundColor: "var(--secondary)",
                  color: "var(--secondary-foreground)",
                  border: "1px solid var(--border)",
                  cursor: "pointer",
                  borderRadius: "var(--radius-card)",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                }}
              >
                <UploadCloud size={16} /> Import Backup
              </button>
            </div>

            {/* Restore journal status */}
            {journal && (
              <div className="rounded-lg border border-border p-4 flex flex-col gap-3" style={{ backgroundColor: "var(--card)" }}>
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <ShieldAlert size={16} style={{ color: "var(--chart-5)" }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                      Last Restore
                    </p>
                  </div>
                  <Chip>{journal.phase}</Chip>
                </div>
                {journal.message && (
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                    {journal.message}
                  </p>
                )}
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  {formatDate(journal.updated_at)} · from {journal.bundle_id}
                </p>
                {canUndo && (
                  <button
                    onClick={() => setUndoConfirmOpen(true)}
                    className="flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80 self-start px-4"
                    style={{
                      height: "40px",
                      backgroundColor: "var(--secondary)",
                      color: "var(--secondary-foreground)",
                      border: "1px solid var(--border)",
                      cursor: "pointer",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      fontWeight: "var(--font-weight-medium)",
                    }}
                  >
                    <Undo2 size={15} /> Undo Last Restore
                  </button>
                )}
              </div>
            )}

            {/* Backup history */}
            <div className="flex flex-col gap-3">
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                BACKUP HISTORY
              </p>

              {historyLoading && (
                <div className="flex items-center justify-center py-8">
                  <Loader2 size={20} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
                </div>
              )}

              {!historyLoading && historyError && (
                <div className="rounded-lg border border-border p-4 flex flex-col items-center gap-2 text-center" style={{ backgroundColor: "var(--card)" }}>
                  <AlertTriangle size={18} style={{ color: "var(--destructive)" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>{historyError}</p>
                  <button
                    onClick={loadHistory}
                    style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", background: "none", border: "none", cursor: "pointer" }}
                  >
                    Try again
                  </button>
                </div>
              )}

              {!historyLoading && !historyError && history.length === 0 && (
                <div className="rounded-lg border border-border p-6 flex flex-col items-center gap-2 text-center" style={{ backgroundColor: "var(--card)" }}>
                  <Database size={20} style={{ color: "var(--muted-foreground)" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>No backups yet</p>
                </div>
              )}

              {!historyLoading && !historyError && history.map((record) => (
                <div key={record.id} className="rounded-lg border border-border p-4 flex flex-col gap-3" style={{ backgroundColor: "var(--card)" }}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                        {formatDate(record.created_at)}
                      </p>
                      <p
                        className="truncate"
                        style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--muted-foreground)" }}
                        title={record.id}
                      >
                        {record.id}
                      </p>
                    </div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", flexShrink: 0 }}>
                      {formatBytes(record.size_bytes ?? 0)}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-1.5">
                    <Chip>{record.portable ? "Portable" : "Same-device"}</Chip>
                    {(record.components ?? []).map((component) => (
                      <Chip key={component}>{COMPONENT_LABELS[component] ?? component}</Chip>
                    ))}
                  </div>

                  <div className="flex items-center gap-2 pt-1" style={{ borderTop: "1px solid var(--border)" }}>
                    <button
                      onClick={() => openInspect(record)}
                      title="Inspect"
                      aria-label="Inspect backup"
                      className="flex items-center justify-center rounded-md transition-opacity active:opacity-70 mt-3"
                      style={{ width: "36px", height: "36px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", cursor: "pointer" }}
                    >
                      <ScanSearch size={15} style={{ color: "var(--secondary-foreground)" }} />
                    </button>
                    <button
                      onClick={() => handleDownload(record)}
                      disabled={downloadingId === record.id}
                      title="Download"
                      aria-label="Download backup"
                      className="flex items-center justify-center rounded-md transition-opacity active:opacity-70 mt-3"
                      style={{ width: "36px", height: "36px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", cursor: "pointer" }}
                    >
                      {downloadingId === record.id ? (
                        <Loader2 size={15} className="animate-spin" style={{ color: "var(--secondary-foreground)" }} />
                      ) : (
                        <Download size={15} style={{ color: "var(--secondary-foreground)" }} />
                      )}
                    </button>
                    <button
                      onClick={() => openRestore(record)}
                      className="flex-1 flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80 mt-3"
                      style={{
                        height: "36px",
                        backgroundColor: "var(--primary)",
                        color: "var(--primary-foreground)",
                        border: "none",
                        cursor: "pointer",
                        fontFamily: "Inter, sans-serif",
                        fontSize: "var(--text-xs)",
                        fontWeight: "var(--font-weight-semibold)",
                      }}
                    >
                      <UploadCloud size={14} /> Restore
                    </button>
                    <button
                      onClick={() => setDeleteTarget(record)}
                      title="Delete"
                      aria-label="Delete backup"
                      className="flex items-center justify-center rounded-md transition-opacity active:opacity-70 mt-3"
                      style={{ width: "36px", height: "36px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", cursor: "pointer" }}
                    >
                      <Trash2 size={15} style={{ color: "var(--destructive)" }} />
                    </button>
                  </div>
                </div>
              ))}
            </div>

            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center", lineHeight: 1.5 }}>
              Backups are encrypted and stored locally on your Guardian device. They include device configurations, circle data, and alert history.
            </p>
          </div>
        </div>
      </div>

      {/* Delete confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && !deleting && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this backup?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently removes the backup bundle and its history record. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                handleDelete();
              }}
              disabled={deleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleting ? <Loader2 size={15} className="animate-spin" /> : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Import backup dialog */}
      <Dialog.Root open={importOpen} onOpenChange={(open) => !open && closeImport()}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
          <Dialog.Content
            className="fixed z-[70] rounded-xl border border-border p-6 flex flex-col gap-4"
            style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "420px", maxHeight: "85vh", overflowY: "auto" }}
          >
            <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              Import Backup
            </Dialog.Title>

            <input
              type="file"
              accept=".sgxbak"
              onChange={(event) => setImportFile(event.target.files?.[0] ?? null)}
              disabled={importing}
              className={inputClass}
              style={{ paddingTop: "10px" }}
            />

            <PassphraseField
              value={importPassphrase}
              onChange={setImportPassphrase}
              visible={importPassphraseVisible}
              onToggleVisible={() => setImportPassphraseVisible((v) => !v)}
              autoFocus
            />

            <div className="flex gap-3">
              <button
                onClick={closeImport}
                disabled={importing}
                className="flex-1 flex items-center justify-center rounded-lg transition-opacity active:opacity-80"
                style={{ height: "46px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: importing ? "default" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
              >
                Cancel
              </button>
              <button
                onClick={handleImportBackup}
                disabled={!importFile || !importPassphrase.trim() || importing}
                className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                style={{
                  height: "46px",
                  backgroundColor: "var(--primary)",
                  color: "var(--primary-foreground)",
                  border: "none",
                  cursor: !importFile || !importPassphrase.trim() || importing ? "default" : "pointer",
                  opacity: !importFile || !importPassphrase.trim() ? 0.6 : 1,
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                }}
              >
                {importing ? <Loader2 size={16} className="animate-spin" /> : <UploadCloud size={16} />}
                {importing ? "Importing..." : "Import"}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Undo confirmation */}
      <AlertDialog open={undoConfirmOpen} onOpenChange={(open) => !open && !undoing && setUndoConfirmOpen(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Undo last restore?</AlertDialogTitle>
            <AlertDialogDescription>
              This restores the pre-restore snapshot captured before the last restore. A restart may be required afterward.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={undoing}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={(event) => { event.preventDefault(); handleUndo(); }} disabled={undoing}>
              {undoing ? <Loader2 size={15} className="animate-spin" /> : "Undo Restore"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Inspect / validate dialog */}
      <Dialog.Root open={!!inspectTarget} onOpenChange={(open) => !open && setInspectTarget(null)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
          <Dialog.Content
            className="fixed z-[70] rounded-xl border border-border p-6 flex flex-col gap-4"
            style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "420px", maxHeight: "85vh", overflowY: "auto" }}
          >
            <div className="flex items-center justify-between">
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Inspect Backup
              </Dialog.Title>
              <Dialog.Close asChild>
                <button aria-label="Close" style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)" }}>
                  <X size={18} />
                </button>
              </Dialog.Close>
            </div>

            {!inspectResult ? (
              <>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                  Enter the passphrase to decrypt and validate this bundle without applying it.
                </p>
                <PassphraseField
                  value={inspectPassphrase}
                  onChange={setInspectPassphrase}
                  visible={inspectPassphraseVisible}
                  onToggleVisible={() => setInspectPassphraseVisible((v) => !v)}
                  autoFocus
                />
                <button
                  onClick={handleInspect}
                  disabled={!inspectPassphrase.trim() || inspecting}
                  className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                  style={{
                    height: "46px",
                    backgroundColor: "var(--primary)",
                    color: "var(--primary-foreground)",
                    border: "none",
                    cursor: !inspectPassphrase.trim() || inspecting ? "default" : "pointer",
                    opacity: !inspectPassphrase.trim() ? 0.6 : 1,
                    borderRadius: "var(--radius)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-semibold)",
                  }}
                >
                  {inspecting ? <Loader2 size={16} className="animate-spin" /> : <ScanSearch size={16} />}
                  {inspecting ? "Validating..." : "Validate"}
                </button>
              </>
            ) : (
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-2">
                  <CheckCircle2 size={16} style={{ color: "var(--chart-2)" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                    Bundle is valid
                  </p>
                </div>
                <dl className="flex flex-col gap-1.5" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}>
                  <div className="flex justify-between gap-3"><dt style={{ color: "var(--muted-foreground)" }}>Source node</dt><dd style={{ color: "var(--foreground)", textAlign: "right" }}>{inspectResult.source_node_id ?? "—"}</dd></div>
                  <div className="flex justify-between gap-3"><dt style={{ color: "var(--muted-foreground)" }}>Portable</dt><dd style={{ color: "var(--foreground)" }}>{inspectResult.portable ? "Yes" : "No"}</dd></div>
                  <div className="flex justify-between gap-3"><dt style={{ color: "var(--muted-foreground)" }}>Same-device identity</dt><dd style={{ color: "var(--foreground)" }}>{inspectResult.same_device_identity ? "Yes" : "No"}</dd></div>
                </dl>
                <div className="flex flex-wrap gap-1.5">
                  {inspectResult.components.map((component) => (
                    <Chip key={component.component}>{COMPONENT_LABELS[component.component] ?? component.component}</Chip>
                  ))}
                </div>
                {inspectResult.warnings.length > 0 && (
                  <div className="rounded-md p-3 flex flex-col gap-1" style={{ backgroundColor: "color-mix(in srgb, var(--chart-5) 10%, var(--card))", border: "1px solid color-mix(in srgb, var(--chart-5) 30%, var(--border))" }}>
                    {inspectResult.warnings.map((warning, index) => (
                      <p key={index} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{warning}</p>
                    ))}
                  </div>
                )}
                <Dialog.Close asChild>
                  <button
                    className="w-full flex items-center justify-center rounded-lg transition-opacity active:opacity-80"
                    style={{ height: "44px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
                  >
                    Close
                  </button>
                </Dialog.Close>
              </div>
            )}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Restore flow dialog */}
      <Dialog.Root open={!!restoreTarget} onOpenChange={(open) => !open && closeRestore()}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
          <Dialog.Content
            className="fixed z-[70] rounded-xl border border-border p-6 flex flex-col gap-4"
            style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "440px", maxHeight: "85vh", overflowY: "auto" }}
          >
            <div className="flex items-center justify-between">
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                {restoreStep === "done" ? "Restore Result" : "Restore from Backup"}
              </Dialog.Title>
              {!restoreValidating && !restoreApplying && (
                <button onClick={closeRestore} aria-label="Close" style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)" }}>
                  <X size={18} />
                </button>
              )}
            </div>

            {restoreStep === "form" && (
              <>
                <div className="flex items-start gap-2 rounded-md p-3" style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, var(--card))", border: "1px solid color-mix(in srgb, var(--destructive) 24%, var(--border))" }}>
                  <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0, marginTop: "1px" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", lineHeight: 1.5 }}>
                    Restoring replaces the selected components with data from this backup. Review the plan before applying.
                  </p>
                </div>

                <PassphraseField
                  value={restorePassphrase}
                  onChange={setRestorePassphrase}
                  visible={restorePassphraseVisible}
                  onToggleVisible={() => setRestorePassphraseVisible((v) => !v)}
                  autoFocus
                />

                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "8px" }}>
                    Components to restore
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {ALL_BACKUP_COMPONENTS.map((component) => {
                      const active = restoreComponents.has(component);
                      return (
                        <button
                          key={component}
                          type="button"
                          onClick={() => toggleRestoreComponent(component)}
                          className="rounded-md px-3 py-1.5 transition-opacity active:opacity-80"
                          style={{
                            backgroundColor: active ? "var(--primary)" : "var(--secondary)",
                            color: active ? "var(--primary-foreground)" : "var(--secondary-foreground)",
                            border: "1px solid var(--border)",
                            cursor: "pointer",
                            fontFamily: "Inter, sans-serif",
                            fontSize: "var(--text-xs)",
                            fontWeight: "var(--font-weight-medium)",
                          }}
                        >
                          {COMPONENT_LABELS[component] ?? component}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <label className="flex items-center gap-2" style={{ cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={allowPolicyRollback}
                    onChange={(event) => setAllowPolicyRollback(event.target.checked)}
                    style={{ width: "16px", height: "16px", accentColor: "var(--primary)" }}
                  />
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
                    Allow policy rollback to an older version
                  </span>
                </label>

                <button
                  onClick={handleRestoreValidate}
                  disabled={!restorePassphrase.trim() || restoreComponents.size === 0 || restoreValidating}
                  className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                  style={{
                    height: "46px",
                    backgroundColor: "var(--primary)",
                    color: "var(--primary-foreground)",
                    border: "none",
                    cursor: !restorePassphrase.trim() || restoreComponents.size === 0 || restoreValidating ? "default" : "pointer",
                    opacity: !restorePassphrase.trim() || restoreComponents.size === 0 ? 0.6 : 1,
                    borderRadius: "var(--radius)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-semibold)",
                  }}
                >
                  {restoreValidating ? <Loader2 size={16} className="animate-spin" /> : <ScanSearch size={16} />}
                  {restoreValidating ? "Building plan..." : "Preview Restore Plan"}
                </button>
              </>
            )}

            {restoreStep === "review" && restoreValidateResult && (
              <>
                <dl className="flex flex-col gap-1.5" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}>
                  <div className="flex justify-between gap-3"><dt style={{ color: "var(--muted-foreground)" }}>Mode</dt><dd style={{ color: "var(--foreground)" }}>{restoreValidateResult.mode === "same_device" ? "Same device" : "Cross device"}</dd></div>
                  <div className="flex justify-between gap-3"><dt style={{ color: "var(--muted-foreground)" }}>Destructive apply</dt><dd style={{ color: "var(--foreground)" }}>{restoreValidateResult.destructive_apply_enabled ? "Enabled" : "Disabled"}</dd></div>
                </dl>

                <div className="flex flex-col gap-2">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>
                    Restore plan
                  </p>
                  {restoreValidateResult.plan.map((step, index) => (
                    <div key={index} className="rounded-md p-2.5" style={{ backgroundColor: "var(--secondary)", border: "1px solid var(--border)" }}>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                        {COMPONENT_LABELS[step.component] ?? step.component} · {step.action}
                      </p>
                      {step.reason && (
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", color: "var(--muted-foreground)", marginTop: "2px" }}>{step.reason}</p>
                      )}
                    </div>
                  ))}
                </div>

                {restoreValidateResult.warnings.length > 0 && (
                  <div className="rounded-md p-3 flex flex-col gap-1" style={{ backgroundColor: "color-mix(in srgb, var(--chart-5) 10%, var(--card))", border: "1px solid color-mix(in srgb, var(--chart-5) 30%, var(--border))" }}>
                    {restoreValidateResult.warnings.map((warning, index) => (
                      <p key={index} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{warning}</p>
                    ))}
                  </div>
                )}

                <div className="flex gap-3">
                  <button
                    onClick={() => setRestoreStep("form")}
                    disabled={restoreApplying}
                    className="flex-1 flex items-center justify-center rounded-lg transition-opacity active:opacity-80"
                    style={{ height: "46px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
                  >
                    Back
                  </button>
                  <button
                    onClick={handleRestoreApply}
                    disabled={restoreApplying}
                    className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                    style={{ height: "46px", backgroundColor: "var(--destructive)", color: "var(--destructive-foreground)", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
                  >
                    {restoreApplying ? <Loader2 size={16} className="animate-spin" /> : "Confirm & Restore"}
                  </button>
                </div>
              </>
            )}

            {restoreStep === "done" && restoreApplyResult && (
              <>
                <div className="flex items-center gap-2">
                  <CheckCircle2 size={18} style={{ color: restoreApplyResult.status === "committed" ? "var(--chart-2)" : "var(--chart-5)" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                    {restoreApplyResult.status === "committed" ? "Restore committed" : "Restore committed with warnings"}
                  </p>
                </div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                  {restoreApplyResult.message}
                </p>
                {restoreApplyResult.restart_required && (
                  <div className="flex items-start gap-2 rounded-md p-3" style={{ backgroundColor: "color-mix(in srgb, var(--chart-5) 10%, var(--card))", border: "1px solid color-mix(in srgb, var(--chart-5) 30%, var(--border))" }}>
                    <AlertTriangle size={15} style={{ color: "var(--chart-5)", flexShrink: 0, marginTop: "1px" }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
                      A Guardian restart is required for the restored state to take effect.
                    </p>
                  </div>
                )}
                <button
                  onClick={closeRestore}
                  className="w-full flex items-center justify-center rounded-lg transition-opacity active:opacity-80"
                  style={{ height: "46px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
                >
                  Done
                </button>
              </>
            )}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  );
}
