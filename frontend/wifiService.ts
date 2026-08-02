import { useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import { Database, UploadCloud, AlertTriangle } from "lucide-react";
import * as Dialog from "@radix-ui/react-dialog";

export function ST05BackupRestore() {
  const [restoreDialogOpen, setRestoreDialogOpen] = useState(false);
  const [backing, setBacking] = useState(false);

  const handleBackup = () => {
    setBacking(true);
    setTimeout(() => setBacking(false), 2000);
  };

  return (
    <>
      <div className="flex flex-col h-full">
        <PageHeader title="Backup & Restore" />
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">
          <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "4px" }}>Last Backup</p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>March 15, 2026</p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>11:30 PM · 14.2 MB</p>
          </div>

          <button
            onClick={handleBackup}
            disabled={backing}
            className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
            style={{ height: "52px", backgroundColor: backing ? "var(--muted)" : "var(--primary)", color: backing ? "var(--muted-foreground)" : "var(--primary-foreground)", border: "none", cursor: backing ? "default" : "pointer", borderRadius: "var(--radius-card)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)" }}
          >
            <Database size={18} />
            {backing ? "Creating Backup..." : "Create Backup"}
          </button>

          <button
            onClick={() => setRestoreDialogOpen(true)}
            className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
            style={{ height: "52px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius-card)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-medium)" }}
          >
            <UploadCloud size={18} /> Restore from Backup
          </button>

          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center", lineHeight: 1.5 }}>
            Backups are encrypted and stored locally on your Guardian device. They include device configurations, circle data, and alert history.
          </p>
          </div>
        </div>
      </div>

      <Dialog.Root open={restoreDialogOpen} onOpenChange={setRestoreDialogOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
          <Dialog.Content className="fixed z-[70] rounded-xl border border-border p-6" style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "380px" }}>
            <div className="flex items-center gap-3 mb-3">
              <AlertTriangle size={20} style={{ color: "var(--chart-5)" }} />
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Restore from Backup?</Dialog.Title>
            </div>
            <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6, marginBottom: "20px" }}>
              Restoring will replace your current configuration with the backup data. Your active data will be overwritten. This cannot be undone.
            </Dialog.Description>
            <div className="flex gap-3">
              <Dialog.Close asChild>
                <button className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "44px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}>Cancel</button>
              </Dialog.Close>
              <button onClick={() => setRestoreDialogOpen(false)} className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "44px", backgroundColor: "var(--destructive)", color: "var(--destructive-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}>Restore</button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  );
}