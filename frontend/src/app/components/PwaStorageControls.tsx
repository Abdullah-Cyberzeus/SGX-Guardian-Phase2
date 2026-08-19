import { useEffect, useState } from "react";
import { Database, Download, Eraser, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import {
  clearOfflineData,
  estimateClearImpact,
  exportEncryptedArchive,
  storageEstimate,
  verifyDatabase,
  EXPORTABLE_CATEGORIES,
  STORE_LABELS,
  type ClearImpact,
} from "../../pwa/db/maintenance";
import type { StoreName } from "../../pwa/db/schema";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "./ui/alert-dialog";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "./ui/dialog";
import { Button } from "./ui/button";

const size = (value: number) => value < 1024 * 1024 ? `${Math.round(value / 1024)} KB` : `${(value / 1024 / 1024).toFixed(1)} MB`;

export function PwaStorageControls() {
  const [estimate, setEstimate] = useState({ usage: 0, quota: 0, percent: 0 });
  const refresh = () => void storageEstimate().then(setEstimate).catch(() => {});
  useEffect(refresh, []);

  const [clearTarget, setClearTarget] = useState<{ preserveMembership: boolean; impact: ClearImpact } | null>(null);
  const [clearing, setClearing] = useState(false);

  const [exportOpen, setExportOpen] = useState(false);
  const [selectedCategories, setSelectedCategories] = useState<Set<StoreName>>(new Set(EXPORTABLE_CATEGORIES));
  const [passphrase, setPassphrase] = useState("");
  const [exporting, setExporting] = useState(false);

  const verify = async () => {
    try { const result = await verifyDatabase(); toast.success(`Offline storage is healthy (schema v${result.version})`); }
    catch (cause) { toast.error("Offline storage needs recovery", { description: cause instanceof Error ? cause.message : undefined }); }
  };

  const openExportDialog = () => {
    setSelectedCategories(new Set(EXPORTABLE_CATEGORIES));
    setPassphrase("");
    setExportOpen(true);
  };

  const toggleCategory = (name: StoreName) => {
    setSelectedCategories((current) => {
      const next = new Set(current);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  };

  const confirmExport = async () => {
    if (passphrase.length < 12 || selectedCategories.size === 0) return;
    setExporting(true);
    try {
      const archive = await exportEncryptedArchive(passphrase, [...selectedCategories]);
      const url = URL.createObjectURL(new Blob([JSON.stringify(archive)], { type: "application/json" }));
      const link = document.createElement("a"); link.href = url; link.download = `guardian-pwa-export-${new Date().toISOString().slice(0, 10)}.sgx.json`; link.click(); URL.revokeObjectURL(url);
      toast.success("Encrypted offline archive exported");
      setExportOpen(false);
    } catch (cause) {
      toast.error("Export failed", { description: cause instanceof Error ? cause.message : undefined });
    } finally {
      setExporting(false);
    }
  };

  const openClearDialog = async (preserveMembership: boolean) => {
    try {
      const impact = await estimateClearImpact(preserveMembership);
      setClearTarget({ preserveMembership, impact });
    } catch (cause) {
      toast.error("Could not estimate what would be cleared", { description: cause instanceof Error ? cause.message : undefined });
    }
  };

  const confirmClear = async () => {
    if (!clearTarget) return;
    setClearing(true);
    try {
      await clearOfflineData(clearTarget.preserveMembership);
      toast.success(clearTarget.preserveMembership ? "Offline cache cleared" : "All offline PWA data removed");
      setClearTarget(null);
      refresh();
    } catch (cause) {
      toast.error("Offline data could not be cleared", { description: cause instanceof Error ? cause.message : undefined });
    } finally {
      setClearing(false);
    }
  };

  return <section className="rounded-xl border border-border bg-card p-5">
    <div className="flex items-start gap-3"><Database size={20} className="mt-0.5 text-primary" /><div className="flex-1"><h2 className="font-semibold">Offline storage</h2><p className="mt-1 text-sm text-muted-foreground">{size(estimate.usage)} used{estimate.quota ? ` of ${size(estimate.quota)} (${estimate.percent.toFixed(1)}%)` : ""}. Sensitive records are encrypted locally.</p></div></div>
    {estimate.percent >= 80 && <p className="mt-3 flex gap-2 rounded-md bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300"><ShieldAlert size={15} />Storage is above 80%; clear old cached data before downloads fail.</p>}
    <div className="mt-4 grid gap-2 sm:grid-cols-2">
      <button onClick={() => void verify()} className="flex items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-sm"><Database size={15} />Check integrity</button>
      <button onClick={openExportDialog} className="flex items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-sm"><Download size={15} />Encrypted export</button>
      <button onClick={() => void openClearDialog(true)} className="flex items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-sm"><Eraser size={15} />Clear cache</button>
      <button onClick={() => void openClearDialog(false)} className="flex items-center justify-center gap-2 rounded-md border border-destructive/40 px-3 py-2 text-sm text-destructive"><Eraser size={15} />Remove all offline data</button>
    </div>

    {/* Itemized clear-cache confirmation */}
    <AlertDialog open={!!clearTarget} onOpenChange={(open) => { if (!open) setClearTarget(null); }}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {clearTarget?.preserveMembership ? "Clear offline cache?" : "Remove all offline data?"}
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div>
              {clearTarget?.impact.total ? (
                <>
                  <p className="mb-2">This removes:</p>
                  <ul className="mb-2 flex flex-col gap-1">
                    {clearTarget.impact.perStore.map((entry) => (
                      <li key={entry.store} className="flex justify-between text-xs">
                        <span>{entry.label}</span>
                        <span className="font-medium">{entry.count}</span>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <p className="mb-2">There's nothing cached to remove right now.</p>
              )}
              {!clearTarget?.preserveMembership && <p>This also removes your membership registration on this browser — you'll need a new invitation to rejoin.</p>}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={clearing}>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={() => void confirmClear()} disabled={clearing}>
            {clearing ? "Clearing…" : "Clear"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>

    {/* Category-picker export */}
    <Dialog open={exportOpen} onOpenChange={setExportOpen}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Encrypted export</DialogTitle>
          <DialogDescription>Choose what to include, then set a passphrase to encrypt the download.</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          {EXPORTABLE_CATEGORIES.map((name) => (
            <label key={name} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={selectedCategories.has(name)}
                onChange={() => toggleCategory(name)}
              />
              {STORE_LABELS[name]}
            </label>
          ))}
        </div>
        <input
          type="password"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          placeholder="12+ character passphrase"
          className="w-full rounded-md border border-border bg-transparent px-3 py-2 text-sm outline-none"
        />
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => setExportOpen(false)} disabled={exporting}>
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => void confirmExport()}
            disabled={exporting || passphrase.length < 12 || selectedCategories.size === 0}
          >
            {exporting ? "Exporting…" : "Export"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </section>;
}
