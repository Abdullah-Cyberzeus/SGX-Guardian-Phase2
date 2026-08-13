import { useEffect, useState } from "react";
import { Database, Download, Eraser, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { clearOfflineData, exportEncryptedArchive, storageEstimate, verifyDatabase } from "../../pwa/db/maintenance";

const size = (value: number) => value < 1024 * 1024 ? `${Math.round(value / 1024)} KB` : `${(value / 1024 / 1024).toFixed(1)} MB`;

export function PwaStorageControls() {
  const [estimate, setEstimate] = useState({ usage: 0, quota: 0, percent: 0 });
  const refresh = () => void storageEstimate().then(setEstimate).catch(() => {});
  useEffect(refresh, []);

  const verify = async () => {
    try { const result = await verifyDatabase(); toast.success(`Offline storage is healthy (schema v${result.version})`); }
    catch (cause) { toast.error("Offline storage needs recovery", { description: cause instanceof Error ? cause.message : undefined }); }
  };
  const exportData = async () => {
    const passphrase = window.prompt("Create a 12+ character passphrase for this encrypted export:");
    if (!passphrase) return;
    try {
      const archive = await exportEncryptedArchive(passphrase);
      const url = URL.createObjectURL(new Blob([JSON.stringify(archive)], { type: "application/json" }));
      const link = document.createElement("a"); link.href = url; link.download = `guardian-pwa-export-${new Date().toISOString().slice(0, 10)}.sgx.json`; link.click(); URL.revokeObjectURL(url);
      toast.success("Encrypted offline archive exported");
    } catch (cause) { toast.error("Export failed", { description: cause instanceof Error ? cause.message : undefined }); }
  };
  const clear = async (preserveMembership: boolean) => {
    const warning = preserveMembership ? "Clear cached messages, files, contacts, calls and queued operations?" : "Remove ALL offline data and membership metadata from this browser?";
    if (!window.confirm(warning)) return;
    try { await clearOfflineData(preserveMembership); toast.success(preserveMembership ? "Offline cache cleared" : "All offline PWA data removed"); refresh(); }
    catch (cause) { toast.error("Offline data could not be cleared", { description: cause instanceof Error ? cause.message : undefined }); }
  };

  return <section className="rounded-xl border border-border bg-card p-5">
    <div className="flex items-start gap-3"><Database size={20} className="mt-0.5 text-primary" /><div className="flex-1"><h2 className="font-semibold">Offline storage</h2><p className="mt-1 text-sm text-muted-foreground">{size(estimate.usage)} used{estimate.quota ? ` of ${size(estimate.quota)} (${estimate.percent.toFixed(1)}%)` : ""}. Sensitive records are encrypted locally.</p></div></div>
    {estimate.percent >= 80 && <p className="mt-3 flex gap-2 rounded-md bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300"><ShieldAlert size={15} />Storage is above 80%; clear old cached data before downloads fail.</p>}
    <div className="mt-4 grid gap-2 sm:grid-cols-2">
      <button onClick={() => void verify()} className="flex items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-sm"><Database size={15} />Check integrity</button>
      <button onClick={() => void exportData()} className="flex items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-sm"><Download size={15} />Encrypted export</button>
      <button onClick={() => void clear(true)} className="flex items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-sm"><Eraser size={15} />Clear cache</button>
      <button onClick={() => void clear(false)} className="flex items-center justify-center gap-2 rounded-md border border-destructive/40 px-3 py-2 text-sm text-destructive"><Eraser size={15} />Remove all offline data</button>
    </div>
  </section>;
}
