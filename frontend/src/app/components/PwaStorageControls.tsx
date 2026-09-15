import { useEffect, useState } from "react";
import { Database, ShieldAlert } from "lucide-react";
import { storageEstimate } from "../../pwa/db/maintenance";

const size = (value: number) => value < 1024 * 1024 ? `${Math.round(value / 1024)} KB` : `${(value / 1024 / 1024).toFixed(1)} MB`;

export function PwaStorageControls() {
  const [estimate, setEstimate] = useState({ usage: 0, quota: 0, percent: 0 });
  const refresh = () => void storageEstimate().then(setEstimate).catch(() => {});
  useEffect(refresh, []);

  return <section className="rounded-xl border border-border bg-card p-5">
    <div className="flex items-start gap-3"><Database size={20} className="mt-0.5 text-primary" /><div className="flex-1"><h2 className="font-semibold">Offline storage</h2><p className="mt-1 text-sm text-muted-foreground">{size(estimate.usage)} used{estimate.quota ? ` of ${size(estimate.quota)} (${estimate.percent.toFixed(1)}%)` : ""}. Sensitive records are encrypted locally.</p></div></div>
    {estimate.percent >= 80 && <p className="mt-3 flex gap-2 rounded-md bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300"><ShieldAlert size={15} />Storage is above 80%; clear old cached data before downloads fail.</p>}
  </section>;
}
