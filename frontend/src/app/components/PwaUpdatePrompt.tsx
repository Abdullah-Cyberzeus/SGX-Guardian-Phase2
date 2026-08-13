import { RefreshCw } from "lucide-react";

export function PwaUpdatePrompt({ apply }: { apply: () => void }) {
  return <div className="fixed bottom-20 left-1/2 z-[180] w-[min(92vw,420px)] -translate-x-1/2 rounded-xl border border-primary/35 bg-card p-4 shadow-2xl" role="status">
    <div className="flex items-start gap-3">
      <RefreshCw size={20} className="mt-0.5 shrink-0 text-primary" />
      <div className="min-w-0 flex-1"><p className="text-sm font-semibold">Guardian update ready</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Apply it when no message or file operation is in progress.</p></div>
      <button onClick={apply} className="rounded-md bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground">Update</button>
    </div>
  </div>;
}
