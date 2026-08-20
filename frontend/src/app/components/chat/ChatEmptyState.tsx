import { MessageSquare } from "lucide-react";

export function ChatEmptyState() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-12 text-center" style={{ backgroundColor: "var(--muted)" }}>
      <div className="grid h-16 w-16 place-items-center rounded-full" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
        <MessageSquare size={28} style={{ color: "var(--primary)" }} />
      </div>
      <p className="text-sm font-semibold" style={{ color: "var(--foreground)" }}>Select a chat to start secure messaging</p>
      <p className="max-w-xs text-xs" style={{ color: "var(--muted-foreground)" }}>Choose a peer or group from the list to open the conversation here.</p>
    </div>
  );
}
