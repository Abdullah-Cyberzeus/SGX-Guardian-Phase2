import { PageHeader } from "../../components/PageHeader";
import { Settings2 } from "lucide-react";

export function ST10DeviceSettings() {
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Device Settings" />
      <div className="flex-1 flex flex-col items-center justify-center gap-4 px-6 text-center">
        <div className="rounded-full flex items-center justify-center" style={{ width: "64px", height: "64px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
          <Settings2 size={28} style={{ color: "var(--muted-foreground)" }} />
        </div>
        <h3 style={{ fontFamily: "Inter, sans-serif", color: "var(--foreground)" }}>Device Settings</h3>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "240px", lineHeight: 1.6 }}>
          Advanced device configuration options will be available in a future Guardian firmware update.
        </p>
        <span
          className="px-4 py-1.5 rounded-full"
          style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", backgroundColor: "var(--muted)", borderRadius: "9999px" }}
        >
          Coming soon
        </span>
      </div>
    </div>
  );
}
