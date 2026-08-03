import { PageHeader } from "../../components/PageHeader";
import { Plus, Star, Trash2, Shield } from "lucide-react";
import { mockGuardian } from "../../data/mockData";
import { StatusBadge } from "../../components/SeverityBadge";

const guardians = [
  { id: "grd_001", name: mockGuardian.name, lastSeen: "Now", status: "online" as const, primary: true },
  { id: "grd_002", name: "Guardian-TX-Mobile", lastSeen: "3 days ago", status: "offline" as const, primary: false },
];

export function ST09ManageGuardians() {
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Manage Guardians" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-4xl p-4 md:p-6 flex flex-col gap-4">
        <button
          className="w-full flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
          style={{ height: "44px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
        >
          <Plus size={16} /> Add Guardian
        </button>

        <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
          {guardians.map((g, i) => (
            <div key={g.id} className="flex items-center gap-3 px-4 py-4" style={{ borderBottom: i < guardians.length - 1 ? "1px solid var(--border)" : undefined }}>
              <div className="rounded-lg flex items-center justify-center flex-shrink-0" style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
                <Shield size={20} style={{ color: "var(--primary)" }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{g.name}</p>
                  {g.primary && <StatusBadge status="Primary" variant="info" />}
                </div>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: g.status === "online" ? "var(--chart-2)" : "var(--muted-foreground)" }} />
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                    {g.status === "online" ? "Online" : `Last seen ${g.lastSeen}`}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-1">
                {!g.primary && (
                  <button style={{ background: "none", border: "none", cursor: "pointer", padding: "8px" }} title="Set as primary">
                    <Star size={15} style={{ color: "var(--muted-foreground)" }} />
                  </button>
                )}
                <button style={{ background: "none", border: "none", cursor: "pointer", padding: "8px" }}>
                  <Trash2 size={15} style={{ color: "var(--muted-foreground)" }} />
                </button>
              </div>
            </div>
          ))}
        </div>
        </div>
      </div>
    </div>
  );
}
