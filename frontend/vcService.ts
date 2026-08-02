import { useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import { Pencil, Camera, Check, Lock } from "lucide-react";
import { mockGuardian } from "../../data/mockData";
import { useCurrentUser } from "../../hooks/useCurrentUser";

export function ST03Profile() {
  const currentUser = useCurrentUser();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(currentUser.name);
  const [email, setEmail] = useState(currentUser.email);

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Profile"
        right={
          editing ? (
            <button
              onClick={() => setEditing(false)}
              className="flex items-center gap-1.5 px-3 rounded-md transition-opacity active:opacity-70"
              style={{ height: "36px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", borderRadius: "var(--radius-sm)" }}
            >
              <Check size={13} /> Save
            </button>
          ) : (
            <button
              onClick={() => setEditing(true)}
              className="flex items-center gap-1.5 px-3 rounded-md transition-opacity active:opacity-70"
              style={{ height: "36px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", borderRadius: "var(--radius-sm)" }}
            >
              <Pencil size={12} /> Edit
            </button>
          )
        }
      />

      {/* UX-06: Live Guardian health indicator in settings */}
      <div
        className="flex items-center gap-3 px-4 md:px-6 py-3 border-b border-border"
        style={{ backgroundColor: "color-mix(in srgb, var(--primary) 4%, var(--card))" }}
      >
        <div style={{ width: "7px", height: "7px", borderRadius: "50%", backgroundColor: "var(--chart-2)", flexShrink: 0 }} />
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", flex: 1 }}>
          {mockGuardian.name} · Online
        </span>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-2)", fontWeight: "var(--font-weight-medium)" }}>
          Healthy
        </span>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5">
        {/* Avatar */}
        <div className="flex flex-col items-center py-4">
          <div className="relative mb-3">
            <div className="rounded-full flex items-center justify-center" style={{ width: "80px", height: "80px", backgroundColor: "color-mix(in srgb, var(--primary) 20%, transparent)", border: "2px solid color-mix(in srgb, var(--primary) 35%, transparent)" }}>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: 700, color: "var(--primary)" }}>{currentUser.initials}</span>
            </div>
            {editing && (
              <button
                className="absolute bottom-0 right-0 rounded-full flex items-center justify-center transition-opacity active:opacity-70"
                style={{ width: "28px", height: "28px", backgroundColor: "var(--primary)", border: "2px solid var(--background)", cursor: "pointer" }}
              >
                <Camera size={13} style={{ color: "var(--primary-foreground)" }} />
              </button>
            )}
          </div>
          {!editing && (
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{name}</p>
          )}
        </div>

        {/* View mode notice (QA-19) */}
        {!editing && (
          <div className="flex items-center gap-2 px-3 py-2.5 rounded-lg" style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
            <Lock size={13} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              View mode — tap <strong style={{ color: "var(--foreground)" }}>Edit</strong> to make changes
            </p>
          </div>
        )}

        {/* Fields */}
        <div className="flex flex-col gap-4">
          {[
            { key: "name", label: "Full Name", value: name, setter: setName },
            { key: "email", label: "Email Address", value: email, setter: setEmail },
          ].map(({ key, label, value, setter }) => (
            <div key={key}>
              <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>
                {label}
              </label>
              {editing ? (
                <input
                  value={value}
                  onChange={(e) => setter(e.target.value)}
                  className="w-full px-4 outline-none"
                  style={{
                    height: "48px",
                    backgroundColor: "var(--input-background)",
                    border: "1.5px solid var(--primary)",
                    borderRadius: "var(--radius)",
                    color: "var(--foreground)",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                  }}
                />
              ) : (
                /* QA-19: Read-only fields look clearly different from edit inputs */
                <div
                  className="rounded-lg px-4 flex items-center justify-between"
                  style={{
                    height: "48px",
                    backgroundColor: "var(--muted)",
                    border: "1px solid transparent",
                  }}
                >
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>{value}</span>
                  <Lock size={13} style={{ color: "var(--muted-foreground)", opacity: 0.5 }} />
                </div>
              )}
            </div>
          ))}
          <div>
            <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>Role</label>
            <div
              className="rounded-lg px-4 flex items-center justify-between"
              style={{ height: "48px", backgroundColor: "var(--muted)", border: "1px solid transparent" }}
            >
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{currentUser.role}</span>
              <Lock size={13} style={{ color: "var(--muted-foreground)", opacity: 0.4 }} />
            </div>
          </div>
        </div>
        </div>
      </div>
    </div>
  );
}