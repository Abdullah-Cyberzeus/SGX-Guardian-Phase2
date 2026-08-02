import { useState } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  Users, Check, ChevronDown, ChevronRight, Loader2, Shield, Network, Radio,
  UserPlus, X, Zap,
} from "lucide-react";

type BuildMode = "quick" | "visual";

// Sample members added during visual builder
interface VisualMember {
  id: string;
  name: string;
  initials: string;
  online: boolean;
}

const mockCandidates: VisualMember[] = [
  { id: "m1", name: "Sofia Chen", initials: "SC", online: true },
  { id: "m2", name: "James Park", initials: "JP", online: true },
  { id: "m3", name: "Aisha Okonkwo", initials: "AO", online: false },
  { id: "m4", name: "Raj Patel", initials: "RP", online: false },
];

function getNodePosition(index: number, total: number, radius: number, cx: number, cy: number) {
  const angle = (index / total) * 2 * Math.PI - Math.PI / 2;
  return { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
}

export function NW02CreateCircle() {
  const navigate = useNavigate();
  const [buildMode, setBuildMode] = useState<BuildMode>("quick");

  // Quick create state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);

  // Visual builder state
  const [circleName, setCircleName] = useState("");
  const [members, setMembers] = useState<VisualMember[]>([]);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [visualLoading, setVisualLoading] = useState(false);
  const [visualDone, setVisualDone] = useState(false);
  const [animatingMember, setAnimatingMember] = useState<string | null>(null);

  const canCreate = circleName.trim().length > 0 && members.length > 0;

  const handleQuickCreate = () => {
    if (!name) return;
    setLoading(true);
    setTimeout(() => { navigate("/network", { replace: true }); }, 3000);
  };

  const handleAddMember = (candidate: VisualMember) => {
    if (members.find((m) => m.id === candidate.id)) return;
    setAnimatingMember(candidate.id);
    setTimeout(() => {
      setMembers((prev) => [...prev, candidate]);
      setAnimatingMember(null);
    }, 300);
    setShowInviteModal(false);
  };

  const removeMember = (id: string) => {
    setMembers((prev) => prev.filter((m) => m.id !== id));
  };

  const handleVisualCreate = () => {
    setVisualLoading(true);
    setTimeout(() => {
      setVisualLoading(false);
      setVisualDone(true);
      setTimeout(() => navigate("/network", { replace: true }), 1800);
    }, 2200);
  };

  const perks = [
    "Certificate Authority will be generated",
    "Circle network will be configured",
    "Your Guardian will join automatically",
    "Network relay enabled",
  ];

  // ── Visual Builder canvas ────────────────────────────────────────────────
  if (buildMode === "visual") {
    const svgSize = 300;
    const cx = svgSize / 2;
    const cy = svgSize / 2;
    const radius = 95;

    return (
      <div
        className="flex flex-col h-full"
        style={{ backgroundColor: "var(--background)" }}
      >
        {/* Top bar */}
        <div
          className="flex items-center justify-between px-4 md:px-6 py-3 border-b border-border flex-shrink-0"
          style={{ backgroundColor: "var(--background)" }}
        >
          <button
            onClick={() => setBuildMode("quick")}
            className="flex items-center justify-center"
            style={{ width: "40px", height: "40px", background: "none", border: "none", cursor: "pointer" }}
            aria-label="Back"
          >
            <ChevronRight size={20} style={{ color: "var(--foreground)", transform: "rotate(180deg)" }} />
          </button>

          {/* Circle name input */}
          <input
            value={circleName}
            onChange={(e) => setCircleName(e.target.value)}
            placeholder="Name your Circle…"
            className="flex-1 mx-3 outline-none text-center"
            style={{
              background: "none", border: "none",
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
            }}
          />

          {/* Create button */}
          <button
            onClick={handleVisualCreate}
            disabled={!canCreate || visualLoading}
            className="px-4 rounded-md transition-opacity active:opacity-80"
            style={{
              height: "36px",
              backgroundColor: canCreate && !visualLoading ? "var(--primary)" : "var(--muted)",
              color: canCreate && !visualLoading ? "var(--primary-foreground)" : "var(--muted-foreground)",
              border: "none", cursor: canCreate && !visualLoading ? "pointer" : "default",
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)",
              flexShrink: 0,
            }}
          >
            {visualLoading ? <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} /> : "Create Circle"}
          </button>
        </div>

        {/* Canvas */}
        <div className="flex-1 flex flex-col items-center justify-center px-4 py-4 relative">
          {/* Success overlay */}
          {visualDone && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 z-10" style={{ backgroundColor: "var(--background)" }}>
              <div
                className="rounded-full flex items-center justify-center"
                style={{ width: "80px", height: "80px", backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)", border: "2px solid color-mix(in srgb, var(--chart-2) 35%, transparent)", animation: "popIn 0.35s ease-out forwards" }}
              >
                <Check size={40} strokeWidth={2.5} style={{ color: "var(--chart-2)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Circle created!
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                Going to topology view…
              </p>
            </div>
          )}

          <svg width="100%" viewBox={`0 0 ${svgSize} ${svgSize}`} style={{ maxWidth: "320px", display: "block" }}>
            {/* Dashed ring */}
            {members.length === 0 && (
              <circle cx={cx} cy={cy} r={radius} fill="none" stroke="var(--border)" strokeWidth="1.5" strokeDasharray="6 5" opacity={0.7} />
            )}

            {/* Lines to members */}
            {members.map((m, i) => {
              const pos = getNodePosition(i, members.length, radius, cx, cy);
              return (
                <line key={m.id}
                  x1={cx} y1={cy} x2={pos.x} y2={pos.y}
                  stroke="var(--border)" strokeWidth="1.5"
                  style={{ animation: "fadeIn 0.4s ease-out forwards" }}
                />
              );
            })}

            {/* Center node — You */}
            <g>
              <circle cx={cx} cy={cy} r={30} fill="color-mix(in srgb, var(--primary) 18%, transparent)" stroke="var(--primary)" strokeWidth="2.5" />
              <circle cx={cx} cy={cy} r={20} fill="var(--primary)" />
              <text x={cx} y={cy + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", fontWeight: 700, fill: "var(--primary-foreground)" }}>GX</text>
              <text x={cx} y={cy + 46} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: 700, fill: "var(--primary)" }}>You</text>
            </g>

            {/* Member nodes */}
            {members.map((m, i) => {
              const pos = getNodePosition(i, members.length, radius, cx, cy);
              return (
                <g key={m.id} style={{ animation: "fadeIn 0.4s ease-out forwards" }}>
                  <circle cx={pos.x} cy={pos.y} r={22}
                    fill="var(--muted)" stroke={m.online ? "var(--chart-2)" : "var(--border)"} strokeWidth="1.5" />
                  <circle cx={pos.x + 14} cy={pos.y - 14} r={5}
                    fill={m.online ? "var(--chart-2)" : "var(--muted-foreground)"} stroke="var(--card)" strokeWidth="1.5" />
                  <text x={pos.x} y={pos.y + 4} textAnchor="middle"
                    style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: 600, fill: "var(--foreground)" }}>
                    {m.initials}
                  </text>
                  <text x={pos.x} y={pos.y + 37} textAnchor="middle"
                    style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fill: "var(--muted-foreground)" }}>
                    {m.name.split(" ")[0]}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Empty hint — only while no members added yet */}
          {members.length === 0 && (
            <div className="flex flex-col items-center gap-2 mt-2">
              <div
                className="rounded-full flex items-center justify-center"
                style={{ width: "36px", height: "36px", backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)" }}
              >
                <UserPlus size={16} style={{ color: "var(--primary)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center" }}>
                Add members to build your Circle of Trust
              </p>
            </div>
          )}

          {/* Members list chips */}
          {members.length > 0 && (
            <div className="flex flex-wrap gap-2 justify-center mt-4">
              {members.map((m) => (
                <div
                  key={m.id}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-full"
                  style={{ backgroundColor: "var(--card)", border: "1px solid var(--border)" }}
                >
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{m.name}</span>
                  <button onClick={() => removeMember(m.id)} style={{ background: "none", border: "none", cursor: "pointer", display: "flex", alignItems: "center" }}>
                    <X size={11} style={{ color: "var(--muted-foreground)" }} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Bottom Add Member button */}
        <div className="mx-auto w-full max-w-2xl px-4 md:px-6 pb-10 pt-2 flex-shrink-0">
          <button
            onClick={() => setShowInviteModal(true)}
            className="w-full flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
            style={{
              height: "52px",
              backgroundColor: "var(--card)",
              color: "var(--foreground)",
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)",
              borderRadius: "var(--radius)", border: "1.5px solid var(--border)", cursor: "pointer",
            }}
          >
            <UserPlus size={18} style={{ color: "var(--primary)" }} />
            Add Member
          </button>
        </div>

        {/* Invite modal */}
        {showInviteModal && (
          <div
            className="fixed inset-0 z-50 flex items-end md:items-center justify-center cursor-pointer"
            style={{ backgroundColor: "rgba(0,0,0,0.6)", maxWidth: "440px", margin: "0 auto" }}
            onClick={() => setShowInviteModal(false)}
          >
            <div
              className="w-full rounded-t-2xl md:rounded-2xl border-t md:border border-border"
              style={{ backgroundColor: "var(--card)", maxHeight: "60dvh", display: "flex", flexDirection: "column" }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex justify-center pt-3 pb-1 md:hidden">
                <div style={{ width: "36px", height: "4px", borderRadius: "2px", backgroundColor: "var(--border)" }} />
              </div>
              <div className="flex items-center justify-between px-5 py-3 border-b border-border">
                <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                  Add Member
                </h3>
                <button onClick={() => setShowInviteModal(false)} style={{ background: "none", border: "none", cursor: "pointer" }}>
                  <X size={18} style={{ color: "var(--muted-foreground)" }} />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto">
                {mockCandidates.filter((c) => !members.find((m) => m.id === c.id)).map((candidate) => (
                  <button
                    key={candidate.id}
                    onClick={() => handleAddMember(candidate)}
                    className="w-full flex items-center gap-3 px-5 py-4 text-left transition-opacity active:opacity-70"
                    style={{ backgroundColor: "transparent", border: "none", cursor: "pointer", borderBottom: "1px solid var(--border)" }}
                  >
                    <div
                      className="rounded-full flex items-center justify-center flex-shrink-0"
                      style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 22%, transparent)" }}
                    >
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)" }}>{candidate.initials}</span>
                    </div>
                    <div className="flex flex-col flex-1">
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{candidate.name}</span>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <div style={{ width: "5px", height: "5px", borderRadius: "50%", backgroundColor: candidate.online ? "var(--chart-2)" : "var(--muted-foreground)", flexShrink: 0 }} />
                        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{candidate.online ? "Online" : "Offline"}</span>
                      </div>
                    </div>
                    <UserPlus size={16} style={{ color: "var(--primary)", flexShrink: 0 }} />
                  </button>
                ))}
                {mockCandidates.filter((c) => !members.find((m) => m.id === c.id)).length === 0 && (
                  <div className="flex flex-col items-center py-8 gap-2">
                    <Check size={24} style={{ color: "var(--chart-2)" }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>All available members added</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        <style>{`
          @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
          @keyframes fadeIn{from{opacity:0;transform:scale(0.8)}to{opacity:1;transform:scale(1)}}
          @keyframes popIn{0%{transform:scale(0.85)}60%{transform:scale(1.08)}100%{transform:scale(1)}}
        `}</style>
      </div>
    );
  }

  // ── Quick Create (default) ────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Create New Circle" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">

        {/* Mode selector */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
            Creation Mode
          </p>
          <div className="grid grid-cols-2 gap-3">
            {/* Quick Create card */}
            <button
              onClick={() => setBuildMode("quick")}
              className="flex flex-col items-start gap-2 p-4 rounded-lg border text-left transition-opacity active:opacity-80"
              style={{
                backgroundColor: buildMode === "quick" ? "color-mix(in srgb, var(--primary) 8%, var(--card))" : "var(--card)",
                borderColor: buildMode === "quick" ? "var(--primary)" : "var(--border)",
                borderWidth: buildMode === "quick" ? "1.5px" : "1px",
                cursor: "pointer",
              }}
            >
              <div
                className="rounded-md flex items-center justify-center"
                style={{ width: "36px", height: "36px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}
              >
                <Zap size={18} style={{ color: "var(--primary)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Quick Create
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.4 }}>
                Fill in a form and create instantly.
              </p>
              {buildMode === "quick" && (
                <div className="flex items-center gap-1 mt-1">
                  <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--primary)" }} />
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--primary)", fontWeight: "var(--font-weight-semibold)" }}>Selected</span>
                </div>
              )}
            </button>

            {/* Visual Builder card */}
            <button
              onClick={() => setBuildMode("visual")}
              className="flex flex-col items-start gap-2 p-4 rounded-lg border text-left transition-opacity active:opacity-80"
              style={{
                backgroundColor: buildMode === "visual" ? "color-mix(in srgb, var(--primary) 8%, var(--card))" : "var(--card)",
                borderColor: buildMode === "visual" ? "var(--primary)" : "var(--border)",
                borderWidth: buildMode === "visual" ? "1.5px" : "1px",
                cursor: "pointer",
              }}
            >
              <div
                className="rounded-md flex items-center justify-center"
                style={{ width: "36px", height: "36px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}
              >
                <Network size={18} style={{ color: "var(--primary)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Build Visually
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.4 }}>
                See your Circle form as you add people.
              </p>
            </button>
          </div>
        </div>

        {/* Info card */}
        <div
          className="rounded-lg border p-4"
          style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}
        >
          {loading ? (
            <div className="flex flex-col items-center gap-3 py-2">
              <Loader2 size={24} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
                Initializing Circle network...
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                This may take a moment.
              </p>
            </div>
          ) : (
            <>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", marginBottom: "6px" }}>
                Circle Network
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
                Your Circle uses peer-to-peer encrypted communication. No data passes through Cervais servers.
              </p>
            </>
          )}
        </div>

        {/* Name input */}
        <div>
          <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>
            Circle Name <span style={{ color: "var(--destructive)" }}>*</span>
          </label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Control Room Alpha"
            disabled={loading}
            className="w-full px-4 outline-none"
            style={{
              height: "48px", backgroundColor: "var(--input-background)", border: "1.5px solid var(--border)",
              borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
              opacity: loading ? 0.5 : 1,
            }}
          />
        </div>

        {/* Description */}
        <div>
          <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>
            Description <span style={{ color: "var(--muted-foreground)" }}>(optional)</span>
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe this circle's purpose..."
            rows={3}
            disabled={loading}
            className="w-full px-4 py-3 outline-none resize-none"
            style={{
              backgroundColor: "var(--input-background)", border: "1.5px solid var(--border)",
              borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)", lineHeight: 1.5, opacity: loading ? 0.5 : 1,
            }}
          />
        </div>

        {/* Create button */}
        <button
          onClick={handleQuickCreate}
          disabled={!name || loading}
          className="w-full flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
          style={{
            height: "52px",
            backgroundColor: name && !loading ? "var(--primary)" : "var(--muted)",
            color: name && !loading ? "var(--primary-foreground)" : "var(--muted-foreground)",
            fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)", border: "none", cursor: name && !loading ? "pointer" : "default",
          }}
        >
          {loading && <Loader2 size={18} style={{ animation: "spin 1s linear infinite" }} />}
          {loading ? "Creating Circle..." : "Create Circle"}
        </button>

        {/* Perks */}
        {!loading && (
          <div className="flex flex-col gap-2">
            {perks.map((perk) => (
              <div key={perk} className="flex items-center gap-2">
                <Check size={14} style={{ color: "var(--chart-2)", flexShrink: 0 }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{perk}</span>
              </div>
            ))}
          </div>
        )}

        {/* What is a Circle expandable */}
        <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full flex items-center justify-between px-4 py-4 transition-opacity active:opacity-70"
            style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
          >
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
              What is a Circle?
            </span>
            {expanded ? <ChevronDown size={16} style={{ color: "var(--muted-foreground)" }} /> : <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />}
          </button>
          {expanded && (
            <div className="px-4 pb-4 border-t border-border pt-3">
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.65 }}>
                A Circle of Trust is a private peer-to-peer encrypted group. Members share security alerts, coordinate via encrypted voice and video calls, and communicate without data leaving your private infrastructure.
              </p>
            </div>
          )}
        </div>
        </div>
      </div>
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}