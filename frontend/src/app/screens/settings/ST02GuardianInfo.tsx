import { useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import { Copy, Check, ChevronDown, ChevronRight, Share2 } from "lucide-react";
import { mockGuardian } from "../../data/mockData";
import { useCurrentUser } from "../../hooks/useCurrentUser";
import { QRCodeSVG } from "qrcode.react";

type DIDTab = "full" | "alias" | "qr";

// Alias derived from Guardian name segments + user initials, e.g. "TX-042-MR"
function buildAlias(guardianName: string, initials: string): { alias: string; groups: string[] } {
  // "Guardian-TX-042" → ["TX", "042"]
  const segments = guardianName.replace(/^Guardian-?/i, "").split("-").filter(Boolean).slice(0, 2);
  const groups = [...segments, initials];
  return { alias: groups.join("-"), groups };
}

export function ST02GuardianInfo() {
  const { name, email, role, initials, did } = useCurrentUser();
  const { alias: SHORT_ALIAS, groups: ALIAS_GROUPS } = buildAlias(mockGuardian.name, initials);
  const [didTab, setDIDTab] = useState<DIDTab>("full");
  const [copied, setCopied] = useState(false);
  const [aliasCopied, setAliasCopied] = useState(false);
  const [didExpanded, setDidExpanded] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(did).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyAlias = () => {
    navigator.clipboard.writeText(SHORT_ALIAS).catch(() => {});
    setAliasCopied(true);
    setTimeout(() => setAliasCopied(false), 2000);
  };

  const handleShare = async () => {
    if (navigator.share) {
      navigator.share({ title: "My Cervais DID", text: `${name}'s Guardian DID: ${did}` }).catch(() => {});
    } else {
      handleCopy();
    }
  };

  const didTabs: { id: DIDTab; label: string }[] = [
    { id: "full", label: "Full DID" },
    { id: "alias", label: "Short Alias" },
    { id: "qr", label: "QR Code" },
  ];

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Guardian Info" subtitle="Device & Identity" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">

        {/* User info */}
        <div className="flex items-center gap-3 rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
          <div className="rounded-full flex items-center justify-center flex-shrink-0" style={{ width: "52px", height: "52px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", border: "1.5px solid color-mix(in srgb, var(--primary) 30%, transparent)" }}>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)" }}>{initials}</span>
          </div>
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{name}</p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{email}</p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{role}</p>
          </div>
        </div>

        {/* Viewing settings for */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "8px" }}>Viewing settings for:</p>
          <div className="rounded-lg border border-border p-4 flex items-center gap-3" style={{ backgroundColor: "var(--card)" }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "var(--chart-2)", flexShrink: 0 }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{mockGuardian.name}</p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginLeft: "auto" }}>Online</p>
          </div>
        </div>

        {/* DID section */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
            My Decentralized Identifier (DID)
          </p>

          {/* Tab switcher */}
          <div
            className="flex p-1 rounded-lg mb-3"
            style={{ backgroundColor: "var(--muted)", borderRadius: "var(--radius-card)" }}
          >
            {didTabs.map(({ id, label }) => (
              <button
                key={id}
                onClick={() => setDIDTab(id)}
                className="flex-1 flex items-center justify-center transition-all"
                style={{
                  height: "34px",
                  borderRadius: "var(--radius)",
                  backgroundColor: didTab === id ? "var(--card)" : "transparent",
                  color: didTab === id ? "var(--foreground)" : "var(--muted-foreground)",
                  fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
                  fontWeight: didTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                  border: didTab === id ? "1px solid var(--border)" : "none",
                  cursor: "pointer",
                  boxShadow: didTab === id ? "var(--elevation-sm)" : "none",
                }}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Full DID */}
          {didTab === "full" && (
            <div className="flex flex-col gap-2">
              <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                <div className="flex items-center justify-between px-4 py-3 border-b border-border">
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.06em" }}>
                    Your DID
                  </span>
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 px-3 rounded transition-opacity active:opacity-70"
                    style={{
                      height: "30px",
                      backgroundColor: copied ? "color-mix(in srgb, var(--chart-2) 15%, transparent)" : "color-mix(in srgb, var(--primary) 15%, transparent)",
                      color: copied ? "var(--chart-2)" : "var(--primary)",
                      border: "none", cursor: "pointer",
                      fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)",
                    }}
                  >
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                    {copied ? "Copied!" : "Copy"}
                  </button>
                </div>
                <div className="p-4">
                  <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", wordBreak: "break-all", lineHeight: 1.7 }}>
                    {did || <span style={{ color: "var(--muted-foreground)" }}>No DID assigned yet</span>}
                  </p>
                </div>
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                Share this DID with others to receive Circle invitations.
              </p>
            </div>
          )}

          {/* Short Alias */}
          {didTab === "alias" && (
            <div className="flex flex-col gap-3">
              <div className="rounded-lg border border-border p-5 flex flex-col items-center gap-4" style={{ backgroundColor: "var(--card)" }}>
                <div className="flex items-center gap-3">
                  {ALIAS_GROUPS.map((group, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "30px", fontWeight: 700, color: "var(--foreground)", letterSpacing: "0.05em", lineHeight: 1 }}>
                        {group}
                      </span>
                      {i < ALIAS_GROUPS.length - 1 && (
                        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "22px", color: "var(--border)", lineHeight: 1 }}>·</span>
                      )}
                    </div>
                  ))}
                </div>
                <button
                  onClick={handleCopyAlias}
                  className="flex items-center gap-2 px-5 rounded-md transition-opacity active:opacity-70"
                  style={{
                    height: "40px",
                    backgroundColor: aliasCopied ? "color-mix(in srgb, var(--chart-2) 15%, transparent)" : "color-mix(in srgb, var(--primary) 15%, transparent)",
                    color: aliasCopied ? "var(--chart-2)" : "var(--primary)",
                    border: `1px solid ${aliasCopied ? "color-mix(in srgb, var(--chart-2) 30%, transparent)" : "color-mix(in srgb, var(--primary) 25%, transparent)"}`,
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)",
                  }}
                >
                  {aliasCopied ? <Check size={15} /> : <Copy size={15} />}
                  {aliasCopied ? "Copied!" : "Copy Alias"}
                </button>
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
                Short alias for quick identification. Share your full DID for Circle invites.
              </p>
            </div>
          )}

          {/* QR Code */}
          {didTab === "qr" && (
            <div className="flex flex-col gap-3">
              <div className="rounded-lg border border-border p-5 flex flex-col items-center gap-4" style={{ backgroundColor: "var(--card)" }}>
                <div className="rounded-lg overflow-hidden" style={{ padding: "16px", backgroundColor: "#ffffff" }}>
                  <QRCodeSVG value={did || "did:cervais:pending"} size={180} bgColor="#ffffff" fgColor="#000000" level="M" />
                </div>
                <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: 600, color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                  {SHORT_ALIAS}
                </p>
                <button
                  onClick={handleShare}
                  className="flex items-center gap-2 px-6 rounded-md transition-opacity active:opacity-70"
                  style={{
                    height: "44px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
                    border: "none", cursor: "pointer",
                    fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)",
                    borderRadius: "var(--radius)",
                  }}
                >
                  <Share2 size={15} />
                  Share QR Code
                </button>
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5, textAlign: "center" }}>
                Teammates can scan this to add you instantly.
              </p>
            </div>
          )}
        </div>

        {/* What is a DID expandable */}
        <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
          <button
            onClick={() => setDidExpanded(!didExpanded)}
            className="w-full flex items-center justify-between px-4 py-4 transition-opacity active:opacity-70"
            style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
          >
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>What is a DID?</span>
            {didExpanded ? <ChevronDown size={16} style={{ color: "var(--muted-foreground)" }} /> : <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />}
          </button>
          {didExpanded && (
            <div className="px-4 pb-4 border-t border-border pt-3">
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.65 }}>
                A Decentralized Identifier (DID) is a globally unique identifier that you control. Unlike email or usernames, it's tied to a cryptographic key that only you possess, enabling trustless identity verification across the Cervais network.
              </p>
            </div>
          )}
        </div>

        {/* Connection type & signal */}
        <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
          {[
            { label: "Connection Type", value: mockGuardian.connectionType },
            { label: "Signal Strength", value: `${mockGuardian.signal}%` },
          ].map(({ label, value }, i) => (
            <div key={label} className="flex items-center justify-between px-4 py-3.5" style={{ borderBottom: i === 0 ? "1px solid var(--border)" : undefined }}>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{label}</span>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{value}</span>
            </div>
          ))}
        </div>
        </div>
      </div>
    </div>
  );
}