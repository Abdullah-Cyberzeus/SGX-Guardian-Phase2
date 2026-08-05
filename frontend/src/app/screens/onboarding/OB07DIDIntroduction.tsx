import { useState } from "react";
import { useNavigate } from "react-router";
import { ProgressDots } from "../../components/ProgressDots";
import { Copy, Check, ChevronDown, ChevronRight, Share2 } from "lucide-react";
import { useCurrentUser } from "../../hooks/useCurrentUser";
import { mockGuardian } from "../../data/mockData";
import { QRCodeSVG } from "qrcode.react";

type DIDTab = "full" | "alias" | "qr";

// Alias derived from Guardian name segments + user initials
function buildAlias(guardianName: string, initials: string): { alias: string; groups: string[] } {
  const segments = guardianName.replace(/^Guardian-?/i, "").split("-").filter(Boolean).slice(0, 2);
  const groups = [...segments, initials];
  return { alias: groups.join("-"), groups };
}

export function OB07DIDIntroduction() {
  const navigate = useNavigate();
  const { name, initials, did } = useCurrentUser();
  const { alias: SHORT_ALIAS, groups: ALIAS_GROUPS } = buildAlias(mockGuardian.name, initials);
  const [didTab, setDIDTab] = useState<DIDTab>("full");
  const [copied, setCopied] = useState(false);
  const [aliasCopied, setAliasCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);

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
      navigator.share({
        title: "My Cervais DID",
        text: `${name}'s Guardian DID: ${did}`,
      }).catch(() => {});
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
    <div
      className="flex flex-col"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      <div className="flex flex-col items-center px-6 pt-12 pb-6">
        <ProgressDots total={3} current={3} />
      </div>

      <div className="flex flex-col px-5 flex-1 overflow-y-auto pb-6 gap-5">
        {/* Header */}
        <div>
          <h2
            style={{
              fontFamily: "Inter, sans-serif", fontSize: "24px", fontWeight: 700,
              color: "var(--foreground)", letterSpacing: "-0.02em", lineHeight: 1.2, marginBottom: "8px",
            }}
          >
            Your Decentralized Identifier
          </h2>
          <p
            style={{
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
              color: "var(--muted-foreground)", lineHeight: 1.6,
            }}
          >
            Your DID is your unique cryptographic identity on the Guardian network.
          </p>
        </div>

        {/* Tab switcher */}
        <div
          className="flex p-1 rounded-lg"
          style={{ backgroundColor: "var(--muted)", borderRadius: "var(--radius-card)" }}
        >
          {didTabs.map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setDIDTab(id)}
              className="flex-1 flex items-center justify-center transition-all"
              style={{
                height: "36px",
                borderRadius: "var(--radius)",
                backgroundColor: didTab === id ? "var(--card)" : "transparent",
                color: didTab === id ? "var(--foreground)" : "var(--muted-foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
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

        {/* â”€â”€ Tab: Full DID â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        {didTab === "full" && (
          <div className="flex flex-col gap-3">
            <div
              className="rounded-lg border border-border overflow-hidden"
              style={{ backgroundColor: "var(--card)" }}
            >
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
              Share this full DID with teammates to receive Circle invitations.
            </p>
          </div>
        )}

        {/* â”€â”€ Tab: Short Alias â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        {didTab === "alias" && (
          <div className="flex flex-col gap-3">
            <div
              className="rounded-lg border border-border p-5 flex flex-col items-center gap-5"
              style={{ backgroundColor: "var(--card)" }}
            >
              {/* Big alias display */}
              <div className="flex items-center gap-3">
                {ALIAS_GROUPS.map((group, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <span
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: "32px",
                        fontWeight: 700,
                        color: "var(--foreground)",
                        letterSpacing: "0.05em",
                        lineHeight: 1,
                      }}
                    >
                      {group}
                    </span>
                    {i < ALIAS_GROUPS.length - 1 && (
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "24px", color: "var(--border)", lineHeight: 1 }}>Â·</span>
                    )}
                  </div>
                ))}
              </div>

              {/* Copy button below */}
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

            <div
              className="rounded-lg border border-border p-3"
              style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 18%, transparent)" }}
            >
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
                Short alias for quick identification. Read out over a call or in person.{" "}
                <span style={{ color: "var(--foreground)", fontWeight: "var(--font-weight-medium)" }}>Share your full DID for Circle invites.</span>
              </p>
            </div>
          </div>
        )}

        {/* â”€â”€ Tab: QR Code â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        {didTab === "qr" && (
          <div className="flex flex-col gap-3">
            <div
              className="rounded-lg border border-border p-5 flex flex-col items-center gap-4"
              style={{ backgroundColor: "var(--card)" }}
            >
              {/* QR must have white bg */}
              <div
                className="rounded-lg overflow-hidden"
                style={{ padding: "16px", backgroundColor: "#ffffff" }}
              >
                <QRCodeSVG
                  value={did || "did:cervais:pending"}
                  size={200}
                  bgColor="#ffffff"
                  fgColor="#000000"
                  level="M"
                />
              </div>

              {/* Short alias reference */}
              <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: 600, color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                {SHORT_ALIAS}
              </p>

              {/* Share button */}
              <button
                onClick={handleShare}
                className="flex items-center gap-2 px-6 rounded-md transition-opacity active:opacity-70"
                style={{
                  height: "44px",
                  backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
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
              Teammates can scan this QR to add you to a Circle instantly.
            </p>
          </div>
        )}

        {/* What is a DID expandable */}
        <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full flex items-center justify-between px-4 py-4 transition-opacity active:opacity-70"
            style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
          >
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
              What is a DID?
            </span>
            {expanded ? (
              <ChevronDown size={16} style={{ color: "var(--muted-foreground)" }} />
            ) : (
              <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />
            )}
          </button>
          {expanded && (
            <div className="px-4 pb-4 border-t border-border pt-3">
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.65 }}>
                A Decentralized Identifier (DID) is a globally unique identifier that you control. Unlike email or usernames, it's tied to a cryptographic key that only you possess, enabling trustless identity verification across the Cervais network.
              </p>
            </div>
          )}
        </div>
      </div>

      <div className="px-5 pb-10 pt-3">
        <button
          onClick={() => {
            localStorage.setItem("sgx_onboarded", "1");
            navigate("/home", { replace: true });
          }}
          className="w-full flex items-center justify-center gap-2 transition-opacity active:opacity-80"
          style={{
            height: "52px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
            fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)", border: "none", cursor: "pointer",
          }}
        >
          Go to Dashboard
        </button>
      </div>
    </div>
  );
}