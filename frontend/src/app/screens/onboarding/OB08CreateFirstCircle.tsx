import { useState } from "react";
import { useNavigate } from "react-router";
import { ChevronDown, ChevronRight } from "lucide-react";

export function OB08CreateFirstCircle() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="flex flex-col"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      <div className="flex flex-col px-5 pt-12 pb-6 gap-4 flex-1">
        <div>
          <h2
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xl)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
              marginBottom: "8px",
            }}
          >
            Create Your First Circle
          </h2>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              color: "var(--muted-foreground)",
              lineHeight: 1.65,
            }}
          >
            A Circle is your trusted team group. Add teammates to share alerts, chat securely, and coordinate responses.
          </p>
        </div>

        {/* Circle name */}
        <div>
          <label
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--muted-foreground)",
              marginBottom: "6px",
              display: "block",
            }}
          >
            Circle Name <span style={{ color: "var(--destructive)" }}>*</span>
          </label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Texas Grid Ops"
            className="w-full px-4 outline-none"
            style={{
              height: "48px",
              backgroundColor: "var(--input-background)",
              border: "1.5px solid var(--border)",
              borderRadius: "var(--radius)",
              color: "var(--foreground)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
            }}
          />
        </div>

        {/* Description */}
        <div>
          <label
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--muted-foreground)",
              marginBottom: "6px",
              display: "block",
            }}
          >
            Description <span style={{ color: "var(--muted-foreground)" }}>(optional)</span>
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Brief description of this Circle's purpose..."
            rows={3}
            className="w-full px-4 py-3 outline-none resize-none"
            style={{
              backgroundColor: "var(--input-background)",
              border: "1.5px solid var(--border)",
              borderRadius: "var(--radius)",
              color: "var(--foreground)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              lineHeight: 1.5,
            }}
          />
        </div>

        {/* Expandable */}
        <div
          className="rounded-lg border border-border overflow-hidden"
          style={{ backgroundColor: "var(--card)" }}
        >
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full flex items-center justify-between px-4 py-4 transition-opacity active:opacity-70"
            style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
          >
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-medium)",
                color: "var(--foreground)",
              }}
            >
              What is a Circle?
            </span>
            {expanded ? (
              <ChevronDown size={16} style={{ color: "var(--muted-foreground)" }} />
            ) : (
              <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />
            )}
          </button>
          {expanded && (
            <div className="px-4 pb-4 border-t border-border pt-3">
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  color: "var(--muted-foreground)",
                  lineHeight: 1.65,
                }}
              >
                A Circle of Trust is a private, peer-to-peer encrypted group built on your Guardian's decentralized network. Members share security alerts, coordinate over encrypted voice and video calls, and communicate without any data leaving your private infrastructure.
              </p>
            </div>
          )}
        </div>
      </div>

      <div className="px-5 pb-10 flex flex-col gap-3">
        <button
          onClick={() => navigate("/onboarding/complete")}
          className="w-full flex items-center justify-center transition-opacity active:opacity-80"
          style={{
            height: "52px",
            backgroundColor: name ? "var(--primary)" : "var(--muted)",
            color: name ? "var(--primary-foreground)" : "var(--muted-foreground)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-base)",
            fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)",
            border: "none",
            cursor: "pointer",
          }}
        >
          Create Circle
        </button>
        <button
          onClick={() => navigate("/onboarding/complete")}
          className="flex items-center justify-center transition-opacity active:opacity-60"
          style={{
            height: "44px",
            background: "none",
            border: "none",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
            cursor: "pointer",
            textDecoration: "underline",
            textDecorationStyle: "dotted",
            textUnderlineOffset: "3px",
          }}
        >
          Skip for now
        </button>
      </div>
    </div>
  );
}
