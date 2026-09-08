import { useMemo, useState, useEffect } from "react";
import { PageHeader } from "../../components/PageHeader";
import {
  Fingerprint,
  RefreshCw,
  Users,
  Loader2,
  AlertTriangle,
  Copy,
  Clock,
  Server,
  Key,
  Layers,
  FileCheck,
  Shuffle,
  Hourglass,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { useVidShow, useVidPeers } from "../../hooks/useApiData";
import { useContactNames } from "../../contexts/ContactNameContext";
import type { VidPeer, VidChangeReason } from "../../services/vidService";
import { toast } from "sonner";

// ── Helpers ────────────────────────────────────────────────────────────────────

function shortDid(did: string) {
  if (!did) return "";
  if (did.length <= 22) return did;
  return did.slice(0, 16) + "…" + did.slice(-6);
}

function shortHex(hex: string, head = 8, tail = 6) {
  if (!hex) return "";
  if (hex.length <= head + tail + 1) return hex;
  return hex.slice(0, head) + "…" + hex.slice(-tail);
}

function fmtTime(iso?: string) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function secondsUntil(iso?: string): number | null {
  if (!iso) return null;
  try {
    const ms = new Date(iso).getTime() - Date.now();
    return Math.max(0, Math.round(ms / 1000));
  } catch {
    return null;
  }
}

async function copyText(text: string) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast.success("Copied");
  } catch {
    toast.error("Copy failed");
  }
}

function CopyButton({ text }: { text: string }) {
  if (!text) return null;
  return (
    <button
      onClick={() => copyText(text)}
      title="Copy"
      className="rounded p-1"
      style={{
        background: "none",
        border: "none",
        color: "var(--muted-foreground)",
        cursor: "pointer",
        display: "inline-flex",
      }}
    >
      <Copy size={11} />
    </button>
  );
}

function ErrorBlock({ message }: { message: string }) {
  return (
    <div
      className="flex items-center gap-3 rounded-xl px-4 py-3"
      style={{
        background: "color-mix(in srgb, var(--destructive) 10%, transparent)",
        border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
      }}
    >
      <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0 }} />
      <span
        style={{
          fontSize: "var(--text-xs)",
          color: "var(--destructive)",
          fontFamily: "Inter, sans-serif",
        }}
      >
        {message}
      </span>
    </div>
  );
}

// ── Change reason badge ────────────────────────────────────────────────────────

function reasonColor(reason: VidChangeReason): string {
  switch (reason) {
    case "initial_observation":
      return "var(--muted-foreground)";
    case "nonce_refreshed":
      return "var(--chart-2)";
    case "dkp_rotated":
      return "var(--chart-1)";
    case "pcr_changed":
      return "var(--chart-4)";
    case "policy_changed":
      return "var(--chart-3)";
    default:
      return "var(--muted-foreground)";
  }
}

function ChangeReasonBadge({ reason }: { reason?: VidChangeReason }) {
  if (!reason) return null;
  const color = reasonColor(reason);
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5"
      style={{
        fontSize: "10px",
        fontFamily: "Inter, sans-serif",
        color,
        background: `color-mix(in srgb, ${color} 10%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
      }}
    >
      <Shuffle size={10} />
      {reason.replace(/_/g, " ")}
    </span>
  );
}

// ── Field row ──────────────────────────────────────────────────────────────────

function Field({
  label,
  value,
  mono,
  icon,
  copyValue,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  icon?: React.ReactNode;
  copyValue?: string;
}) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ background: "var(--background)", border: "1px solid var(--border)" }}
    >
      <div
        style={{
          fontSize: "10px",
          color: "var(--muted-foreground)",
          fontFamily: "Inter, sans-serif",
          marginBottom: "3px",
          display: "flex",
          alignItems: "center",
          gap: "4px",
        }}
      >
        {icon}
        {label}
      </div>
      <div className="flex items-center gap-2">
        <span
          className="flex-1 break-all"
          style={{
            fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--foreground)",
          }}
        >
          {value}
        </span>
        {copyValue && <CopyButton text={copyValue} />}
      </div>
    </div>
  );
}

// ── Session expiry countdown (re-renders every second) ─────────────────────────

function ExpiryCountdown({ expiresAt, ttl }: { expiresAt?: string; ttl?: number }) {
  const [secs, setSecs] = useState<number | null>(secondsUntil(expiresAt));
  useEffect(() => {
    setSecs(secondsUntil(expiresAt));
    const id = setInterval(() => setSecs(secondsUntil(expiresAt)), 1000);
    return () => clearInterval(id);
  }, [expiresAt]);
  if (secs === null) return <span>—</span>;
  const color = secs <= 5 ? "var(--destructive)" : secs <= 15 ? "var(--chart-4)" : "var(--chart-2)";
  return (
    <span className="inline-flex items-center gap-1">
      <span style={{ color, fontFamily: "JetBrains Mono, monospace" }}>
        {secs}s
      </span>
      {typeof ttl === "number" && (
        <span style={{ color: "var(--muted-foreground)", fontSize: "10px" }}>
          / {ttl}s TTL
        </span>
      )}
    </span>
  );
}

// ── Current VID card ──────────────────────────────────────────────────────────

function CurrentVidCard() {
  const { data, loading, error, refetch } = useVidShow();
  const { displayForDid } = useContactNames();

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center py-10">
        <Loader2 size={20} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
      </div>
    );
  }

  if (error && !data) {
    return <ErrorBlock message={error.message} />;
  }

  if (!data) return null;

  return (
    <div
      className="rounded-xl px-4 py-4 flex flex-col gap-3"
      style={{ background: "var(--card)", border: "1px solid var(--border)" }}
    >
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Fingerprint size={18} style={{ color: "var(--primary)" }} />
          <div>
            <div
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
              }}
            >
              Current VirtualID
            </div>
            <div
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
              }}
            >
              SHA256(DID ‖ DKP ‖ PCR ‖ policy ‖ nonce_I ‖ nonce_R)
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ChangeReasonBadge reason={data.changeReason} />
          <button
            onClick={refetch}
            className="flex items-center gap-1 rounded-md px-2.5 py-1"
            style={{
              fontSize: "var(--text-xs)",
              fontFamily: "Inter, sans-serif",
              color: "var(--muted-foreground)",
              background: "var(--muted)",
              border: "1px solid var(--border)",
              cursor: "pointer",
            }}
          >
            <RefreshCw size={11} />
            Refresh
          </button>
        </div>
      </div>

      {/* VID hash — big primary block */}
      <div
        className="rounded-md px-3 py-3"
        style={{
          background: "var(--muted)",
          border: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            fontSize: "10px",
            color: "var(--muted-foreground)",
            fontFamily: "Inter, sans-serif",
            marginBottom: "4px",
            display: "flex",
            alignItems: "center",
            gap: "4px",
          }}
        >
          <Fingerprint size={11} />
          Virtual ID
        </div>
        <div className="flex items-center gap-2">
          <code
            className="flex-1 break-all"
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "var(--text-xs)",
              color: "var(--foreground)",
              lineHeight: 1.5,
            }}
            title={data.virtualId}
          >
            {data.virtualId || "—"}
          </code>
          <CopyButton text={data.virtualId} />
        </div>
      </div>

      {/* Node + DID + session */}
      <div
        className="grid gap-2"
        style={{ gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}
      >
        <Field
          label="Node"
          value={data.node || "—"}
          icon={<Server size={11} />}
          copyValue={data.node}
        />
        <Field
          label="DID"
          value={displayForDid(data.did, shortDid(data.did) || "—")}
          icon={<Fingerprint size={11} />}
          copyValue={data.did}
        />
        <Field
          label="Session Expires"
          value={
            <ExpiryCountdown expiresAt={data.sessionExpiresAt} ttl={data.sessionTtl} />
          }
          icon={<Hourglass size={11} />}
        />
        <Field
          label="Session Expires At"
          value={fmtTime(data.sessionExpiresAt)}
          icon={<Clock size={11} />}
        />
      </div>

      {/* Input digests block */}
      <div>
        <div
          style={{
            fontSize: "10px",
            color: "var(--muted-foreground)",
            fontFamily: "Inter, sans-serif",
            marginBottom: "6px",
            display: "flex",
            alignItems: "center",
            gap: "4px",
          }}
        >
          <Layers size={11} />
          VID Inputs
        </div>
        <div
          className="grid gap-2"
          style={{ gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}
        >
          <DigestRow
            label="DKP"
            primary={`v${data.dkpVersion ?? "—"}`}
            secondary={
              typeof data.dkpBytes === "number" ? `${data.dkpBytes} bytes` : undefined
            }
            icon={<Key size={11} />}
          />
          <DigestRow
            label="PCR Digest"
            value={data.pcrDigest}
            icon={<Layers size={11} />}
          />
          <DigestRow
            label="Policy Digest"
            value={data.policyDigest}
            icon={<FileCheck size={11} />}
          />
          <DigestRow label="Nonce I (initiator)" value={data.nonceI} />
          <DigestRow label="Nonce R (responder)" value={data.nonceR} />
        </div>
      </div>
    </div>
  );
}

function DigestRow({
  label,
  value,
  primary,
  secondary,
  icon,
}: {
  label: string;
  value?: string;
  primary?: string;
  secondary?: string;
  icon?: React.ReactNode;
}) {
  return (
    <div
      className="flex items-center gap-2 rounded-md px-2 py-1.5"
      style={{ background: "var(--background)", border: "1px solid var(--border)" }}
    >
      <span
        style={{
          fontSize: "10px",
          fontFamily: "Inter, sans-serif",
          color: "var(--muted-foreground)",
          minWidth: "120px",
          display: "flex",
          alignItems: "center",
          gap: "4px",
        }}
      >
        {icon}
        {label}
      </span>
      <div className="flex-1 min-w-0 flex items-center gap-2">
        {value ? (
          <>
            <code
              className="truncate flex-1"
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "var(--text-xs)",
                color: "var(--foreground)",
              }}
              title={value}
            >
              {shortHex(value, 10, 8)}
            </code>
            <CopyButton text={value} />
          </>
        ) : (
          <>
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--foreground)",
                fontWeight: "var(--font-weight-medium)",
              }}
            >
              {primary ?? "—"}
            </span>
            {secondary && (
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "10px",
                  color: "var(--muted-foreground)",
                  marginLeft: "auto",
                }}
              >
                {secondary}
              </span>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ── Peer rows ─────────────────────────────────────────────────────────────────

function PeerVidRow({ peer }: { peer: VidPeer }) {
  const [open, setOpen] = useState(false);
  const peerLabel = peer.nodeName?.trim() || "Unmapped Guardian";
  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ background: "var(--card)", border: "1px solid var(--border)" }}
    >
      <button
        className="w-full flex items-center justify-between gap-3 px-4 py-3"
        onClick={() => setOpen((v) => !v)}
        style={{
          background: "none",
          border: "none",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <Fingerprint size={14} style={{ color: "var(--chart-1)", flexShrink: 0 }} />
          <div className="min-w-0">
            <div
              className="truncate"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
              }}
              title={peer.nodeName || "No DID registry node name is available"}
            >
              {peerLabel}
            </div>
            <div
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "10px",
                color: "var(--muted-foreground)",
              }}
              title={peer.did}
            >
              DID {shortDid(peer.did)} · VID {shortHex(peer.virtualId, 10, 8)} · {fmtTime(peer.observedAt)}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <ChangeReasonBadge reason={peer.lastRotationReason} />
          {open ? (
            <ChevronUp size={14} style={{ color: "var(--muted-foreground)" }} />
          ) : (
            <ChevronDown size={14} style={{ color: "var(--muted-foreground)" }} />
          )}
        </div>
      </button>
      {open && (
        <div
          className="px-4 py-3 flex flex-col gap-2"
          style={{ borderTop: "1px solid var(--border)" }}
        >
          {peer.nodeName && <Field label="Guardian Node" value={peer.nodeName} />}
          <Field label="DID" value={peer.did} mono copyValue={peer.did} />
          <Field
            label="Virtual ID"
            value={peer.virtualId}
            mono
            copyValue={peer.virtualId}
          />
          <Field
            label="Observed At"
            value={fmtTime(peer.observedAt)}
            icon={<Clock size={11} />}
          />
          {peer.lastRotationReason && (
            <Field label="Last Rotation Reason" value={peer.lastRotationReason} />
          )}
        </div>
      )}
    </div>
  );
}

function PeersList() {
  const { data, loading, error, refetch } = useVidPeers();
  const peers = useMemo(() => data?.peers ?? [], [data]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Users size={14} style={{ color: "var(--muted-foreground)" }} />
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
            }}
          >
            Peer VirtualIDs
          </span>
          <span
            className="rounded-md px-1.5 py-0.5"
            style={{
              fontSize: "10px",
              fontFamily: "Inter, sans-serif",
              color: "var(--muted-foreground)",
              background: "var(--muted)",
              border: "1px solid var(--border)",
            }}
          >
            {peers.length}
          </span>
        </div>
        <button
          onClick={refetch}
          className="flex items-center gap-1 rounded-md px-2.5 py-1"
          style={{
            fontSize: "var(--text-xs)",
            fontFamily: "Inter, sans-serif",
            color: "var(--muted-foreground)",
            background: "var(--muted)",
            border: "1px solid var(--border)",
            cursor: "pointer",
          }}
        >
          <RefreshCw size={11} />
          Refresh
        </button>
      </div>

      {loading && peers.length === 0 && (
        <div className="flex items-center justify-center py-10">
          <Loader2 size={20} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
        </div>
      )}
      {error && peers.length === 0 && <ErrorBlock message={error.message} />}
      {!loading && !error && peers.length === 0 && (
        <div className="flex flex-col items-center justify-center py-12 gap-2">
          <Users size={36} style={{ color: "var(--muted-foreground)", opacity: 0.4 }} />
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              color: "var(--muted-foreground)",
            }}
          >
            No peer VirtualIDs observed yet
          </p>
        </div>
      )}
      {peers.map((p) => (
        <PeerVidRow key={p.did} peer={p} />
      ))}
    </div>
  );
}

export function SC04VirtualId() {
  return (
    <div className="flex flex-col h-full" style={{ background: "var(--background)" }}>
      <PageHeader
        title="Virtual ID"
        subtitle="Session-bound identifier derived from DID, DKP, PCR, policy, and nonces"
        icon={<Fingerprint size={20} />}
      />
      <div
        className="flex-1 overflow-y-auto px-4 py-4 flex flex-col"
        style={{ gap: "16px" }}
      >
        <CurrentVidCard />
        <PeersList />
      </div>
    </div>
  );
}

export default SC04VirtualId;
