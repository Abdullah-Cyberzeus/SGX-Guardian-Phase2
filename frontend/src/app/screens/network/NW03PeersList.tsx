import { useState, useMemo } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  ShieldCheck,
  Clock,
  RefreshCw,
  Loader2,
  Network,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  ChevronRight,
} from "lucide-react";
import { usePeers } from "../../hooks/useApiData";
import { useContactNames } from "../../contexts/ContactNameContext";
import { peerService, type Peer } from "../../services/peerService";
import { toast } from "sonner";

type FilterTab = "all" | "verified" | "pending" | "failed";

/** Full-word relative time for the network-status banner (e.g. "2 days ago"),
 *  distinct from the compact "2d ago" used on individual peer rows. */
function formatVerifiedAgo(isoDate: string): string {
  const diffMs = Date.now() - new Date(isoDate).getTime();
  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function StatusBadge({ status }: { status: Peer["status"] }) {
  const config = {
    verified: {
      label: "Verified",
      color: "var(--chart-2)",
      icon: CheckCircle2,
    },
    pending: {
      label: "Pending",
      color: "var(--chart-5)",
      icon: Clock,
    },
    failed: {
      label: "Failed",
      color: "var(--destructive)",
      icon: XCircle,
    },
  }[status];

  const Icon = config.icon;

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full"
      style={{
        backgroundColor: `color-mix(in srgb, ${config.color} 15%, transparent)`,
        border: `1px solid color-mix(in srgb, ${config.color} 30%, transparent)`,
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        color: config.color,
      }}
    >
      <Icon size={12} />
      {config.label}
    </span>
  );
}

function PeerCard({
  peer,
  onAttest,
  attesting,
}: {
  peer: Peer;
  onAttest: (id: string) => void;
  attesting: boolean;
}) {
  const { displayForDid } = useContactNames();
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const peerDisplayName = displayForDid(peer.did, peer.peerId);

  const copyPeerId = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(peer.peerId);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div
      className="rounded-lg border overflow-hidden"
      style={{
        backgroundColor: "var(--card)",
        borderColor: peer.status === "failed"
          ? "color-mix(in srgb, var(--destructive) 30%, var(--border))"
          : "var(--border)",
      }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left"
        style={{ backgroundColor: "transparent", border: "none", cursor: "pointer" }}
      >
        {/* Status dot */}
        <div
          className="flex-shrink-0 rounded-full"
          style={{
            width: "10px",
            height: "10px",
            backgroundColor:
              peer.status === "verified"
                ? "var(--chart-2)"
                : peer.status === "pending"
                ? "var(--chart-5)"
                : "var(--destructive)",
          }}
        />

        {/* Peer info */}
        <div className="flex-1 min-w-0">
          <p
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
              marginBottom: "2px",
            }}
          >
            {peerDisplayName}
          </p>
          <div className="flex items-center gap-2">
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
              }}
            >
              {peer.lastSeenAgo}
            </span>
            <span style={{ fontSize: "var(--text-xs)", color: peer.online ? "var(--chart-2)" : "var(--muted-foreground)" }}>
              · {peer.online ? "Online" : "Offline"}
            </span>
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
              }}
            >
              ·
            </span>
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
              }}
            >
              {peer.attestationCount} attestations
            </span>
          </div>
        </div>

        <StatusBadge status={peer.status} />
      </button>

      {expanded && (
        <div
          className="px-4 pb-4 pt-2 border-t flex flex-col gap-3"
          style={{ borderColor: "var(--border)" }}
        >
          {/* Details grid */}
          <div className="flex flex-col gap-2">
            {[
              { label: "Peer ID", value: displayForDid(peer.did, peer.peerId), mono: true },
              { label: "IP Address", value: peer.ip, mono: true },
              { label: "Port", value: String(peer.port), mono: true },
              { label: "Last Seen", value: new Date(peer.lastSeen).toLocaleString(), mono: false },
              { label: "Attestations", value: String(peer.attestationCount), mono: false },
            ].map(({ label, value, mono }) => (
              <div key={label} className="flex items-center justify-between">
                <span
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    color: "var(--muted-foreground)",
                  }}
                >
                  {label}
                </span>
                <span
                  style={{
                    fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-medium)",
                    color: "var(--foreground)",
                  }}
                >
                  {value}
                </span>
              </div>
            ))}
          </div>

          {/* Actions */}
          <div className="flex gap-2">
            <button
              onClick={copyPeerId}
              className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
              style={{
                height: "40px",
                backgroundColor: "var(--muted)",
                color: "var(--foreground)",
                border: "1px solid var(--border)",
                cursor: "pointer",
                borderRadius: "var(--radius)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-medium)",
              }}
            >
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? "Copied" : "Copy Peer ID"}
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onAttest(peer.id);
              }}
              disabled={attesting}
              className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
              style={{
                height: "40px",
                backgroundColor: "var(--primary)",
                color: "var(--primary-foreground)",
                border: "none",
                cursor: attesting ? "not-allowed" : "pointer",
                borderRadius: "var(--radius)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)",
                opacity: attesting ? 0.7 : 1,
              }}
            >
              {attesting ? (
                <RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} />
              ) : (
                <ShieldCheck size={14} />
              )}
              {attesting ? "Attesting..." : "Attest"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function NW03PeersList() {
  const navigate = useNavigate();
  const { data: peersData, loading, source, refetch } = usePeers();
  const [filter, setFilter] = useState<FilterTab>("all");
  const [attestingId, setAttestingId] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const peers: Peer[] = useMemo(() => {
    if (!peersData) return [];
    return Array.isArray(peersData) ? peersData : [];
  }, [peersData]);

  const filteredPeers = useMemo(() => {
    if (filter === "all") return peers;
    return peers.filter((p) => p.status === filter);
  }, [peers, filter]);

  const counts = useMemo(() => ({
    all: peers.length,
    verified: peers.filter((p) => p.status === "verified").length,
    pending: peers.filter((p) => p.status === "pending").length,
    failed: peers.filter((p) => p.status === "failed").length,
  }), [peers]);

  const lastVerifiedAgo = useMemo(() => {
    const verifiedTimestamps = peers
      .filter((p) => p.status === "verified" && p.lastSeen)
      .map((p) => new Date(p.lastSeen).getTime())
      .filter((t) => !Number.isNaN(t));
    if (verifiedTimestamps.length === 0) return null;
    return formatVerifiedAgo(new Date(Math.max(...verifiedTimestamps)).toISOString());
  }, [peers]);

  const handleAttest = async (peerId: string) => {
    setAttestingId(peerId);
    try {
      await peerService.attest(peerId);
      toast.success("Attestation initiated", { description: `Peer ${peerId} attestation started` });
    } catch {
      toast.error("Attestation failed", { description: "Could not initiate attestation" });
    } finally {
      setTimeout(() => setAttestingId(null), 1200);
    }
  };

  const handleRefreshAll = async () => {
    setIsRefreshing(true);
    await refetch();
    setTimeout(() => {
      setIsRefreshing(false);
      toast.success("Peers refreshed", { description: `${peers.length} peers discovered` });
    }, 1000);
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading peers...</span>
      </div>
    );
  }

  const filters: { id: FilterTab; label: string }[] = [
    { id: "all", label: "All" },
    { id: "verified", label: "Verified" },
    { id: "pending", label: "Pending" },
    { id: "failed", label: "Failed" },
  ];

  const dataSourceColor = source === "api" ? "var(--chart-2)" : "var(--chart-5)";

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Peers" subtitle="Circle of Trust" onBack={() => navigate("/network")} />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-4xl">
        {/* Stats row */}
        <div className="grid grid-cols-3 gap-3 p-4 pb-0">
          <div
            className="rounded-lg border p-3 text-center"
            style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}
          >
            <CheckCircle2 size={18} style={{ color: "var(--chart-2)", margin: "0 auto 8px" }} />
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-lg)",
                fontWeight: "var(--font-weight-bold)",
                color: "var(--chart-2)",
              }}
            >
              {counts.verified}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Verified
            </p>
          </div>
          <div
            className="rounded-lg border p-3 text-center"
            style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}
          >
            <Clock size={18} style={{ color: "var(--chart-5)", margin: "0 auto 8px" }} />
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-lg)",
                fontWeight: "var(--font-weight-bold)",
                color: "var(--chart-5)",
              }}
            >
              {counts.pending}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Pending
            </p>
          </div>
          <div
            className="rounded-lg border p-3 text-center"
            style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}
          >
            <XCircle
              size={18}
              style={{
                color: counts.failed > 0 ? "var(--destructive)" : "var(--muted-foreground)",
                margin: "0 auto 8px",
              }}
            />
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-lg)",
                fontWeight: "var(--font-weight-bold)",
                color: counts.failed > 0 ? "var(--destructive)" : "var(--foreground)",
              }}
            >
              {counts.failed}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Failed
            </p>
          </div>
        </div>

        {/* Filter tabs */}
        <div className="px-4 py-3">
          <div className="flex p-1 rounded-lg" style={{ backgroundColor: "var(--muted)" }}>
            {filters.map(({ id, label }) => (
              <button
                key={id}
                onClick={() => setFilter(id)}
                className="flex-1 flex items-center justify-center gap-1"
                style={{
                  height: "32px",
                  borderRadius: "var(--radius)",
                  backgroundColor: filter === id ? "var(--card)" : "transparent",
                  color: filter === id ? "var(--foreground)" : "var(--muted-foreground)",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: filter === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                  border: filter === id ? "1px solid var(--border)" : "none",
                  cursor: "pointer",
                }}
              >
                {label}
                {counts[id] > 0 && (
                  <span
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "10px",
                      color: filter === id ? "var(--primary)" : "var(--muted-foreground)",
                      fontWeight: "var(--font-weight-semibold)",
                    }}
                  >
                    {counts[id]}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Peer cards */}
        <div className="flex flex-col gap-3 px-4 pb-4">
          {filteredPeers.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-12 text-center">
              <Network size={40} style={{ color: "var(--muted-foreground)" }} />
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-medium)",
                  color: "var(--foreground)",
                }}
              >
                No {filter === "all" ? "" : filter} peers found
              </p>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                  maxWidth: "240px",
                }}
              >
                {filter === "all"
                  ? "No peers have been discovered yet."
                  : `No peers with status "${filter}".`}
              </p>
            </div>
          ) : (
            filteredPeers.map((peer) => (
              <PeerCard
                key={peer.id}
                peer={peer}
                onAttest={handleAttest}
                attesting={attestingId === peer.id}
              />
            ))
          )}
        </div>

        {/* Topology link */}
        <div className="px-4 pb-4">
          <button
            onClick={() => navigate("/home/topology")}
            className="w-full flex items-center justify-between p-4 rounded-lg border transition-opacity active:opacity-80"
            style={{
              backgroundColor: "var(--card)",
              borderColor: "var(--border)",
              cursor: "pointer",
            }}
          >
            <div className="flex items-center gap-3">
              <div
                className="flex items-center justify-center rounded-lg"
                style={{
                  width: "36px",
                  height: "36px",
                  backgroundColor: "color-mix(in srgb, var(--primary) 14%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--primary) 24%, transparent)",
                }}
              >
                <Network size={18} style={{ color: "var(--primary)" }} />
              </div>
              <div>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-semibold)",
                    color: "var(--foreground)",
                  }}
                >
                  View Network Topology
                </p>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    color: "var(--muted-foreground)",
                  }}
                >
                  Visual map of peer connections
                </p>
              </div>
            </div>
            <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />
          </button>
        </div>

        {/* Refresh button */}
        <div className="px-4 pb-4">
          <button
            onClick={handleRefreshAll}
            disabled={isRefreshing}
            className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-80"
            style={{
              backgroundColor: "var(--primary)",
              color: "var(--primary-foreground)",
              border: "none",
              cursor: isRefreshing ? "not-allowed" : "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              opacity: isRefreshing ? 0.7 : 1,
            }}
          >
            <RefreshCw size={16} style={{ animation: isRefreshing ? "spin 1s linear infinite" : "none" }} />
            {isRefreshing ? "Discovering Peers..." : "Refresh Peers"}
          </button>
        </div>

        {/* Network verification status */}
        <div className="px-4 pb-6">
          <div
            className="flex items-start gap-3 p-4 rounded-lg"
            style={{
              backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)",
              border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)",
            }}
          >
            <Network size={18} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
            <div>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--primary)",
                  lineHeight: 1.5,
                }}
              >
                {counts.verified > 0
                  ? `Your Guardian network is verified and secure. Peer verification last completed ${lastVerifiedAgo || "recently"}.`
                  : "Your Guardian network has no verified peers yet."}
              </p>
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "10px",
                  color: dataSourceColor,
                  fontWeight: "var(--font-weight-medium)",
                  marginTop: "4px",
                }}
              >
                Source: {source === "api" ? "Server" : "Offline"}
              </p>
            </div>
          </div>
        </div>
        </div>
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
