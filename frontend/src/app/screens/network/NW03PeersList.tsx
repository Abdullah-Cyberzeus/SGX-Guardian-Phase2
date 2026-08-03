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
  Phone,
  Video,
  Users,
} from "lucide-react";
import { usePeers } from "../../hooks/useApiData";
import { peerService, type Peer } from "../../services/peerService";
import { toast } from "sonner";
import { useCall } from "../../../features/calls/CallContext";
import { useGroupCall } from "../../../features/calls/GroupCallContext";
import type { MediaType } from "../../../features/calls/call.types";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "../../components/ui/dialog";

type FilterTab = "all" | "verified" | "pending" | "failed";

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
  onCall,
  selected,
  onSelect,
  attesting,
}: {
  peer: Peer;
  onAttest: (id: string) => void;
  onCall: (peerId: string, media: MediaType[]) => void;
  selected: boolean;
  onSelect: (peerId: string) => void;
  attesting: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

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
            {peer.peerId}
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
              { label: "Peer ID", value: peer.peerId, mono: true },
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
            {peer.callAvailable && (
              <button
                onClick={(event) => { event.stopPropagation(); onSelect(peer.peerId); }}
                className="flex items-center justify-center rounded-lg px-3"
                style={{ height: 40, background: selected ? "var(--primary)" : "var(--secondary)", color: selected ? "var(--primary-foreground)" : "var(--foreground)", border: "1px solid var(--border)", cursor: "pointer" }}
              >{selected ? "Selected" : "Add to group"}</button>
            )}
            {peer.callAvailable && <>
              <button
                onClick={(event) => { event.stopPropagation(); onCall(peer.peerId, ["audio"]); }}
                aria-label={`Voice call ${peer.peerId}`}
                className="flex items-center justify-center rounded-lg"
                disabled={!peer.callAvailable}
                title={peer.callUnavailableReason}
                style={{ width: 40, height: 40, background: "var(--secondary)", border: "1px solid var(--border)", color: "var(--foreground)", cursor: peer.callAvailable ? "pointer" : "not-allowed", opacity: peer.callAvailable ? 1 : .45 }}
              ><Phone size={15} /></button>
              <button
                onClick={(event) => { event.stopPropagation(); onCall(peer.peerId, ["audio", "video"]); }}
                aria-label={`Video call ${peer.peerId}`}
                className="flex items-center justify-center rounded-lg"
                disabled={!peer.callAvailable}
                title={peer.callUnavailableReason}
                style={{ width: 40, height: 40, background: "var(--secondary)", border: "1px solid var(--border)", color: "var(--foreground)", cursor: peer.callAvailable ? "pointer" : "not-allowed", opacity: peer.callAvailable ? 1 : .45 }}
              ><Video size={15} /></button>
            </>}
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
  const { startCall, call } = useCall();
  const groupCalling = useGroupCall();
  const [selectedPeers, setSelectedPeers] = useState<string[]>([]);
  const [groupDialogOpen, setGroupDialogOpen] = useState(false);
  const [groupTitle, setGroupTitle] = useState("Guardian group call");
  const [groupMedia, setGroupMedia] = useState<MediaType[]>(["audio", "video"]);
  const [startingGroup, setStartingGroup] = useState(false);

  const handleCall = async (peerId: string, media: MediaType[]) => {
    if (call) {
      toast.error("Guardian is busy", { description: "End the current call before starting another." });
      return;
    }
    if (groupCalling.group) {
      toast.error("A group session is still open", {
        description: "Rejoin it or leave/end that session before starting a new call.",
      });
      return;
    }
    try {
      await startCall(peerId, media);
    } catch (cause) {
      toast.error("Call could not start", {
        description: cause instanceof Error ? cause.message : "The remote Guardian may be offline or busy.",
      });
    }
  };

  const toggleGroupPeer = (peerId: string) => {
    setSelectedPeers((current) => current.includes(peerId)
      ? current.filter((item) => item !== peerId)
      : [...current, peerId]);
  };

  const startGroupCall = async (media: MediaType[]) => {
    if (!selectedPeers.length) return;
    if (call || groupCalling.group) {
      toast.error("Guardian is busy", {
        description: "End, leave, or dismiss the current call session first.",
      });
      return;
    }
    setStartingGroup(true);
    try {
      await groupCalling.createGroup(selectedPeers, false, media, groupTitle.trim() || "Guardian group call");
      setSelectedPeers([]);
      setGroupDialogOpen(false);
    } catch (cause) {
      toast.error("Group call could not start", {
        description: cause instanceof Error ? cause.message : "One or more Guardians may be unavailable.",
      });
    } finally {
      setStartingGroup(false);
    }
  };

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
  const callablePeers = useMemo(
    () => peers.filter((peer) => peer.callAvailable && peer.online),
    [peers],
  );

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

        <div className="px-4 pt-4">
          <Button
            className="h-11 w-full gap-2"
            disabled={callablePeers.length === 0 || !!call || !!groupCalling.group}
            onClick={() => setGroupDialogOpen(true)}
          >
            <Users size={17} /> Create group call
          </Button>
          {(call || groupCalling.group) && (
            <p className="mt-2 text-center text-xs text-muted-foreground">
              Finish or leave the current call before creating another.
            </p>
          )}
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
                onCall={(peerId, media) => void handleCall(peerId, media)}
                selected={selectedPeers.includes(peer.peerId)}
                onSelect={toggleGroupPeer}
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

        {/* Data source + CLI info */}
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
                Peers are discovered and attested via <code style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px" }}>sgx-pa-cli peers</code>.
                Data sourced from <code style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px" }}>trusted_peers.json</code>.
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

      <Dialog open={groupDialogOpen} onOpenChange={(open) => { if (!startingGroup) setGroupDialogOpen(open); }}>
        <DialogContent className="max-h-[85vh] overflow-hidden sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Create a group call</DialogTitle>
            <DialogDescription>
              Choose trusted online members and the media they may use. You will be the host and can control participant microphones, cameras, and membership.
            </DialogDescription>
          </DialogHeader>

          <label className="space-y-1.5 text-xs font-medium">
            Call name
            <Input value={groupTitle} maxLength={80} onChange={(event) => setGroupTitle(event.target.value)} placeholder="Guardian group call" />
          </label>

          <div className="flex gap-2">
            <Button
              type="button"
              variant={groupMedia.includes("audio") ? "default" : "outline"}
              className="flex-1 gap-2"
              aria-pressed={groupMedia.includes("audio")}
              onClick={() => setGroupMedia((current) =>
                current.includes("audio") ? current.filter((item) => item !== "audio") : [...current, "audio"]
              )}
            >
              <Phone size={15} /> Voice
            </Button>
            <Button
              type="button"
              variant={groupMedia.includes("video") ? "default" : "outline"}
              className="flex-1 gap-2"
              aria-pressed={groupMedia.includes("video")}
              onClick={() => setGroupMedia((current) =>
                current.includes("video") ? current.filter((item) => item !== "video") : [...current, "video"]
              )}
            >
              <Video size={15} /> Video
            </Button>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Invite members</p>
              <p className="text-xs text-muted-foreground">{selectedPeers.length} of {callablePeers.length} selected</p>
            </div>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setSelectedPeers(
                selectedPeers.length === callablePeers.length ? [] : callablePeers.map((peer) => peer.peerId)
              )}
            >
              {selectedPeers.length === callablePeers.length ? "Clear all" : "Select all"}
            </Button>
          </div>

          <div className="max-h-64 space-y-2 overflow-y-auto rounded-lg border border-border p-2">
            {callablePeers.map((peer) => {
              const selected = selectedPeers.includes(peer.peerId);
              return (
                <button
                  type="button"
                  key={peer.peerId}
                  aria-pressed={selected}
                  onClick={() => toggleGroupPeer(peer.peerId)}
                  className="flex w-full items-center gap-3 rounded-md p-3 text-left hover:bg-muted/60"
                  style={{ background: selected ? "color-mix(in srgb, var(--primary) 12%, transparent)" : undefined }}
                >
                  <span
                    className="grid h-5 w-5 shrink-0 place-items-center rounded border"
                    style={{ borderColor: selected ? "var(--primary)" : "var(--border)", background: selected ? "var(--primary)" : "transparent", color: "var(--primary-foreground)" }}
                  >
                    {selected && <Check size={13} />}
                  </span>
                  <span className="min-w-0 flex-1">
                    <strong className="block truncate text-sm">{peer.peerId}</strong>
                    <span className="block truncate text-xs text-muted-foreground">{peer.ip} · Online and verified</span>
                  </span>
                </button>
              );
            })}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" disabled={startingGroup} onClick={() => setGroupDialogOpen(false)}>Cancel</Button>
            <Button
              type="button"
              disabled={startingGroup || selectedPeers.length === 0 || groupMedia.length === 0}
              onClick={() => void startGroupCall(groupMedia)}
              className="gap-2"
            >
              {startingGroup ? <Loader2 size={15} className="animate-spin" /> : <Users size={15} />}
              {startingGroup ? "Starting secure call…" : `Call ${selectedPeers.length} member${selectedPeers.length === 1 ? "" : "s"}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
