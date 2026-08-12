import { useMemo, useState } from "react";
import { ArrowDownLeft, ArrowUpRight, Clock, Loader2, Phone, Search, Users, Video } from "lucide-react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { useCallHistory } from "../../hooks/useCallHistory";
import { useCommunicationPeers } from "../../hooks/useApiData";
import type { CallHistoryRecord } from "../../services/callHistoryService";
import { useCall } from "../../../features/calls/CallContext";
import { useGroupCall } from "../../../features/calls/GroupCallContext";
import type { MediaType } from "../../../features/calls/call.types";
import { useContactNames } from "../../contexts/ContactNameContext";
import { toast } from "sonner";

function duration(seconds: number) {
  if (!seconds) return "No answer";
  const hours = Math.floor(seconds / 3600), minutes = Math.floor((seconds % 3600) / 60), remainder = seconds % 60;
  return hours ? `${hours}h ${minutes}m` : minutes ? `${minutes}m ${remainder}s` : `${remainder}s`;
}

function outcomeLabel(record: CallHistoryRecord) {
  return { completed: duration(record.durationSeconds), missed: "Missed", declined: "Declined", cancelled: "Cancelled", failed: "Failed" }[record.outcome];
}

export function CallsHistoryScreen() {
  const navigate = useNavigate();
  const history = useCallHistory();
  const { data: peersData, loading } = useCommunicationPeers();
  const { displayForDid } = useContactNames();
  const [query, setQuery] = useState("");
  const [starting, setStarting] = useState<string | null>(null);
  const { startCall, call, currentDevice } = useCall();
  const groupCalling = useGroupCall();
  const peers = Array.isArray(peersData) ? peersData : [];
  const peerName = (id: string) => {
    const peer = peers.find((item: any) => item.peerId === id);
    return displayForDid(peer?.did, peer?.peerId || id);
  };
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return needle ? history.filter((record) => `${record.title} ${record.participantIds.map(peerName).join(" ")} ${record.participantIds.join(" ")} ${record.outcome}`.toLowerCase().includes(needle)) : history;
  }, [history, query, peers, displayForDid]);

  const startAgain = async (record: CallHistoryRecord, media: MediaType[]) => {
    if (call || groupCalling.group) {
      toast.error("Guardian is busy", { description: "End or leave the current call before starting another." });
      return;
    }
    const mode = media.includes("video") ? "video" : "audio";
    const key = `${record.id}:${mode}`;
    setStarting(key);
    try {
      if (record.kind === "group") {
        const participantIds = Array.from(new Set(record.participantIds.filter((id) => id && id !== currentDevice)));
        if (!participantIds.length) throw new Error("No group participants are available to call.");
        await groupCalling.createGroup(participantIds, false, media, record.title || "Group call");
        toast.success(`Calling ${participantIds.length} group participant${participantIds.length === 1 ? "" : "s"}`);
      } else {
        const target = record.participantIds[0];
        const targetPeer = peers.find((peer: any) => peer.peerId === target);
        if (!target) throw new Error("The peer for this call is unavailable.");
        if (targetPeer && (!targetPeer.callAvailable || !targetPeer.online)) {
          throw new Error(targetPeer.callUnavailableReason || "The peer is currently offline.");
        }
        await startCall(target, media);
      }
    } catch (cause) {
      toast.error("Call could not start", { description: cause instanceof Error ? cause.message : "One or more participants may be unavailable." });
    } finally {
      setStarting(null);
    }
  };

  return <div className="flex h-full flex-col">
    <PageHeader title="Calls" subtitle={`${history.length} call${history.length === 1 ? "" : "s"} in history`} />
    <div className="shrink-0 border-b border-border bg-card p-3 md:px-6">
      <div className="mx-auto flex max-w-3xl gap-2">
        <button onClick={() => navigate("/chats")} className="rounded-full border border-border px-4 text-sm font-medium">Chats</button>
        <label className="flex h-11 flex-1 items-center gap-2 rounded-full border border-border bg-input-background px-4"><Search size={17} className="text-muted-foreground" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search call history" className="min-w-0 flex-1 bg-transparent text-sm outline-none" /></label>
      </div>
    </div>
    <div className="flex-1 overflow-y-auto"><div className="mx-auto max-w-3xl divide-y divide-border">
      {loading && <div className="grid place-items-center p-12"><Loader2 className="animate-spin" /></div>}
      {!loading && visible.length === 0 && <div className="flex flex-col items-center gap-3 p-12 text-center"><Clock size={40} className="text-muted-foreground" /><p className="text-sm font-semibold">No call history yet</p><p className="max-w-xs text-xs text-muted-foreground">Audio and video calls will appear here with participants, time, outcome, and duration.</p></div>}
      {visible.map((record) => {
        const video = record.media.includes("video");
        const failed = record.outcome !== "completed";
        return <div key={record.id} className="flex items-center gap-3 px-4 py-3.5 md:px-6">
          <div className="grid h-12 w-12 shrink-0 place-items-center rounded-full bg-primary/15 text-primary">{record.kind === "group" ? <Users size={20} /> : video ? <Video size={20} /> : <Phone size={20} />}</div>
          <div className="min-w-0 flex-1"><p className="truncate text-sm font-semibold">{record.kind === "group" ? record.title : peerName(record.participantIds[0])}</p><div className={`flex items-center gap-1 text-xs ${failed ? "text-destructive" : "text-muted-foreground"}`}>{record.direction === "incoming" ? <ArrowDownLeft size={13} /> : <ArrowUpRight size={13} />}<span>{record.direction === "incoming" ? "Incoming" : "Outgoing"} {video ? "video" : "audio"} · {outcomeLabel(record)}</span></div>{record.kind === "group" && <p className="truncate text-[11px] text-muted-foreground">{record.participantIds.map(peerName).join(", ")}</p>}</div>
          <div className="flex shrink-0 items-center gap-1">
            <time className="mr-1 hidden self-start pt-1 text-[10px] text-muted-foreground sm:block">{new Date(record.startedAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</time>
            <button aria-label={`Call ${record.kind === "group" ? record.title : peerName(record.participantIds[0])}`} title={record.kind === "group" ? "Call group" : "Voice call"} disabled={starting !== null} onClick={() => void startAgain(record, ["audio"])} className="grid h-9 w-9 place-items-center rounded-full text-primary hover:bg-primary/10 disabled:opacity-40">{starting === `${record.id}:audio` ? <Loader2 size={17} className="animate-spin" /> : record.kind === "group" ? <Users size={17} /> : <Phone size={17} />}</button>
            <button aria-label={`Video call ${record.kind === "group" ? record.title : peerName(record.participantIds[0])}`} title={record.kind === "group" ? "Video call group" : "Video call"} disabled={starting !== null} onClick={() => void startAgain(record, ["audio", "video"])} className="grid h-9 w-9 place-items-center rounded-full text-primary hover:bg-primary/10 disabled:opacity-40">{starting === `${record.id}:video` ? <Loader2 size={17} className="animate-spin" /> : <Video size={17} />}</button>
          </div>
        </div>;
      })}
    </div></div>
  </div>;
}
