import { useEffect, useMemo, useState } from "react";
import { CalendarDays, Loader2, MessageSquare, Phone, Search, ShieldCheck, Smartphone, Users, Video, X } from "lucide-react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { useCommunicationPeers } from "../../hooks/useApiData";
import type { Peer } from "../../services/peerService";
import { contactRepository } from "../../../pwa/db/contactRepository";
import { useGuardianConnectivity } from "../../../pwa/connectivity/GuardianConnectivityContext";
import { useCall } from "../../../features/calls/CallContext";
import { useGroupCall } from "../../../features/calls/GroupCallContext";
import type { MediaType } from "../../../features/calls/call.types";

function initials(peer: Peer) {
  return (peer.displayName || peer.peerId).split(/[-_:\s]/).filter(Boolean).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "P";
}

function dedupePeers(peers: Peer[]) {
  const byDid = new Map<string, Peer>();
  for (const peer of peers) {
    if (!peer.did) continue;
    const existing = byDid.get(peer.did);
    byDid.set(peer.did, existing ? { ...existing, ...peer, online: existing.online || peer.online } : peer);
  }
  return [...byDid.values()];
}

function dateLabel(value?: string) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
}

function profileTarget(peer: Peer) {
  return peer.memberType === "browser" ? peer.did || peer.peerId : peer.peerId || peer.did;
}

export function MemberContactsScreen() {
  const navigate = useNavigate();
  const { data, loading, error, refetch } = useCommunicationPeers();
  const { reachable } = useGuardianConnectivity();
  const { startCall, call } = useCall();
  const groupCalling = useGroupCall();
  const [cached, setCached] = useState<Peer[]>([]);
  const [query, setQuery] = useState("");
  const [selectedDid, setSelectedDid] = useState<string | null>(null);
  const [startingCall, setStartingCall] = useState<"audio" | "video" | null>(null);
  useEffect(() => {
    if (Array.isArray(data)) {
      const current = dedupePeers(data as Peer[]);
      setCached(current);
      current.filter((peer) => peer.did).forEach((peer) => void contactRepository.save({
        did: peer.did!,
        displayName: peer.displayName || peer.peerId,
        fullName: peer.fullName,
        deviceName: peer.deviceName,
        role: peer.role,
        memberType: peer.memberType,
        joinDate: peer.joinDate,
        online: peer.online,
        presenceStatus: peer.presenceStatus,
        presenceStale: peer.presenceStale,
        lastSeen: peer.lastSeenAgo,
        updatedAt: Date.now(),
      }));
    } else if (error) {
      void contactRepository.list().then((items) => setCached(dedupePeers(items.map((item) => ({
        id: `cached_${item.did}`,
        peerId: item.did,
        displayName: item.displayName,
        fullName: item.fullName,
        deviceName: item.deviceName || "Cached device",
        did: item.did,
        ip: "",
        port: 0,
        status: "verified",
        role: item.role || "member",
        memberType: item.memberType || "guardian",
        joinDate: item.joinDate,
        online: false,
        presenceStatus: "stale",
        presenceStale: true,
        lastSeen: "",
        lastSeenAgo: item.lastSeen || "Cached",
        attestationCount: 0,
        callAvailable: false,
      } as Peer)))));
    }
  }, [data, error]);
  const contacts = useMemo(() => {
    const all = dedupePeers((Array.isArray(data) ? data : cached).filter((peer: Peer) => peer.status === "verified" && Boolean(peer.did)));
    const needle = query.trim().toLowerCase();
    return needle ? all.filter((peer: Peer) => `${peer.displayName} ${peer.fullName || ""} ${peer.deviceName} ${peer.role} ${peer.peerId} ${peer.did}`.toLowerCase().includes(needle)) : all;
  }, [data, cached, query]);
  const selected = contacts.find((peer) => peer.did === selectedDid) || null;
  const staleRoster = Boolean(error || !reachable || contacts.some((peer) => peer.presenceStale));

  const startContactCall = async (peer: Peer, media: MediaType[]) => {
    if (!peer.callAvailable) return;
    if (call || groupCalling.group) {
      toast.error("Guardian is busy", { description: "End or leave the current call before starting another." });
      return;
    }
    const target = profileTarget(peer);
    if (!target) {
      toast.error("Contact cannot be called", { description: "This contact has no callable identity." });
      return;
    }
    const mode = media.includes("video") ? "video" : "audio";
    setStartingCall(mode);
    try {
      await startCall(target, media, peer.online && !peer.presenceStale);
    } catch (cause) {
      toast.error("Call could not start", { description: cause instanceof Error ? cause.message : "The contact may be unavailable." });
    } finally {
      setStartingCall(null);
    }
  };

  return <div className="flex h-full flex-col">
    <PageHeader title="Contacts" subtitle="Trusted communication contacts" />
    {staleRoster && <div className="border-b border-border bg-muted/40 px-4 py-2 text-center text-xs text-muted-foreground">Showing cached roster or stale presence</div>}
    <div className="shrink-0 border-b border-border bg-card p-3 md:px-6">
      <label className="mx-auto flex h-11 max-w-3xl items-center gap-2 rounded-full border border-border bg-input-background px-4">
        <Search size={17} className="text-muted-foreground" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search contacts" className="min-w-0 flex-1 bg-transparent text-sm outline-none" />
      </label>
    </div>
    <div className="flex-1 overflow-y-auto"><div className="mx-auto max-w-3xl divide-y divide-border">
      {loading && <div className="flex items-center justify-center gap-2 p-12 text-sm text-muted-foreground"><Loader2 size={20} className="animate-spin" />Loading contacts…</div>}
      {!loading && error && cached.length === 0 && <div className="p-10 text-center"><p className="text-sm text-destructive">Contacts could not be loaded.</p><button onClick={() => void refetch()} className="mt-3 rounded-md border border-border px-4 py-2 text-sm">Try again</button></div>}
      {!loading && !error && contacts.length === 0 && <div className="flex flex-col items-center gap-3 p-12 text-center"><Users size={40} className="text-muted-foreground" /><p className="text-sm font-semibold">No trusted contacts yet</p><p className="max-w-xs text-xs text-muted-foreground">Contacts appear after their Guardian is attested and authorized for communication.</p></div>}
      {contacts.map((peer: Peer) => <article key={peer.did} className="flex items-center gap-3 px-4 py-4 md:px-6">
        <div className="relative grid h-12 w-12 shrink-0 place-items-center rounded-full bg-primary/15 font-semibold text-primary">{initials(peer)}<span className="absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-background" style={{ background: peer.online ? "var(--chart-2)" : "var(--muted-foreground)" }} /></div>
        <button type="button" onClick={() => setSelectedDid(peer.did!)} className="min-w-0 flex-1 text-left">
          <div className="flex items-center gap-2"><p className="truncate text-sm font-semibold">{peer.displayName || peer.peerId}</p><ShieldCheck size={14} className="text-primary" /></div>
          <p className="truncate text-xs text-muted-foreground">{peer.presenceStale ? "Presence stale" : peer.online ? "Online" : `Offline · ${peer.lastSeenAgo}`}</p>
          <p className="truncate text-[11px] text-muted-foreground">{peer.deviceName} · {peer.role}</p>
        </button>
        <div className="flex items-center gap-1">
          <button aria-label={`Message ${peer.peerId}`} onClick={() => navigate(`/chats/${encodeURIComponent(peer.did!)}`)} className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted"><MessageSquare size={17} /></button>
          <button aria-label={`Voice call ${peer.peerId}`} onClick={() => void startContactCall(peer, ["audio"])} disabled={!peer.callAvailable || startingCall !== null} className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted disabled:opacity-35">{startingCall === "audio" ? <Loader2 size={17} className="animate-spin" /> : <Phone size={17} />}</button>
          <button aria-label={`Video call ${peer.peerId}`} onClick={() => void startContactCall(peer, ["audio", "video"])} disabled={!peer.callAvailable || startingCall !== null} className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted disabled:opacity-35">{startingCall === "video" ? <Loader2 size={17} className="animate-spin" /> : <Video size={17} />}</button>
        </div>
      </article>)}
    </div></div>
    {selected && <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-sm" onClick={() => setSelectedDid(null)}>
      <aside className="ml-auto flex h-full w-full max-w-sm flex-col border-l border-border bg-card shadow-xl" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border p-4">
          <div className="min-w-0"><p className="truncate text-base font-semibold">{selected.displayName || selected.peerId}</p><p className="truncate text-xs text-muted-foreground">{selected.did}</p></div>
          <button aria-label="Close profile" onClick={() => setSelectedDid(null)} className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted"><X size={17} /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          <div className="mb-5 flex items-center gap-3">
            <div className="relative grid h-14 w-14 shrink-0 place-items-center rounded-full bg-primary/15 text-base font-semibold text-primary">{initials(selected)}<span className="absolute bottom-0 right-0 h-3.5 w-3.5 rounded-full border-2 border-card" style={{ background: selected.online && !selected.presenceStale ? "var(--chart-2)" : "var(--muted-foreground)" }} /></div>
            <div className="min-w-0"><p className="truncate text-sm font-semibold">{selected.fullName || selected.displayName}</p><p className="text-xs text-muted-foreground">{selected.presenceStale ? "Presence stale" : selected.online ? "Online" : `Offline · ${selected.lastSeenAgo}`}</p></div>
          </div>
          <dl className="grid gap-3 text-sm">
            <div className="flex items-center justify-between gap-4 border-b border-border pb-2"><dt className="flex items-center gap-2 text-muted-foreground"><Smartphone size={15} />Device</dt><dd className="truncate font-medium">{selected.deviceName}</dd></div>
            <div className="flex items-center justify-between gap-4 border-b border-border pb-2"><dt className="text-muted-foreground">Role</dt><dd className="font-medium capitalize">{selected.role}</dd></div>
            <div className="flex items-center justify-between gap-4 border-b border-border pb-2"><dt className="text-muted-foreground">Type</dt><dd className="font-medium capitalize">{selected.memberType}</dd></div>
            <div className="flex items-center justify-between gap-4 border-b border-border pb-2"><dt className="flex items-center gap-2 text-muted-foreground"><CalendarDays size={15} />Join Date</dt><dd className="font-medium">{dateLabel(selected.joinDate)}</dd></div>
          </dl>
        </div>
        <div className="grid grid-cols-3 gap-2 border-t border-border p-4">
          <button onClick={() => navigate(`/chats/${encodeURIComponent(selected.did!)}`)} className="flex h-11 items-center justify-center gap-2 rounded-md border border-border text-sm font-medium"><MessageSquare size={16} />Message</button>
          <button onClick={() => void startContactCall(selected, ["audio"])} disabled={!selected.callAvailable || startingCall !== null} className="flex h-11 items-center justify-center gap-2 rounded-md border border-border text-sm font-medium disabled:opacity-40"><Phone size={16} />Voice</button>
          <button onClick={() => void startContactCall(selected, ["audio", "video"])} disabled={!selected.callAvailable || startingCall !== null} className="flex h-11 items-center justify-center gap-2 rounded-md border border-border text-sm font-medium disabled:opacity-40"><Video size={16} />Video</button>
        </div>
      </aside>
    </div>}
  </div>;
}
