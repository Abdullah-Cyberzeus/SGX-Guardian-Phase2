import { useEffect, useMemo, useState } from "react";
import { Loader2, MessageSquare, RefreshCw, Search, ShieldCheck } from "lucide-react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { useCommunicationPeers } from "../../hooks/useApiData";
import { useChatUnread } from "../../contexts/ChatUnreadContext";
import { useContactNames } from "../../contexts/ContactNameContext";
import type { Peer } from "../../services/peerService";
import { contactRepository } from "../../../pwa/db/contactRepository";

function initials(peer: Peer) {
  return peer.peerId.split(/[-_:]/).filter(Boolean).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "P";
}

function displayName(peer: Peer, contactName?: string) {
  return contactName || peer.peerId || peer.did || "Trusted peer";
}

function previewTime(timestamp?: number) {
  if (!timestamp) return "";
  const date = new Date(timestamp > 10_000_000_000 ? timestamp : timestamp * 1000);
  const today = new Date();
  return date.toDateString() === today.toDateString()
    ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString([], { month: "short", day: "numeric" });
}

export function ChatsListScreen() {
  const navigate = useNavigate();
  const { data, loading, error, refetch } = useCommunicationPeers();
  const { counts: unreadCounts, previews } = useChatUnread();
  const { contactNameForDid } = useContactNames();
  const [query, setQuery] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [cachedPeers, setCachedPeers] = useState<Peer[]>([]);
  useEffect(() => {
    if (Array.isArray(data)) {
      const current = data as Peer[];
      setCachedPeers(current);
      current.filter((peer) => peer.did).forEach((peer) => void contactRepository.save({ did: peer.did!, displayName: peer.peerId, online: peer.online, lastSeen: peer.lastSeenAgo, updatedAt: Date.now() }));
    } else if (error) {
      void contactRepository.list().then((items) => setCachedPeers(items.map((item) => ({ peerId: item.displayName, did: item.did, online: false, lastSeenAgo: item.lastSeen || "Cached", status: "verified", callAvailable: false } as Peer))));
    }
  }, [data, error]);
  const peers = useMemo(() => (Array.isArray(data) ? data : cachedPeers).filter((peer: Peer) => peer.status === "verified" && Boolean(peer.did)), [data, cachedPeers]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = needle ? peers.filter((peer: Peer) => `${displayName(peer, contactNameForDid(peer.did))} ${peer.peerId} ${peer.did} ${peer.ip}`.toLowerCase().includes(needle)) : peers;
    return [...filtered].sort((a, b) => (previews[b.did!]?.timestamp || 0) - (previews[a.did!]?.timestamp || 0));
  }, [peers, previews, query, contactNameForDid]);

  const refresh = async () => {
    setRefreshing(true);
    await refetch();
    setRefreshing(false);
  };

  return <div className="flex h-full flex-col">
    <PageHeader title="Chats" subtitle={`${peers.length} attested peer${peers.length === 1 ? "" : "s"}`} right={
      <button aria-label="Refresh peers" onClick={() => void refresh()} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted"><RefreshCw size={18} className={refreshing ? "animate-spin" : ""} /></button>
    } />
    <div className="shrink-0 border-b border-border bg-card p-3 md:px-6">
      <div className="mx-auto flex max-w-3xl gap-2"><button onClick={() => navigate("/calls")} className="rounded-full border border-border px-4 text-sm font-medium">Calls</button><label className="flex h-11 flex-1 items-center gap-2 rounded-full border border-border bg-input-background px-4">
        <Search size={17} className="text-muted-foreground" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search attested peers" className="min-w-0 flex-1 bg-transparent text-sm outline-none" />
      </label></div>
    </div>
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto w-full max-w-3xl divide-y divide-border">
        {loading && <div className="flex items-center justify-center gap-2 p-12 text-sm text-muted-foreground"><Loader2 size={20} className="animate-spin" /> Loading chats…</div>}
        {!loading && error && cachedPeers.length === 0 && <div className="p-8 text-center text-sm text-destructive">Attested peers could not be loaded.</div>}
        {!loading && !error && visible.length === 0 && <div className="flex flex-col items-center gap-3 p-12 text-center"><MessageSquare size={40} className="text-muted-foreground" /><p className="text-sm font-semibold">{query ? "No peers found" : "No attested peers yet"}</p><p className="max-w-xs text-xs text-muted-foreground">Once a peer is successfully attested and has a DID, you can message them here without sharing a Circle.</p></div>}
        {visible.map((peer: Peer) => {
          const preview = previews[peer.did!];
          const unread = unreadCounts[peer.did!] || 0;
          const name = displayName(peer, contactNameForDid(peer.did));
          return <button key={peer.did} onClick={() => navigate(`/chats/${encodeURIComponent(peer.did!)}`)} className="flex w-full items-center gap-3 bg-transparent px-4 py-3.5 text-left hover:bg-muted/50 md:px-6">
            <div className="relative grid h-12 w-12 shrink-0 place-items-center rounded-full bg-primary/15 font-semibold text-primary">{name.split(/[-_:\s]/).filter(Boolean).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || initials(peer)}<span className="absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-background" style={{ background: peer.online ? "var(--chart-2)" : "var(--muted-foreground)" }} /></div>
            <div className="min-w-0 flex-1"><div className="flex items-center gap-2"><p className="truncate text-sm font-semibold">{name}</p><ShieldCheck size={14} className="shrink-0 text-primary" /></div><p className={`truncate text-xs ${unread > 0 ? "font-semibold text-foreground" : "text-muted-foreground"}`}>{preview?.text || `${peer.online ? "Online" : peer.lastSeenAgo} · Tap to start chatting`}</p></div>
            <div className="flex shrink-0 flex-col items-end gap-1.5 self-start pt-1">
              <span className="text-[10px] text-muted-foreground">{previewTime(preview?.timestamp)}</span>
              {unread > 0 && <span className="grid min-w-[18px] place-items-center rounded-full px-1.5 text-[10px] font-semibold" style={{ height: "18px", background: "var(--primary)", color: "var(--primary-foreground)" }}>{unread > 99 ? "99+" : unread}</span>}
            </div>
          </button>;
        })}
      </div>
    </div>
  </div>;
}
