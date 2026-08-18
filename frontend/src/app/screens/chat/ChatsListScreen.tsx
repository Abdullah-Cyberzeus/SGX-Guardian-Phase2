import { useEffect, useMemo, useState } from "react";
import { Loader2, MessageSquare, RefreshCw, Search, ShieldCheck, UsersRound } from "lucide-react";
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

function dedupePeers(peers: Peer[]) {
  const byDid = new Map<string, Peer>();
  for (const peer of peers) {
    if (!peer.did) continue;
    const existing = byDid.get(peer.did);
    byDid.set(peer.did, existing ? { ...existing, ...peer, online: existing.online || peer.online } : peer);
  }
  return [...byDid.values()];
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
  const { counts: unreadCounts, previews, circleCounts, circlePreviews, circleChats, refresh: refreshChat } = useChatUnread();
  const { contactNameForDid } = useContactNames();
  const [query, setQuery] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [cachedPeers, setCachedPeers] = useState<Peer[]>([]);
  useEffect(() => {
    if (Array.isArray(data)) {
      const current = dedupePeers(data as Peer[]);
      setCachedPeers(current);
      current.filter((peer) => peer.did).forEach((peer) => void contactRepository.save({ did: peer.did!, displayName: peer.peerId, online: peer.online, lastSeen: peer.lastSeenAgo, updatedAt: Date.now() }));
    } else if (error) {
      void contactRepository.list().then((items) => setCachedPeers(dedupePeers(items.map((item) => ({ peerId: item.displayName, did: item.did, online: false, lastSeenAgo: item.lastSeen || "Cached", status: "verified", callAvailable: false } as Peer)))));
    }
  }, [data, error]);
  const peers = useMemo(() => dedupePeers((Array.isArray(data) ? data : cachedPeers).filter((peer: Peer) => peer.status === "verified" && Boolean(peer.did))), [data, cachedPeers]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const peerRows = peers.map((peer) => ({ kind: "peer" as const, peer, id: peer.did!, name: displayName(peer, contactNameForDid(peer.did)), preview: previews[peer.did!], unread: unreadCounts[peer.did!] || 0 }));
    const circleRows = circleChats.map((circle) => ({ kind: "circle" as const, circle, id: circle.circleId, name: circle.name, preview: circlePreviews[circle.circleId], unread: circleCounts[circle.circleId] || 0 }));
    const rows = [...peerRows, ...circleRows];
    const filtered = needle ? rows.filter((row) => {
      const extra = row.kind === "peer" ? `${row.peer.peerId} ${row.peer.did} ${row.peer.ip}` : `circle group ${row.circle.memberCount} members`;
      return `${row.name} ${extra}`.toLowerCase().includes(needle);
    }) : rows;
    return filtered.sort((a, b) => (b.preview?.timestamp || 0) - (a.preview?.timestamp || 0));
  }, [peers, previews, unreadCounts, circleChats, circlePreviews, circleCounts, query, contactNameForDid]);

  const refresh = async () => {
    setRefreshing(true);
    await refetch();
    refreshChat();
    setRefreshing(false);
  };

  return <div className="flex h-full flex-col">
    <PageHeader title="Chats" subtitle={`${visible.length} conversation${visible.length === 1 ? "" : "s"}`} right={
      <button aria-label="Refresh peers" onClick={() => void refresh()} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted"><RefreshCw size={18} className={refreshing ? "animate-spin" : ""} /></button>
    } />
    <div className="shrink-0 border-b border-border bg-card p-3 md:px-6">
      <div className="mx-auto flex max-w-3xl gap-2"><button onClick={() => navigate("/calls")} className="rounded-full border border-border px-4 text-sm font-medium">Calls</button><label className="flex h-11 flex-1 items-center gap-2 rounded-full border border-border bg-input-background px-4">
        <Search size={17} className="text-muted-foreground" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search chats" className="min-w-0 flex-1 bg-transparent text-sm outline-none" />
      </label></div>
    </div>
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto w-full max-w-3xl divide-y divide-border">
        {loading && <div className="flex items-center justify-center gap-2 p-12 text-sm text-muted-foreground"><Loader2 size={20} className="animate-spin" /> Loading chats…</div>}
        {!loading && error && cachedPeers.length === 0 && circleChats.length === 0 && <div className="p-8 text-center text-sm text-destructive">Chats could not be loaded.</div>}
        {!loading && visible.length === 0 && <div className="flex flex-col items-center gap-3 p-12 text-center"><MessageSquare size={40} className="text-muted-foreground" /><p className="text-sm font-semibold">{query ? "No chats found" : "No conversations yet"}</p><p className="max-w-xs text-xs text-muted-foreground">Peer chats appear after attestation. Circle chats appear here after their first group message.</p></div>}
        {visible.map((row) => {
          const { preview, unread, name } = row;
          const peer = row.kind === "peer" ? row.peer : null;
          const fallback = peer ? `${peer.online ? "Online" : peer.lastSeenAgo} · Tap to start chatting` : `${row.circle.memberCount} member${row.circle.memberCount === 1 ? "" : "s"} · Circle group chat`;
          return <button key={`${row.kind}:${row.id}`} onClick={() => navigate(row.kind === "circle" ? `/network/${encodeURIComponent(row.id)}/chat?from=chats` : `/chats/${encodeURIComponent(row.id)}`)} className="flex w-full items-center gap-3 bg-transparent px-4 py-3.5 text-left hover:bg-muted/50 md:px-6">
            <div className="relative grid h-12 w-12 shrink-0 place-items-center rounded-full bg-primary/15 font-semibold text-primary">{row.kind === "circle" ? <UsersRound size={21} /> : (name.split(/[-_:\s]/).filter(Boolean).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || initials(peer!))}{peer && <span className="absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-background" style={{ background: peer.online ? "var(--chart-2)" : "var(--muted-foreground)" }} />}</div>
            <div className="min-w-0 flex-1"><div className="flex items-center gap-2"><p className="truncate text-sm font-semibold">{name}</p>{row.kind === "peer" ? <ShieldCheck size={14} className="shrink-0 text-primary" /> : <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-primary">Circle</span>}</div><p className={`truncate text-xs ${unread > 0 ? "font-semibold text-foreground" : "text-muted-foreground"}`}>{preview?.text || fallback}</p></div>
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
