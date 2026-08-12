import { useMemo, useState } from "react";
import { Loader2, MessageSquare, Phone, Search, ShieldCheck, Users, Video } from "lucide-react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { useCommunicationPeers } from "../../hooks/useApiData";
import type { Peer } from "../../services/peerService";

function initials(peer: Peer) {
  return peer.peerId.split(/[-_:]/).filter(Boolean).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "P";
}

export function MemberContactsScreen() {
  const navigate = useNavigate();
  const { data, loading, error, refetch } = useCommunicationPeers();
  const [query, setQuery] = useState("");
  const contacts = useMemo(() => {
    const all = (Array.isArray(data) ? data : []).filter((peer: Peer) => peer.status === "verified" && Boolean(peer.did));
    const needle = query.trim().toLowerCase();
    return needle ? all.filter((peer: Peer) => `${peer.peerId} ${peer.did}`.toLowerCase().includes(needle)) : all;
  }, [data, query]);

  return <div className="flex h-full flex-col">
    <PageHeader title="Contacts" subtitle="Trusted communication contacts" />
    <div className="shrink-0 border-b border-border bg-card p-3 md:px-6">
      <label className="mx-auto flex h-11 max-w-3xl items-center gap-2 rounded-full border border-border bg-input-background px-4">
        <Search size={17} className="text-muted-foreground" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search contacts" className="min-w-0 flex-1 bg-transparent text-sm outline-none" />
      </label>
    </div>
    <div className="flex-1 overflow-y-auto"><div className="mx-auto max-w-3xl divide-y divide-border">
      {loading && <div className="flex items-center justify-center gap-2 p-12 text-sm text-muted-foreground"><Loader2 size={20} className="animate-spin" />Loading contacts…</div>}
      {!loading && error && <div className="p-10 text-center"><p className="text-sm text-destructive">Contacts could not be loaded.</p><button onClick={() => void refetch()} className="mt-3 rounded-md border border-border px-4 py-2 text-sm">Try again</button></div>}
      {!loading && !error && contacts.length === 0 && <div className="flex flex-col items-center gap-3 p-12 text-center"><Users size={40} className="text-muted-foreground" /><p className="text-sm font-semibold">No trusted contacts yet</p><p className="max-w-xs text-xs text-muted-foreground">Contacts appear after their Guardian is attested and authorized for communication.</p></div>}
      {contacts.map((peer: Peer) => <article key={peer.did} className="flex items-center gap-3 px-4 py-4 md:px-6">
        <div className="relative grid h-12 w-12 shrink-0 place-items-center rounded-full bg-primary/15 font-semibold text-primary">{initials(peer)}<span className="absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-background" style={{ background: peer.online ? "var(--chart-2)" : "var(--muted-foreground)" }} /></div>
        <div className="min-w-0 flex-1"><div className="flex items-center gap-2"><p className="truncate text-sm font-semibold">{peer.peerId}</p><ShieldCheck size={14} className="text-primary" /></div><p className="truncate text-xs text-muted-foreground">{peer.online ? "Online" : `Offline · ${peer.lastSeenAgo}`}</p></div>
        <div className="flex items-center gap-1">
          <button aria-label={`Message ${peer.peerId}`} onClick={() => navigate(`/chats/${encodeURIComponent(peer.did!)}`)} className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted"><MessageSquare size={17} /></button>
          <button aria-label={`Voice call ${peer.peerId}`} onClick={() => navigate("/calls")} disabled={!peer.callAvailable} className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted disabled:opacity-35"><Phone size={17} /></button>
          <button aria-label={`Video call ${peer.peerId}`} onClick={() => navigate("/calls")} disabled={!peer.callAvailable} className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted disabled:opacity-35"><Video size={17} /></button>
        </div>
      </article>)}
    </div></div>
  </div>;
}
