import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { AlertTriangle, BellRing, Bug, CheckCircle2, Clock3, CloudOff, Eye, Inbox, Info, Loader2, Radio, RefreshCw, Send, Wifi } from "lucide-react";
import { toast } from "sonner";
import { useContactNames } from "../../contexts/ContactNameContext";
import { useGuardianConnectivity } from "../../../pwa/connectivity/GuardianConnectivityContext";
import {
  crlService,
  type CrlGossipStatusResponse,
  type CrlGossipTriggerResponse,
  type CrlOfflineStatusResponse,
  type CrlOfflineSyncResponse,
  type CrlOperationalResponse,
} from "../../services/crlService";

type Operation = "gossip" | "broadcast" | "seed" | "sync" | null;

type Metric = {
  label: string;
  value: unknown;
  mono?: boolean;
};

function InfoTooltip({ label, placement = "right", children }: { label: string; placement?: "left" | "right"; children: ReactNode }) {
  return (
    <span className="group relative inline-flex align-middle">
      <span
        tabIndex={0}
        role="img"
        aria-label={label}
        className="inline-flex h-6 w-6 cursor-help items-center justify-center rounded-md text-muted-foreground transition hover:bg-muted hover:text-foreground focus:bg-muted focus:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/20"
      >
        <Info size={14} />
      </span>
      <span className={`pointer-events-none absolute top-7 z-30 hidden w-[min(23rem,calc(100vw-2rem))] rounded-md border border-border bg-popover px-3 py-2 text-left text-xs leading-5 text-popover-foreground shadow-lg group-hover:block group-focus-within:block ${placement === "right" ? "left-0" : "right-0"}`}>
        {children}
      </span>
    </span>
  );
}

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : "The CRL operation failed.";
}

function countFrom(value: unknown): number | null {
  if (Array.isArray(value)) return value.length;
  if (typeof value === "number") return value;
  return null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function extractItems(data: unknown, keys: string[]): Record<string, unknown>[] {
  const value = Array.isArray(data)
    ? data
    : keys.map((key) => asRecord(data)?.[key]).find(Array.isArray) ?? [];
  return value.map((item, index) => asRecord(item) ?? { value: item, index });
}

function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length ? value.map(displayValue).join(", ") : "None";
  if (typeof value === "object") return Object.entries(value as Record<string, unknown>)
    .map(([key, nested]) => `${key.replaceAll("_", " ")}: ${displayValue(nested)}`).join(" · ");
  return String(value);
}

function fieldLabel(key: string): string {
  if (key === "ttl") return "TTL (hops)";
  return key.replaceAll("_", " ");
}

function FieldLabel({ fieldKey }: { fieldKey: string }) {
  const label = fieldLabel(fieldKey);
  if (fieldKey !== "ttl") return <>{label}</>;

  return (
    <span className="inline-flex items-center gap-1">
      <span>{label}</span>
      <InfoTooltip label="About TTL hops">
        <span className="block">TTL is the emergency notice relay limit, measured in hops.</span>
        <span className="mt-1 block">Each peer re-broadcast consumes one hop; 0 means the notice is not relayed further.</span>
      </InfoTooltip>
    </span>
  );
}

function displayFieldValue(key: string, value: unknown): string {
  if (key === "ttl" && typeof value === "number") {
    return `${value} ${value === 1 ? "hop" : "hops"}`;
  }
  return displayValue(value);
}

function itemTitle(item: Record<string, unknown>, fallback: string) {
  return displayValue(item.revoked_did ?? item.did ?? item.title ?? item.id ?? item.entry_id ?? fallback);
}

function ItemCards({ data, keys, emptyTitle, emptyMessage, itemLabel }: { data: unknown; keys: string[]; emptyTitle: string; emptyMessage: string; itemLabel: string }) {
  const { displayForDid } = useContactNames();
  const items = extractItems(data, keys);
  if (!items.length) return <div className="mt-3 flex flex-col items-center rounded-lg border border-dashed border-border bg-background/40 px-4 py-8 text-center"><span className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-muted text-muted-foreground"><Inbox size={18} /></span><p className="text-sm font-semibold">{emptyTitle}</p><p className="mt-1 max-w-md text-xs leading-5 text-muted-foreground">{emptyMessage}</p></div>;

  return <div className="mt-3 grid gap-3 md:grid-cols-2">{items.map((item, index) => {
    const hidden = new Set(["id", "entry_id", "did", "revoked_did", "title"]);
    const fields = Object.entries(item).filter(([key, value]) => !hidden.has(key) && value !== undefined).slice(0, 8);
    const did = String(item.revoked_did ?? item.did ?? "");
    return <article key={String(item.id ?? item.entry_id ?? item.did ?? index)} className="rounded-lg border border-border bg-background/60 p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3"><div><p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{itemLabel} {index + 1}</p><h3 className="mt-1 break-all text-sm font-semibold" title={did}>{displayForDid(did, itemTitle(item, `${itemLabel} ${index + 1}`))}</h3></div><CheckCircle2 size={17} className="shrink-0 text-primary" /></div>
      {fields.length > 0 && <dl className="mt-3 grid gap-2">{fields.map(([key, value]) => <div key={key} className="flex items-start justify-between gap-4 border-t border-border/60 pt-2 text-xs"><dt className="shrink-0 capitalize text-muted-foreground"><FieldLabel fieldKey={key} /></dt><dd className="break-all text-right font-medium">{displayFieldValue(key, value)}</dd></div>)}</dl>}
    </article>;
  })}</div>;
}

function Summary({ data }: { data: CrlOperationalResponse | null }) {
  if (!data) return <p className="text-sm text-muted-foreground">No status has been loaded.</p>;
  const metrics = Object.entries(data).filter(([, value]) => ["string", "number", "boolean"].includes(typeof value)).slice(0, 8);
  return metrics.length ? <dl className="grid gap-2 sm:grid-cols-2">{metrics.map(([key, value]) => <div key={key} className="rounded-md border border-border bg-background/60 p-3"><dt className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground"><FieldLabel fieldKey={key} /></dt><dd className="mt-1 break-words text-sm font-medium">{displayFieldValue(key, value)}</dd></div>)}</dl> : <pre className="max-h-64 overflow-auto rounded-md bg-background p-3 text-xs">{JSON.stringify(data, null, 2)}</pre>;
}

function MetricsGrid({ items }: { items: Metric[] }) {
  const visible = items.filter((item) => item.value !== undefined && item.value !== null && item.value !== "");
  if (!visible.length) return <p className="text-sm text-muted-foreground">No details available.</p>;
  return <dl className="grid gap-2 sm:grid-cols-2">{visible.map((item) => <div key={item.label} className="rounded-md border border-border bg-background/60 p-3"><dt className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{item.label}</dt><dd className={`mt-1 break-words text-sm font-medium ${item.mono ? "font-mono text-xs" : ""}`}>{displayValue(item.value)}</dd></div>)}</dl>;
}

function InfoSection({ title, subtitle, tooltip, tooltipPlacement, children }: { title: string; subtitle: string; tooltip?: ReactNode; tooltipPlacement?: "left" | "right"; children: ReactNode }) {
  return <div className="rounded-lg border border-border bg-background/40 p-4"><div className="mb-3"><h3 className="inline-flex items-center gap-1.5 text-sm font-semibold">{title}{tooltip ? <InfoTooltip label={`About ${title}`} placement={tooltipPlacement}>{tooltip}</InfoTooltip> : null}</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">{subtitle}</p></div>{children}</div>;
}

function GossipSummary({ data, latestTrigger }: { data: CrlGossipStatusResponse | null; latestTrigger: CrlGossipTriggerResponse | null }) {
  const { displayForDid } = useContactNames();
  if (!data) return <p className="text-sm text-muted-foreground">No gossip status has been loaded yet.</p>;

  return <div className="space-y-4">
    <MetricsGrid items={[
      { label: "Enabled", value: data.enabled },
      { label: "Port", value: data.port },
      { label: "Interval secs", value: data.interval_secs },
      { label: "Threshold pct", value: data.threshold_pct },
      { label: "Self DID", value: displayForDid(data.self_did, data.self_did), mono: true },
      { label: "Circle ID", value: data.circle_id, mono: true },
      { label: "Other members", value: data.other_members },
      { label: "Threshold count", value: data.threshold_count },
    ]} />

    <InfoSection
      title="Local CRL state"
      subtitle="These are the proof fields for what this node currently believes about CRL propagation."
      tooltipPlacement="right"
      tooltip={
        <>
          <span className="block">Local CRL state is this Guardian's current copy of the revocation list.</span>
          <span className="mt-2 block"><strong>Sequence:</strong> the CRL version number.</span>
          <span className="mt-1 block"><strong>Merkle root:</strong> the fingerprint of the whole list.</span>
          <span className="mt-1 block"><strong>Entries:</strong> revoked identities in this copy.</span>
          <span className="mt-1 block"><strong>Propagated:</strong> entries already shared with peers.</span>
          <span className="mt-1 block"><strong>Rounds:</strong> gossip exchanges started or answered by this Guardian.</span>
          <span className="mt-1 block"><strong>Entries merged:</strong> peer revocations added locally.</span>
        </>
      }
    >
      <MetricsGrid items={[
        { label: "Sequence", value: data.sequence },
        { label: "Merkle root", value: data.merkle_root, mono: true },
        { label: "Entries", value: data.entries },
        { label: "Propagated", value: data.propagated },
        { label: "Rounds initiated", value: data.rounds_initiated },
        { label: "Rounds served", value: data.rounds_served },
        { label: "Entries merged", value: data.entries_merged },
      ]} />
    </InfoSection>

    <InfoSection title="Last recorded gossip round" subtitle="Latest round observed by this node, whether initiated here or served for a peer.">
      {data.last_round ? <MetricsGrid items={[
        { label: "Direction", value: data.last_round.direction },
        { label: "Peer node", value: data.last_round.peer_node },
        { label: "Peer DID", value: displayForDid(data.last_round.peer_did, data.last_round.peer_did), mono: true },
        { label: "Merged", value: data.last_round.merged },
        { label: "Sent", value: data.last_round.sent },
        { label: "Merkle root", value: data.last_round.merkle_root, mono: true },
        { label: "At", value: data.last_round.at, mono: true },
      ]} /> : <p className="text-sm text-muted-foreground">No round has been recorded yet.</p>}
    </InfoSection>

    <InfoSection title="Latest manual trigger" subtitle="This stores the last Trigger round response from this screen. One trigger talks to one active peer only.">
      {latestTrigger ? <MetricsGrid items={[
        { label: "Success", value: latestTrigger.success },
        { label: "Peer node", value: latestTrigger.peer_node },
        { label: "Peer DID", value: displayForDid(latestTrigger.peer_did, latestTrigger.peer_did), mono: true },
        { label: "Merged", value: latestTrigger.merged },
        { label: "Pushed", value: latestTrigger.pushed },
        { label: "Peer merged", value: latestTrigger.peer_merged },
        { label: "Merkle root", value: latestTrigger.merkle_root, mono: true },
        { label: "Newly propagated", value: latestTrigger.newly_propagated },
        { label: "Message", value: latestTrigger.message },
      ]} /> : <p className="text-sm text-muted-foreground">Trigger a round to capture peer selection, merge counts, and the resulting Merkle root.</p>}
    </InfoSection>
  </div>;
}

function OfflineSummary({ data, latestSync }: { data: CrlOfflineStatusResponse | null; latestSync: CrlOfflineSyncResponse | null }) {
  if (!data) return <p className="text-sm text-muted-foreground">No offline sync status has been loaded yet.</p>;
  const peers = Object.entries(data.peer_sync_state ?? {});

  return <div className="space-y-4">
    <MetricsGrid items={[
      { label: "Enabled", value: data.enabled },
      { label: "Online", value: data.online },
      { label: "Sync interval secs", value: data.sync_interval_secs },
      { label: "Flush rounds", value: data.flush_rounds },
      { label: "Max retries", value: data.max_retries },
      { label: "Pending", value: data.pending },
      { label: "Sync cycles", value: data.sync_cycles },
      { label: "Reconnects", value: data.reconnects },
      { label: "Entries delivered", value: data.entries_delivered },
      { label: "Entries fetched", value: data.entries_fetched },
    ]} />

    <InfoSection
      title="Peer sync state"
      subtitle="Last known Merkle root, sequence, and sync time this node has recorded per gossip peer."
      tooltipPlacement="right"
      tooltip={
        <>
          <span className="block">Peer sync state shows what this Guardian last heard from each peer.</span>
          <span className="mt-2 block"><strong>Merkle root:</strong> the peer's last known CRL fingerprint.</span>
          <span className="mt-1 block"><strong>Sequence:</strong> the peer's last known CRL version.</span>
          <span className="mt-1 block"><strong>Last sync at:</strong> when this Guardian last exchanged CRL data with that peer.</span>
        </>
      }
    >
      {peers.length ? <dl className="grid gap-2 sm:grid-cols-2">{peers.map(([peerDid, state]) => <div key={peerDid} className="rounded-md border border-border bg-background/60 p-3"><dt className="break-all text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{peerDid}</dt><dd className="mt-2 space-y-1 text-xs"><div className="flex justify-between gap-2"><span className="text-muted-foreground">Merkle root</span><span className="break-all text-right font-mono">{displayValue(state.last_seen_merkle_root)}</span></div><div className="flex justify-between gap-2"><span className="text-muted-foreground">Sequence</span><span className="font-medium">{displayValue(state.last_seen_sequence)}</span></div><div className="flex justify-between gap-2"><span className="text-muted-foreground">Last sync at</span><span className="font-medium">{displayValue(state.last_sync_at)}</span></div></dd></div>)}</dl> : <p className="text-sm text-muted-foreground">No peer sync state recorded yet.</p>}
    </InfoSection>

    <InfoSection title="Latest sync cycle" subtitle="This stores the last Sync now response from this screen — one fetch-and-flush cycle against reachable peers.">
      {latestSync ? <MetricsGrid items={[
        { label: "Online", value: latestSync.online },
        { label: "Reachable peers", value: latestSync.reachable_peers },
        { label: "Reconciled", value: latestSync.reconciled },
        { label: "Fetched", value: latestSync.fetched },
        { label: "Delivered", value: latestSync.delivered },
        { label: "Pending remaining", value: latestSync.pending_remaining },
      ]} /> : <p className="text-sm text-muted-foreground">Run a sync to capture reachable peers, fetch/deliver counts, and remaining queue depth.</p>}
    </InfoSection>
  </div>;
}

function Card({ title, subtitle, icon: Icon, actions, tooltip, tooltipPlacement, children }: { title: string; subtitle: string; icon: typeof Radio; actions?: ReactNode; tooltip?: ReactNode; tooltipPlacement?: "left" | "right"; children: ReactNode }) {
  return <section className="rounded-xl border border-border bg-card p-4 shadow-sm md:p-5"><div className="mb-4 flex flex-wrap items-start justify-between gap-3"><div className="flex gap-3"><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary"><Icon size={18} /></span><div><h2 className="inline-flex items-center gap-1.5 font-semibold">{title}{tooltip ? <InfoTooltip label={`About ${title}`} placement={tooltipPlacement}>{tooltip}</InfoTooltip> : null}</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">{subtitle}</p></div></div>{actions}</div>{children}</section>;
}

function Button({ children, onClick, busy, danger = false, disabled = false, title }: { children: ReactNode; onClick: () => void; busy?: boolean; danger?: boolean; disabled?: boolean; title?: string }) {
  return <button type="button" title={title} onClick={onClick} disabled={busy || disabled} className={`inline-flex min-h-9 items-center justify-center gap-2 rounded-md border px-3 text-sm font-medium transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50 ${danger ? "border-destructive/35 bg-destructive/10 text-destructive" : "border-primary/30 bg-primary/10 text-primary"}`}>{busy && <Loader2 size={14} className="animate-spin" />}{children}</button>;
}

function Confirm({ title, message, confirmLabel, busy, onClose, onConfirm }: { title: string; message: string; confirmLabel: string; busy: boolean; onClose: () => void; onConfirm: () => void }) {
  return <div className="fixed inset-0 z-[150] flex items-center justify-center bg-black/65 p-4" role="dialog" aria-modal="true" onClick={onClose}><div className="w-full max-w-md rounded-xl border border-border bg-card p-5 shadow-2xl" onClick={(event) => event.stopPropagation()}><div className="flex gap-3"><AlertTriangle className="shrink-0 text-destructive" size={22} /><div><h2 className="font-semibold">{title}</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">{message}</p></div></div><div className="mt-5 flex justify-end gap-2"><button className="rounded-md border border-border px-4 py-2 text-sm" onClick={onClose} disabled={busy}>Cancel</button><Button danger busy={busy} onClick={onConfirm}>{confirmLabel}</Button></div></div></div>;
}

export type CrlOperationsSection = "gossip" | "emergency" | "offline";

const SECTION_HEADER: Record<CrlOperationsSection, { title: string; subtitle: string }> = {
  gossip: { title: "Gossip engine", subtitle: "Peer propagation counters and manual round trigger." },
  emergency: { title: "Emergency revocation", subtitle: "Critical-DID re-broadcast, receiver notifications, and debug session tools." },
  offline: { title: "Offline synchronization", subtitle: "Queued revocations, peer sync state, and fetch-and-flush controls." },
};

export function CrlOperationsPanel({ section }: { section: CrlOperationsSection }) {
  const { reachable } = useGuardianConnectivity();
  const [gossip, setGossip] = useState<CrlGossipStatusResponse | null>(null);
  const [latestTrigger, setLatestTrigger] = useState<CrlGossipTriggerResponse | null>(null);
  const [emergency, setEmergency] = useState<CrlOperationalResponse | null>(null);
  const [notifications, setNotifications] = useState<CrlOperationalResponse | null>(null);
  const [offline, setOffline] = useState<CrlOfflineStatusResponse | null>(null);
  const [latestSync, setLatestSync] = useState<CrlOfflineSyncResponse | null>(null);
  const [pending, setPending] = useState<CrlOperationalResponse | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<Operation>(null);
  const [confirm, setConfirm] = useState<Exclude<Operation, null> | null>(null);
  const [did, setDid] = useState("");
  const [debugResult, setDebugResult] = useState<CrlOperationalResponse | null>(null);

  const load = useCallback(async (announce = false) => {
    setLoading(true);
    const requests = await Promise.allSettled([crlService.gossipStatus(), crlService.emergencyStatus(), crlService.emergencyNotifications(), crlService.offlineStatus(), crlService.offlinePending()]);
    const [gossipResult, emergencyResult, notificationsResult, offlineResult, pendingResult] = requests;
    const nextErrors: Record<string, string> = {};

    if (gossipResult.status === "fulfilled") setGossip(gossipResult.value);
    else nextErrors.gossip = messageOf(gossipResult.reason);

    if (emergencyResult.status === "fulfilled") setEmergency(emergencyResult.value);
    else nextErrors.emergency = messageOf(emergencyResult.reason);

    if (notificationsResult.status === "fulfilled") setNotifications(notificationsResult.value);
    else nextErrors.notifications = messageOf(notificationsResult.reason);

    if (offlineResult.status === "fulfilled") setOffline(offlineResult.value);
    else nextErrors.offline = messageOf(offlineResult.reason);

    if (pendingResult.status === "fulfilled") setPending(pendingResult.value);
    else nextErrors.pending = messageOf(pendingResult.reason);

    setErrors(nextErrors);
    setLoading(false);
    if (announce) Object.keys(nextErrors).length ? toast.warning("Some CRL services are unavailable", { description: Object.values(nextErrors)[0] }) : toast.success("CRL propagation status refreshed");
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { const timer = window.setInterval(() => void load(), 30000); return () => window.clearInterval(timer); }, [load]);

  const pendingCount = useMemo(() => countFrom(pending?.pending ?? pending?.entries ?? pending?.count), [pending]);
  const notificationCount = useMemo(() => countFrom(notifications?.notifications ?? notifications?.entries ?? notifications?.count), [notifications]);

  async function execute(operation: Exclude<Operation, null>) {
    setBusy(operation);
    try {
      if (operation === "gossip") {
        const result = await crlService.triggerGossip();
        setLatestTrigger(result);
        toast.success("Gossip round triggered", { description: `${result.peer_node || "peer"} · merged ${result.merged ?? 0}, pushed ${result.pushed ?? 0}` });
      } else if (operation === "sync") {
        const result = await crlService.syncOffline();
        setLatestSync(result);
        toast.success("Offline synchronization completed", { description: `${result.reachable_peers ?? 0} reachable · fetched ${result.fetched ?? 0}, delivered ${result.delivered ?? 0}, ${result.pending_remaining ?? 0} pending remaining` });
      } else if (operation === "broadcast") {
        await crlService.broadcastEmergency({ did: did.trim() });
        toast.success("Emergency notice re-broadcast sent", { description: did.trim() });
      } else {
        const result = await crlService.seedEmergencyDebugSession({ did: did.trim() });
        setDebugResult(result);
        toast.success("Debug emergency session seeded");
      }
      setConfirm(null);
      await load();
    } catch (error) {
      toast.error("CRL operation failed", { description: messageOf(error) });
    } finally {
      setBusy(null);
    }
  }

  async function inspectDebug() {
    if (!did.trim().startsWith("did:")) return toast.error("Enter a valid DID");
    setBusy("seed");
    try {
      setDebugResult(await crlService.getEmergencyDebugSession(did.trim()));
      toast.success("Debug session loaded");
    } catch (error) {
      toast.error("Debug session lookup failed", { description: messageOf(error) });
    } finally {
      setBusy(null);
    }
  }

  const normalizedDid = did.trim();
  const validDid = normalizedDid.startsWith("did:") && !/[,\s]/.test(normalizedDid);
  const header = SECTION_HEADER[section];
  return <div className="flex flex-col gap-4">
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-card p-4"><div><h2 className="font-semibold">{header.title}</h2><p className="mt-1 text-xs text-muted-foreground">{header.subtitle} Refreshes automatically every 30 seconds.</p></div><Button onClick={() => void load(true)} busy={loading}><RefreshCw size={14} />Refresh</Button></div>
    {Object.keys(errors).length > 0 && <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive"><strong>Partial service failure.</strong> {Object.entries(errors).map(([key, value]) => `${key}: ${value}`).join(" · ")}</div>}
    {section === "gossip" && <Card title="Gossip engine" subtitle="Peer propagation counters, hidden CRL proof fields, and the latest manual trigger result." icon={Radio} tooltip={<><span className="block">The Gossip engine shares revocation updates with trusted peers.</span><span className="mt-2 block"><strong>Enabled:</strong> whether automatic sharing is turned on.</span><span className="mt-1 block"><strong>Port:</strong> the network port used for CRL sharing.</span><span className="mt-1 block"><strong>Interval secs:</strong> how often Guardian tries automatic sharing.</span><span className="mt-1 block"><strong>Threshold:</strong> how many peers must agree before the CRL is considered well shared.</span><span className="mt-1 block"><strong>Self DID:</strong> this Guardian's identity.</span><span className="mt-1 block"><strong>Circle ID:</strong> the trusted group being synchronized.</span><span className="mt-1 block"><strong>Other members:</strong> peers available for sharing.</span><span className="mt-1 block"><strong>Trigger round:</strong> starts one manual exchange with an available peer.</span></>} actions={<Button onClick={() => setConfirm("gossip")} disabled={loading || !reachable} title={!reachable ? "Guardian unreachable — reconnect to make changes" : undefined}><RefreshCw size={14} />Trigger round</Button>}><GossipSummary data={gossip} latestTrigger={latestTrigger} /></Card>}
    {section === "emergency" && <>
      <Card title="Emergency revocation channel" subtitle={`Manual re-broadcast for an existing critical revocation, plus durable receiver notifications${notificationCount !== null ? ` · ${notificationCount} notifications` : ""}.`} icon={BellRing} tooltip={<><span className="block">Emergency revocation is for high-risk identities that must be warned about quickly.</span><span className="mt-2 block"><strong>Re-broadcast:</strong> sends an existing critical revocation notice to peers again.</span><span className="mt-1 block"><strong>Notifications:</strong> emergency notices this Guardian received or stored.</span></>}>
        <Summary data={emergency} />
        <div className="mt-4 grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]"><input className="rounded-md border border-border bg-input-background px-3 py-2 text-sm" value={did} onChange={(event) => setDid(event.target.value)} placeholder="did:guardian:... (single critical revoked DID)" aria-label="Emergency DID" /><Button danger disabled={!validDid || !reachable} title={!reachable ? "Guardian unreachable — reconnect to make changes" : undefined} onClick={() => setConfirm("broadcast")}><Send size={14} />Re-broadcast</Button></div>
        <p className="mt-2 text-xs leading-5 text-muted-foreground">Use one already-revoked <strong>critical</strong> DID only. This control re-sends the emergency notice to active peers; it does not create a new CRL entry.</p>
        <div className="mt-4 rounded-md border border-border p-3"><div className="flex items-center gap-2 text-sm font-medium"><BellRing size={15} />Emergency notifications</div><ItemCards data={notifications} keys={["notifications", "entries", "items"]} itemLabel="Notification" emptyTitle="No emergency notifications" emptyMessage="This is expected until an emergency revocation is received or broadcast and the backend stores a notification." /></div>
      </Card>
      <Card title="Emergency debug session" subtitle="Inspect or seed test session state for backend validation. Debug controls should only be used in non-production environments." icon={Bug} tooltipPlacement="left" tooltip={<><span className="block">Emergency debug session is a testing area for emergency revocation behavior.</span><span className="mt-2 block"><strong>DID field:</strong> the Guardian identity you want to inspect or seed.</span><span className="mt-1 block"><strong>Inspect session:</strong> checks saved debug state for that DID.</span><span className="mt-1 block"><strong>Seed test session:</strong> creates test-only debug state for backend validation.</span></>}>
        <div className="flex flex-wrap gap-2"><Button disabled={!validDid} busy={busy === "seed"} onClick={() => void inspectDebug()}><Eye size={14} />Inspect session</Button><Button disabled={!validDid} onClick={() => setConfirm("seed")}><Bug size={14} />Seed test session</Button></div>{debugResult && <pre className="mt-4 max-h-72 overflow-auto rounded-md bg-background p-3 text-xs">{JSON.stringify(debugResult, null, 2)}</pre>}
      </Card>
    </>}
    {section === "offline" && <Card title="Offline synchronization" subtitle={`Queued revocations, peer synchronization state, and fetch-and-flush controls${pendingCount !== null ? ` · ${pendingCount} pending` : ""}.`} icon={CloudOff} tooltip={<><span className="block">Offline synchronization keeps revocation data moving when a Guardian was disconnected.</span><span className="mt-2 block"><strong>Pending:</strong> revocations waiting to be delivered.</span><span className="mt-1 block"><strong>Fetched:</strong> entries received from peers.</span><span className="mt-1 block"><strong>Delivered:</strong> entries sent to peers.</span><span className="mt-1 block"><strong>Sync now:</strong> starts a manual catch-up cycle.</span></>} actions={<Button onClick={() => setConfirm("sync")} disabled={loading || !reachable} title={!reachable ? "Guardian unreachable — reconnect to make changes" : undefined}><Wifi size={14} />Sync now</Button>}><OfflineSummary data={offline} latestSync={latestSync} /><div className="mt-4 rounded-md border border-border p-3"><div className="flex items-center gap-2 text-sm font-medium"><Clock3 size={15} />Pending revocations</div><ItemCards data={pending} keys={["pending", "revocations", "entries", "items", "queue"]} itemLabel="Revocation" emptyTitle="No pending revocations" emptyMessage="The offline queue is clear. New revocations appear here when they cannot be delivered to peers immediately." /></div></Card>}
    {confirm && <Confirm title={confirm === "broadcast" ? "Re-broadcast critical revocation?" : confirm === "seed" ? "Seed a test emergency session?" : confirm === "sync" ? "Run offline synchronization?" : "Trigger gossip now?"} message={confirm === "broadcast" ? `This re-sends the existing critical revocation notice for ${did.trim()} to active peers. It does not create a new CRL entry.` : confirm === "seed" ? `This changes debug session state for ${did.trim()}.` : confirm === "sync" ? "This starts an immediate fetch-and-flush cycle with configured peers." : "This starts a CRL gossip round immediately and may generate peer traffic."} confirmLabel={confirm === "broadcast" ? "Re-broadcast now" : confirm === "seed" ? "Seed session" : confirm === "sync" ? "Sync now" : "Trigger round"} busy={busy === confirm} onClose={() => !busy && setConfirm(null)} onConfirm={() => void execute(confirm)} />}
  </div>;
}
