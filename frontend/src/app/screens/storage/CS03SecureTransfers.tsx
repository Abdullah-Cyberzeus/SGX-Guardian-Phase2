import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router";
import {
  AlertCircle, ArrowDownToLine, ArrowLeft, ArrowUpFromLine, Ban, Download, File,
  FileCheck2, Folder, Inbox, Loader2, RefreshCw, Send, ShieldCheck, X,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";
import { useContactNames } from "../../contexts/ContactNameContext";
import { useCommunicationPeers } from "../../hooks/useApiData";
import type { Peer } from "../../services/peerService";
import { formatBytes } from "../../components/vault/types";
import {
  xferService, type InboxFile, type TransferListResponse, type TransferSummary,
} from "../../services/xferService";
import {
  vaultService, type FolderNode, type VaultRecord,
} from "../../services/vaultService";

type Tab = "send" | "outbox" | "inbox";

function transferId(item: TransferSummary) {
  return String(item.transfer_id ?? item.id ?? "");
}

function displayTime(value: unknown) {
  if (typeof value !== "string" || !value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function StatusPill({ value }: { value?: string }) {
  const status = (value || "unknown").toLowerCase();
  const good = ["complete", "completed", "sent", "success"].includes(status);
  const bad = ["failed", "cancelled", "canceled"].includes(status);
  return (
    <span
      className="rounded-full px-2 py-1 text-[11px] font-medium"
      style={{
        color: good ? "var(--chart-2)" : bad ? "var(--destructive)" : "var(--primary)",
        backgroundColor: good
          ? "color-mix(in srgb, var(--chart-2) 12%, transparent)"
          : bad
            ? "color-mix(in srgb, var(--destructive) 12%, transparent)"
            : "color-mix(in srgb, var(--primary) 12%, transparent)",
      }}
    >
      {value || "Unknown"}
    </span>
  );
}

export function CS03SecureTransfers() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { displayForDid } = useContactNames();
  const {
    data: peerData,
    loading: peersLoading,
    error: peersError,
    refetch: refetchPeers,
  } = useCommunicationPeers();
  const [tab, setTab] = useState<Tab>("send");
  const [peerDid, setPeerDid] = useState("");
  const [selectedVaultIds, setSelectedVaultIds] = useState<string[]>(
    () => searchParams.get("vault_id") ? [searchParams.get("vault_id")!] : [],
  );
  const [vaultFiles, setVaultFiles] = useState<VaultRecord[]>([]);
  const [vaultFolders, setVaultFolders] = useState<FolderNode[]>([]);
  const [currentFolderId, setCurrentFolderId] = useState("");
  const [vaultLoading, setVaultLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [sendProgress, setSendProgress] = useState({ queued: 0, total: 0 });
  const [loading, setLoading] = useState(false);
  const [activity, setActivity] = useState<TransferListResponse | null>(null);
  const [inbox, setInbox] = useState<InboxFile[]>([]);
  const [detail, setDetail] = useState<TransferSummary | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [sendError, setSendError] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const refreshing = useRef(false);

  const folderId = (folder: FolderNode) => String(folder.folder_id ?? folder.id ?? "");
  const fileId = (file: VaultRecord) => String(file.vault_id ?? file.id ?? "");
  const fileFolderId = (file: VaultRecord) => String(file.folder_id ?? "");
  const childFolders = vaultFolders.filter(
    (folder) => String(folder.parent_id ?? "") === currentFolderId,
  );
  const childFiles = vaultFiles.filter((file) => fileFolderId(file) === currentFolderId);
  const currentFolder = vaultFolders.find((folder) => folderId(folder) === currentFolderId);
  const peers = useMemo(() => {
    const byDid = new Map<string, Peer>();
    for (const peer of peerData ?? []) {
      if (!peer.did || peer.status !== "verified" || peer.memberType === "browser") continue;
      const current = byDid.get(peer.did);
      if (!current || (!current.online && peer.online)) byDid.set(peer.did, peer);
    }
    return [...byDid.values()].sort((a, b) => {
      if (a.online !== b.online) return a.online ? -1 : 1;
      const aName = displayForDid(a.did, a.displayName || a.peerId || a.deviceName);
      const bName = displayForDid(b.did, b.displayName || b.peerId || b.deviceName);
      return aName.localeCompare(bName);
    });
  }, [peerData, displayForDid]);
  const selectedPeer = peers.find((peer) => peer.did === peerDid);

  const loadVault = async () => {
    setVaultLoading(true);
    setVaultError(null);
    try {
      const [files, folders] = await Promise.all([
        vaultService.list(),
        vaultService.listFolders(),
      ]);
      setVaultFiles(files.files);
      setVaultFolders(folders.folders);
      const availableIds = new Set(files.files.map(fileId));
      setSelectedVaultIds((selected) => selected.filter((id) => availableIds.has(id)));
    } catch (cause) {
      setVaultError(cause instanceof Error ? cause.message : "Check the Guardian connection.");
      toast.error("Could not load Vault files", {
        description: cause instanceof Error ? cause.message : "Check the Guardian connection.",
      });
    } finally {
      setVaultLoading(false);
    }
  };

  const refresh = async (quiet = false) => {
    if (refreshing.current) return;
    refreshing.current = true;
    setLoading(true);
    try {
      const [outboxResult, inboxResult] = await Promise.allSettled([
        xferService.list(),
        xferService.inbox(),
      ]);
      if (outboxResult.status === "fulfilled") setActivity(outboxResult.value);
      if (inboxResult.status === "fulfilled") setInbox(inboxResult.value.files);

      const failures = [
        outboxResult.status === "rejected"
          ? `Outbox: ${outboxResult.reason instanceof Error ? outboxResult.reason.message : "unavailable"}`
          : null,
        inboxResult.status === "rejected"
          ? `Inbox: ${inboxResult.reason instanceof Error ? inboxResult.reason.message : "unavailable"}`
          : null,
      ].filter((message): message is string => Boolean(message));
      setLoadError(failures.length ? failures.join(" · ") : null);
      if (!quiet) {
        if (failures.length) {
          toast.error("Some transfers could not be refreshed", { description: failures.join(" · ") });
        } else {
          toast.success("Inbox and Outbox refreshed");
        }
      }
    } finally {
      refreshing.current = false;
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh(true);
    void loadVault();
  }, []);
  useEffect(() => {
    if (tab !== "outbox" && tab !== "inbox") return;
    const timer = window.setInterval(() => void refresh(true), 5000);
    return () => window.clearInterval(timer);
  }, [tab]);

  const handleSend = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedPeer?.did || selectedVaultIds.length === 0) {
      setSendError("Select a peer and at least one Vault file.");
      toast.error("Select a peer and at least one Vault file");
      return;
    }
    setSendError(null);
    setSending(true);
    setSendProgress({ queued: 0, total: selectedVaultIds.length });
    try {
      const failedIds: string[] = [];
      const failureMessages: string[] = [];
      let queued = 0;

      // Queue requests sequentially so a large selection cannot overwhelm the
      // board or create avoidable races in its transfer engine.
      for (const vaultId of selectedVaultIds) {
        try {
          await xferService.send({
            peer_did: selectedPeer.did,
            vault_id: vaultId,
          });
          queued += 1;
          setSendProgress({ queued, total: selectedVaultIds.length });
        } catch (cause) {
          failedIds.push(vaultId);
          failureMessages.push(cause instanceof Error ? cause.message : "Unknown transfer error");
        }
      }

      setSelectedVaultIds(failedIds);
      if (queued > 0) {
        toast.success(`${queued} transfer${queued === 1 ? "" : "s"} queued`, {
          description: `Sending to ${displayForDid(selectedPeer.did, selectedPeer.displayName || selectedPeer.peerId)}`,
        });
        await refresh(true);
      }
      if (failedIds.length > 0) {
        const message = `${failedIds.length} of ${selectedVaultIds.length} files could not be queued. Failed files remain selected so you can retry.`;
        setSendError(`${message} ${failureMessages[0] ?? ""}`.trim());
        toast.error("Some transfers could not be queued", { description: message });
      } else {
        setTab("outbox");
      }
    } catch (cause) {
      setSendError(cause instanceof Error ? cause.message : "Try again.");
      toast.error("Transfer could not be queued", {
        description: cause instanceof Error ? cause.message : "Try again.",
      });
    } finally {
      setSending(false);
      setSendProgress({ queued: 0, total: 0 });
    }
  };

  const openDetail = async (id: string) => {
    setDetailLoading(true);
    try {
      setDetail(await xferService.detail(id));
    } catch (cause) {
      toast.error("Could not load transfer", {
        description: cause instanceof Error ? cause.message : "Try again.",
      });
    } finally { setDetailLoading(false); }
  };

  const cancel = async (id: string) => {
    setCancellingId(id);
    try {
      const result = await xferService.cancel(id);
      toast.success("Transfer cancelled", { description: result.message });
      setDetail(null);
      await refresh(true);
    } catch (cause) {
      toast.error("Could not cancel transfer", {
        description: cause instanceof Error ? cause.message : "It may already be complete.",
      });
    } finally { setCancellingId(null); }
  };

  const downloadInbox = async (file: InboxFile) => {
    if (!file.download_path && !file.vault_id) {
      toast.error("Download is not available yet", {
        description: "Refresh the Inbox after Vault finalization completes.",
      });
      return;
    }
    setDownloadingId(file.transfer_id);
    try {
      const blob = file.download_path
        ? await vaultService.downloadPath(file.download_path)
        : await vaultService.download(file.vault_id!);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = file.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast.success("Download started");
    } catch (cause) {
      toast.error("Download failed", {
        description: cause instanceof Error ? cause.message : "Try again.",
      });
    } finally { setDownloadingId(null); }
  };

  const tabs: Array<{ id: Tab; label: string; icon: typeof Send; count?: number }> = [
    { id: "send", label: "Send", icon: Send },
    { id: "outbox", label: "Outbox", icon: ArrowUpFromLine, count: activity?.count },
    { id: "inbox", label: "Inbox", icon: Inbox, count: inbox.length },
  ];

  return (
    <div className="flex h-full flex-col bg-background">
      <PageHeader
        title="Secure Transfer"
        subtitle="Send and receive files between trusted Guardian peers"
        onBack={() => navigate("/storage")}
        right={
          <Button variant="outline" size="sm" onClick={() => void refresh()} disabled={loading}>
            {loading ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />}
          </Button>
        }
      />

      <div className="flex border-b border-border bg-card">
        {tabs.map(({ id, label, icon: Icon, count }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className="flex flex-1 items-center justify-center gap-2 px-3 py-3 text-sm"
            style={{
              color: tab === id ? "var(--primary)" : "var(--muted-foreground)",
              borderBottom: tab === id ? "2px solid var(--primary)" : "2px solid transparent",
            }}
          >
            <Icon size={16} /> {label}
            {typeof count === "number" && <span className="rounded-full bg-muted px-1.5 text-[10px]">{count}</span>}
          </button>
        ))}
      </div>

      <div className="mx-auto w-full max-w-3xl flex-1 overflow-y-auto p-4 md:p-6">
        {loadError && (
          <Card className="mb-4 flex-row items-center gap-3 border-destructive/40 p-4">
            <AlertCircle size={20} className="shrink-0 text-destructive" />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-destructive">Transfer service unavailable</p>
              <p className="truncate text-xs text-muted-foreground">{loadError}</p>
            </div>
            <Button size="sm" variant="outline" disabled={loading} onClick={() => void refresh()}>
              {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />} Retry
            </Button>
          </Card>
        )}
        {tab === "send" && (
          <form onSubmit={handleSend} className="space-y-4">
            <Card className="gap-4 p-5">
              <div className="flex items-start gap-3">
                <ShieldCheck size={22} className="mt-0.5 text-primary" />
                <div>
                  <h2 className="font-semibold text-foreground">Send with Secure XFER</h2>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">
                    Choose an encrypted Vault file. Secure XFER decrypts it only for transport,
                    verifies it, and stores it encrypted in the receiving Guardian's Vault.
                  </p>
                </div>
              </div>
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-3">
                  <label htmlFor="secure-transfer-peer" className="text-xs font-medium">
                    Destination peer
                  </label>
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    onClick={() => void refetchPeers()}
                    disabled={peersLoading}
                  >
                    <RefreshCw size={14} className={peersLoading ? "animate-spin" : ""} />
                    Refresh
                  </Button>
                </div>
                <select
                  id="secure-transfer-peer"
                  value={peerDid}
                  onChange={(event) => {
                    setPeerDid(event.target.value);
                    setSendError(null);
                  }}
                  disabled={peersLoading || peers.length === 0}
                  className="h-11 w-full rounded-md border border-border bg-input-background px-3 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <option value="">
                    {peersLoading
                      ? "Loading trusted peers…"
                      : peers.length === 0
                        ? "No trusted peers available"
                        : "Select a trusted peer"}
                  </option>
                  {peers.map((peer) => (
                    <option key={peer.did} value={peer.did}>
                      {displayForDid(peer.did, peer.displayName || peer.peerId || peer.deviceName)}
                      {peer.deviceName && peer.deviceName !== peer.displayName ? ` — ${peer.deviceName}` : ""}
                      {peer.online ? " (Online)" : " (Offline)"}
                    </option>
                  ))}
                </select>
                {peersError && (
                  <p className="text-xs text-destructive" role="alert">
                    Trusted peers could not be loaded. Refresh and try again.
                  </p>
                )}
                {!peersLoading && !peersError && peers.length === 0 && (
                  <p className="text-xs text-muted-foreground">
                    No attested Guardian peers are available for secure transfer.
                  </p>
                )}
                {selectedPeer && (
                  <div className="flex items-center gap-2 rounded-md bg-primary/5 px-3 py-2 text-xs text-muted-foreground">
                    <ShieldCheck size={14} className="shrink-0 text-primary" />
                    <span className="truncate">
                      {selectedPeer.online ? "Online" : selectedPeer.lastSeenAgo || "Offline"} · Verified Guardian peer
                    </span>
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium">Vault file</span>
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    onClick={() => void loadVault()}
                    disabled={vaultLoading}
                  >
                    {vaultLoading
                      ? <Loader2 size={14} className="animate-spin" />
                      : <RefreshCw size={14} />}
                    Refresh
                  </Button>
                </div>
                <div className="overflow-hidden rounded-lg border border-border">
                  <div className="flex min-h-10 items-center gap-2 border-b border-border bg-muted/40 px-3">
                    {currentFolderId && (
                      <button
                        type="button"
                        className="rounded p-1 hover:bg-muted"
                        aria-label="Go to parent folder"
                        onClick={() => setCurrentFolderId(String(currentFolder?.parent_id ?? ""))}
                      >
                        <ArrowLeft size={15} />
                      </button>
                    )}
                    <Folder size={15} className="text-primary" />
                    <span className="truncate text-xs font-medium">
                      {currentFolder?.name ?? "Vault"}
                    </span>
                  </div>
                  <div className="max-h-72 overflow-y-auto p-1">
                    {vaultLoading && (
                      <div className="flex items-center justify-center gap-2 px-3 py-10 text-xs text-muted-foreground">
                        <Loader2 size={16} className="animate-spin" /> Loading encrypted files…
                      </div>
                    )}
                    {vaultError && !vaultLoading && (
                      <div className="flex flex-col items-center gap-2 px-3 py-8 text-center">
                        <AlertCircle size={20} className="text-destructive" />
                        <p className="text-xs text-destructive">{vaultError}</p>
                        <Button type="button" size="sm" variant="outline" onClick={() => void loadVault()}>Retry</Button>
                      </div>
                    )}
                    {!vaultLoading && !vaultError && childFolders.length === 0 && childFiles.length === 0 && (
                      <p className="px-3 py-8 text-center text-xs text-muted-foreground">
                        This folder is empty.
                      </p>
                    )}
                    {childFolders.map((folder) => {
                      const id = folderId(folder);
                      return (
                        <button
                          type="button"
                          key={id}
                          onClick={() => setCurrentFolderId(id)}
                          className="flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left hover:bg-muted/60"
                        >
                          <Folder size={18} className="shrink-0 text-primary" />
                          <span className="min-w-0 flex-1 truncate text-sm">{folder.name}</span>
                          <span className="text-xs text-muted-foreground">Open</span>
                        </button>
                      );
                    })}
                    {childFiles.map((file) => {
                      const id = fileId(file);
                      const selected = selectedVaultIds.includes(id);
                      return (
                        <button
                          type="button"
                          key={id}
                          aria-pressed={selected}
                          onClick={() => setSelectedVaultIds((current) =>
                            current.includes(id)
                              ? current.filter((selectedId) => selectedId !== id)
                              : [...current, id]
                          )}
                          className="flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left"
                          style={{
                            backgroundColor: selected
                              ? "color-mix(in srgb, var(--primary) 12%, transparent)"
                              : undefined,
                          }}
                        >
                          <File size={18} className="shrink-0 text-muted-foreground" />
                          <span className="min-w-0 flex-1">
                            <span className="block truncate text-sm font-medium">
                              {String(file.filename ?? file.name ?? id)}
                            </span>
                            <span className="block text-[11px] text-muted-foreground">
                              {formatBytes(Number(file.size_plain ?? file.size ?? 0))}
                            </span>
                          </span>
                          <span
                            className="h-4 w-4 shrink-0 rounded-full border"
                            style={{
                              borderColor: selected ? "var(--primary)" : "var(--border)",
                              backgroundColor: selected ? "var(--primary)" : "transparent",
                              boxShadow: selected ? "inset 0 0 0 3px var(--card)" : undefined,
                            }}
                          />
                        </button>
                      );
                    })}
                  </div>
                </div>
                {selectedVaultIds.length > 0 && (
                  <div className="flex items-center justify-between gap-3 rounded-md bg-muted/40 px-3 py-2">
                    <p className="text-xs text-muted-foreground">
                      <strong className="text-foreground">{selectedVaultIds.length}</strong>{" "}
                      {selectedVaultIds.length === 1 ? "file" : "files"} selected
                    </p>
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      disabled={sending}
                      onClick={() => setSelectedVaultIds([])}
                    >
                      <X size={13} /> Clear
                    </Button>
                  </div>
                )}
              </div>
              {sendError && (
                <div role="alert" className="flex items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-xs text-destructive">
                  <AlertCircle size={15} className="mt-0.5 shrink-0" />
                  <span>{sendError}</span>
                </div>
              )}
              <Button type="submit" disabled={sending || !selectedPeer || selectedVaultIds.length === 0} className="h-11 w-full gap-2">
                {sending ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
                {sending
                  ? `Queuing ${sendProgress.queued} of ${sendProgress.total}…`
                  : selectedVaultIds.length > 0
                    ? `Queue ${selectedVaultIds.length} secure transfer${selectedVaultIds.length === 1 ? "" : "s"}`
                    : "Select files to transfer"}
              </Button>
            </Card>
          </form>
        )}

        {tab === "outbox" && (
          <div className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold">Sent files</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Files queued or sent from this Guardian to another peer.
              </p>
            </div>
            {loading && !activity && <LoadingState text="Loading Outbox…" />}
            {activity && (
              <div className="grid grid-cols-2 gap-2">
                <Card className="gap-1 p-3"><span className="text-xs text-muted-foreground">Outbox files</span><b>{activity.count}</b></Card>
                <Card className="gap-1 p-3"><span className="text-xs text-muted-foreground">Transferred</span><b>{formatBytes(activity.bytes_transferred)}</b></Card>
              </div>
            )}
            {!activity?.transfers.length && !loading && <Empty icon={ArrowUpFromLine} text="No sent files" />}
            {activity?.transfers.map((item) => {
              const id = transferId(item);
              return (
                <button key={id} onClick={() => void openDetail(id)} className="w-full text-left">
                  <Card className="gap-2 p-4 transition-colors hover:bg-muted/40">
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0">
                        <span className="block truncate font-medium">{String(item.filename ?? item.path ?? id)}</span>
                        <span className="mt-0.5 block text-[10px] font-medium uppercase tracking-wide text-primary">Sent file</span>
                      </span>
                      <StatusPill value={item.status} />
                    </div>
                    <div className="flex justify-between gap-3 text-xs text-muted-foreground">
                      <span className="truncate" title={String(item.peer_did ?? "")}>{displayForDid(String(item.peer_did ?? ""), String(item.peer_did ?? id))}</span>
                      <span>{displayTime(item.updated_at ?? item.created_at)}</span>
                    </div>
                    {Number(item.size ?? 0) > 0 && !["completed", "complete", "failed", "cancelled", "canceled"].includes(String(item.status ?? "").toLowerCase()) && (
                      <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                        <div
                          className="h-full rounded-full bg-primary transition-[width]"
                          style={{ width: `${Math.min(100, Math.round((Number(item.bytes_sent ?? item.bytes_transferred ?? 0) / Number(item.size)) * 100))}%` }}
                        />
                      </div>
                    )}
                  </Card>
                </button>
              );
            })}
          </div>
        )}

        {tab === "inbox" && (
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold">Received files</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  Files received by this Guardian. Completed files are stored in Vault.
                </p>
              </div>
              <Button size="sm" variant="outline" disabled={loading} onClick={() => void refresh()}>
                {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                Refresh
              </Button>
            </div>
            {inbox.length > 0 && (
              <div className="grid grid-cols-2 gap-2">
                <Card className="gap-1 p-3">
                  <span className="text-xs text-muted-foreground">Received</span>
                  <b>{inbox.length}</b>
                </Card>
                <Card className="gap-1 p-3">
                  <span className="text-xs text-muted-foreground">Ready to download</span>
                  <b>{inbox.filter((file) => file.completed && (file.download_path || file.vault_id)).length}</b>
                </Card>
              </div>
            )}
            {loading && !inbox.length && <LoadingState text="Checking incoming files…" />}
            {!inbox.length && !loading && <Empty icon={Inbox} text="No received files" />}
            {inbox.map((file) => (
              <Card key={file.transfer_id} className="gap-3 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 gap-3">
                    <div className="rounded-lg bg-primary/10 p-2 text-primary">
                      {file.completed ? <FileCheck2 size={20} /> : <ArrowDownToLine size={20} />}
                    </div>
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{file.filename}</p>
                      <p className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-primary">Received file</p>
                      <p className="truncate text-xs text-muted-foreground" title={file.sender_did}>From {displayForDid(file.sender_did, file.sender_did)}</p>
                    </div>
                  </div>
                  <StatusPill value={file.completed ? "Completed" : "Receiving"} />
                </div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>{formatBytes(file.size)} · {displayTime(file.updated_at)}</span>
                  {file.completed && (file.download_path || file.vault_id) ? (
                    <Button size="sm" variant="outline" disabled={downloadingId === file.transfer_id} onClick={() => void downloadInbox(file)} className="gap-1.5">
                      {downloadingId === file.transfer_id ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />} Download
                    </Button>
                  ) : !file.completed ? (
                    <Button size="sm" variant="outline" disabled className="gap-1.5">
                      <Loader2 size={14} className="animate-spin" /> Receiving
                    </Button>
                  ) : (
                    <Button size="sm" variant="outline" onClick={() => void refresh()} className="gap-1.5">
                      <RefreshCw size={14} /> Check Vault
                    </Button>
                  )}
                </div>
                {file.completed && !file.download_path && !file.vault_id && (
                  <div role="status" className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-amber-600">
                    <AlertCircle size={14} className="mt-0.5 shrink-0" />
                    <span>
                      Transfer completed, but the encrypted Vault record is not available yet.
                      Refresh to check again; download becomes available after Vault finalization.
                    </span>
                  </div>
                )}
                {file.file_sha256 && <p className="truncate font-mono text-[10px] text-muted-foreground">SHA-256 {file.file_sha256}</p>}
              </Card>
            ))}
          </div>
        )}
      </div>

      {detail && (
        <div className="fixed inset-0 z-[100] flex items-end justify-center bg-black/60 p-0 sm:items-center sm:p-4" onClick={() => setDetail(null)}>
          <Card className="w-full max-w-lg rounded-b-none p-5 sm:rounded-xl" onClick={(event) => event.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h2 className="font-semibold">Transfer details</h2>
              <StatusPill value={detail.status} />
            </div>
            <dl className="grid grid-cols-[110px_1fr] gap-2 text-xs">
              <dt className="text-muted-foreground">Transfer ID</dt><dd className="break-all font-mono">{transferId(detail)}</dd>
              <dt className="text-muted-foreground">Peer DID</dt><dd className="break-all" title={String(detail.peer_did ?? "")}>{displayForDid(String(detail.peer_did ?? ""), String(detail.peer_did ?? "—"))}</dd>
              <dt className="text-muted-foreground">File</dt><dd className="break-all">{String(detail.filename ?? detail.path ?? "—")}</dd>
              <dt className="text-muted-foreground">Direction</dt><dd className="capitalize">{String(detail.direction ?? "outbound")}</dd>
              <dt className="text-muted-foreground">Progress</dt><dd>{formatBytes(Number(detail.bytes_sent ?? detail.bytes_transferred ?? 0))} of {formatBytes(Number(detail.size ?? 0))}</dd>
              <dt className="text-muted-foreground">Updated</dt><dd>{displayTime(detail.updated_at)}</dd>
              {(detail.last_error || detail.error) && <><dt className="text-destructive">Error</dt><dd>{String(detail.last_error ?? detail.error)}</dd></>}
            </dl>
            <div className="flex gap-2">
              <Button variant="outline" className="flex-1" onClick={() => setDetail(null)}>Close</Button>
              <Button
                variant="destructive"
                disabled={cancellingId === transferId(detail) || ["completed", "complete", "failed", "cancelled", "canceled"].includes(String(detail.status ?? "").toLowerCase())}
                className="flex-1 gap-2"
                onClick={() => void cancel(transferId(detail))}
              >
                {cancellingId === transferId(detail) ? <Loader2 size={15} className="animate-spin" /> : <Ban size={15} />} Cancel transfer
              </Button>
            </div>
          </Card>
        </div>
      )}
      {detailLoading && (
        <div className="fixed inset-0 z-[99] grid place-items-center bg-black/35" aria-live="polite">
          <div className="flex items-center gap-2 rounded-xl border border-border bg-card px-4 py-3 text-sm shadow-xl">
            <Loader2 size={17} className="animate-spin" /> Loading transfer details…
          </div>
        </div>
      )}
    </div>
  );
}

function LoadingState({ text }: { text: string }) {
  return (
    <div className="flex items-center justify-center gap-2 rounded-lg border border-border bg-card px-4 py-12 text-sm text-muted-foreground">
      <Loader2 size={18} className="animate-spin" /> {text}
    </div>
  );
}

function Empty({ icon: Icon, text }: { icon: typeof Inbox; text: string }) {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center text-muted-foreground">
      <Icon size={36} strokeWidth={1.5} />
      <p className="text-sm">{text}</p>
    </div>
  );
}
