import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FileText, Loader2, MessageSquare, Phone, RefreshCw, RotateCcw, Search, Send, Video, XCircle } from "lucide-react";
import { useNavigate, useParams, useSearchParams } from "react-router";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { AttachmentMenu } from "../../components/circle/AttachmentMenu";
import { FilesTab } from "../../components/circle/FilesTab";
import { MessageAttachment } from "../../components/circle/MessageAttachment";
import type { SharedFile } from "../../components/circle/types";
import { useCircles, useCommunicationPeers } from "../../hooks/useApiData";
import { didService } from "../../services/didService";
import chatService, { openChatSocket, parseChatPayload, type ChatMessageRecord } from "../../services/chatService";
import { useCall } from "../../../features/calls/CallContext";
import { useGroupCall } from "../../../features/calls/GroupCallContext";
import type { MediaType } from "../../../features/calls/call.types";
import { useChatUnread } from "../../contexts/ChatUnreadContext";
import { useAuth } from "../../contexts/AuthContext";
import { isMemberRole } from "../../utils/authorization";
import { peerService } from "../../services/peerService";
import { useContactNames } from "../../contexts/ContactNameContext";
import { messageRepository } from "../../../pwa/db/messageRepository";
import { pendingRepository } from "../../../pwa/db/pendingRepository";
import { decryptValue } from "../../../pwa/crypto/vault";
import { contactRepository } from "../../../pwa/db/contactRepository";
import { ApiError } from "../../services/api";

type View = "chat" | "files";

function timeLabel(timestamp: number) {
  const date = new Date(timestamp > 10_000_000_000 ? timestamp : timestamp * 1000);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function operationId() {
  return typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function isQueueableSendFailure(cause: unknown) {
  if (cause instanceof ApiError) return false;
  if (!(cause instanceof Error)) return false;
  const message = cause.message.toLowerCase();
  return message.includes("failed to fetch")
    || message.includes("network")
    || message.includes("timed out")
    || message.includes("abort")
    || message.includes("load failed");
}

function acceptedStatus(status: string | undefined) {
  return !status || status === "pending" ? "accepted_by_guardian" : status;
}

function statusLabel(status: string, read: boolean) {
  if (status === "pending_local" || status === "pending") return "Pending";
  if (status === "accepted_by_guardian") return "Sent";
  if (status === "delivered_to_remote_guardian" || status === "delivered") return read ? "Read" : "Delivered";
  if (status === "read" || read) return "Read";
  if (status === "failed_retryable" || status === "failed") return "Retry";
  if (status === "failed_permanent") return "Failed";
  if (status === "cancelled") return "Cancelled";
  return "Sent";
}

function conversationIdForRoute(isGroup: boolean, circleId?: string, peerDid?: string, guardianDid?: string, browserMemberDid?: string) {
  if (isGroup) return `circle:${circleId}`;
  const canonicalPeerDid = peerDid && guardianDid && browserMemberDid && peerDid === guardianDid
    ? browserMemberDid
    : peerDid;
  return `peer:${canonicalPeerDid}`;
}

export function ChatConversationScreen() {
  const { circleId, peerDid } = useParams<{ circleId: string; peerDid?: string }>();
  const navigate = useNavigate();
  const { session } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: circlesData, loading: circlesLoading } = useCircles();
  const { data: peersData, loading: peersLoading, error: peersError } = useCommunicationPeers();
  const circle = (Array.isArray(circlesData) ? circlesData : []).find((item: any) => item.id === circleId);
  const member = circle?.members?.find((item: any) => item.did === peerDid);
  const [cachedPeer, setCachedPeer] = useState<any>(null);
  const memberPeer = member?.did ? {
    peerId: member.did,
    did: member.did,
    online: member.status === "active",
    callAvailable: member.status === "active",
    callUnavailableReason: member.status === "active" ? undefined : "The member browser is inactive.",
  } : undefined;
  const peer = (Array.isArray(peersData) ? peersData : []).find((item: any) => item.did === peerDid) || cachedPeer || memberPeer;
  const isGroup = Boolean(circleId && !peerDid);
  const { startCall, call, currentDevice } = useCall();
  const { group } = useGroupCall();
  const { clearPeerUnread, refresh: refreshUnread } = useChatUnread();
  const { contactNameForDid } = useContactNames();
  const [records, setRecords] = useState<ChatMessageRecord[]>([]);
  const [localDid, setLocalDid] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [search, setSearch] = useState("");
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [startingCall, setStartingCall] = useState<"audio" | "video" | null>(null);
  const [liveConnected, setLiveConnected] = useState(false);
  const [queuedMessageIds, setQueuedMessageIds] = useState<Set<string>>(new Set());
  const [queuedMessages, setQueuedMessages] = useState<Map<string, { state: string; lastError?: string }>>(new Map());
  const bottomRef = useRef<HTMLDivElement>(null);
  const recordsRef = useRef<ChatMessageRecord[]>(records);
  const markedReadRef = useRef<Set<string>>(new Set());
  const view: View = searchParams.get("view") === "files" ? "files" : "chat";

  useEffect(() => {
    if (!peerDid || !peersError) return;
    void contactRepository.list().then((items) => {
      const contact = items.find((item) => item.did === peerDid);
      if (contact) setCachedPeer({ peerId: contact.displayName, did: contact.did, online: false, callAvailable: false });
    });
  }, [peerDid, peersError]);

  const loadHistory = useCallback(async () => {
    if ((isGroup && !circleId) || (!isGroup && !peerDid)) return;
    const conversationId = conversationIdForRoute(isGroup, circleId, peerDid, session?.guardianDid, session?.browserMemberDid);
    setLoading(true);
    try {
      const response = isGroup
        ? await chatService.groupHistory(circleId)
        : await chatService.directHistory(peerDid!);
      const sorted = [...response.messages].sort((a, b) => a.seq_no - b.seq_no || a.timestamp - b.timestamp);
      setRecords(sorted);
      await Promise.all(sorted.map((record) => messageRepository.save({
        id: record.message_id,
        conversationId,
        timestamp: record.timestamp,
        sequence: record.seq_no,
        status: record.status,
        value: record,
      })));
    } catch (cause) {
      try {
        const cached = await messageRepository.list(conversationId);
        const restored = await Promise.all(cached.map((record) => decryptValue<ChatMessageRecord>(record.payload)));
        setRecords(restored);
        if (restored.length) toast.info("Showing encrypted cached messages");
        else throw cause;
      } catch {
        toast.error("Conversation could not be loaded", { description: cause instanceof Error ? cause.message : undefined });
      }
    } finally {
      setLoading(false);
    }
  }, [circleId, isGroup, peerDid, session?.browserMemberDid, session?.guardianDid]);

  useEffect(() => {
    if (isMemberRole(session?.user.role) && session.browserMemberDid) {
      setLocalDid(session.browserMemberDid);
      return;
    }
    const identity = isMemberRole(session?.user.role)
      ? peerService.getLocalIdentity()
      : didService.getStatus();
    void identity.then((status) => setLocalDid(status.did)).catch(() => {});
  }, [session?.browserMemberDid, session?.user.role]);
  useEffect(() => {
    if (isMemberRole(session?.user.role)) {
      void loadHistory();
      return;
    }
    void chatService.sync().catch(() => {}).finally(() => void loadHistory());
  }, [loadHistory, session?.user.role]);
  const refreshQueuedMessages = useCallback(() => {
    void pendingRepository.list()
      .then((pending) => {
        const chatPending = pending.filter((record) => record.kind === "chat.send");
        setQueuedMessageIds(new Set(chatPending.filter((record) => record.state === "queued" || record.state === "sending").map((record) => record.id)));
        setQueuedMessages(new Map(chatPending.map((record) => [record.id, { state: record.state, lastError: record.lastError }])));
      })
      .catch(() => {
        setQueuedMessageIds(new Set());
        setQueuedMessages(new Map());
      });
  }, []);
  useEffect(() => {
    refreshQueuedMessages();
    window.addEventListener("sgx:pending-operation", refreshQueuedMessages);
    window.addEventListener("sgx:sync-state", refreshQueuedMessages);
    return () => {
      window.removeEventListener("sgx:pending-operation", refreshQueuedMessages);
      window.removeEventListener("sgx:sync-state", refreshQueuedMessages);
    };
  }, [refreshQueuedMessages]);
  useEffect(() => {
    let refreshTimer: number | undefined;
    const close = openChatSocket(() => {
      if (refreshTimer) window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(() => void loadHistory(), 100);
    }, setLiveConnected);
    return () => { if (refreshTimer) window.clearTimeout(refreshTimer); close(); };
  }, [loadHistory]);
  useEffect(() => { if (view === "chat") bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [records, view]);

  useEffect(() => { recordsRef.current = records; }, [records]);

  // A message is marked read while its conversation is the active, foreground view.
  // The backend persists the receipt before this promise resolves, so refreshing the
  // conversation list afterwards returns the canonical unread count.
  const markMessageRead = useCallback((messageId: string) => {
    if (markedReadRef.current.has(messageId)) return;
    const record = recordsRef.current.find((entry) => entry.message_id === messageId);
    if (!record || !localDid || record.sender_did === localDid || record.status === "read" || record.read_by.includes(localDid)) return;
    markedReadRef.current.add(messageId);
    void chatService.markRead(record.message_id, record.sender_did, isGroup ? circleId : undefined)
      .then(() => {
        setRecords((current) => current.map((entry) => (entry.message_id === messageId
          ? { ...entry, status: "read", read_by: entry.read_by.includes(localDid) ? entry.read_by : [...entry.read_by, localDid] }
          : entry)));
        refreshUnread();
      })
      .catch(() => { markedReadRef.current.delete(messageId); });
  }, [localDid, isGroup, circleId, refreshUnread]);

  const markConversationRead = useCallback(() => {
    recordsRef.current
      .filter((record) => record.sender_did !== localDid && record.status !== "read" && !record.read_by.includes(localDid))
      .forEach((record) => markMessageRead(record.message_id));
  }, [localDid, markMessageRead]);

  // Do not depend on the bottom sentinel for read receipts. It has zero height and
  // IntersectionObserver can miss it during the history-load/auto-scroll transition,
  // leaving a message visibly opened but still counted as unread on the list screen.
  useEffect(() => {
    if (view !== "chat" || !localDid) return;
    const isForeground = () => document.visibilityState === "visible" && document.hasFocus();
    const recheck = () => {
      if (!isForeground()) return;
      if (!isGroup && peerDid) clearPeerUnread(peerDid);
      markConversationRead();
    };

    recheck();
    document.addEventListener("visibilitychange", recheck);
    window.addEventListener("focus", recheck);
    return () => {
      document.removeEventListener("visibilitychange", recheck);
      window.removeEventListener("focus", recheck);
    };
  }, [view, localDid, records, isGroup, peerDid, clearPeerUnread, markConversationRead]);

  const send = async (content: string | null, attachmentId: string | null = null) => {
    if ((isGroup && !circleId) || (!isGroup && !peerDid) || (!content?.trim() && !attachmentId)) return;
    setSending(true);
    const sentContent = content?.trim() || null;
    const recipientId = isGroup ? circleId! : peerDid!;
    const conversationId = conversationIdForRoute(isGroup, circleId, peerDid, session?.guardianDid, session?.browserMemberDid);
    // Generated before the first attempt and reused on every retry, so a
    // network failure followed by an offline-queue replay resends the same
    // canonical ID rather than minting a new one — the backend recognizes the
    // repeat and returns the already-accepted message instead of duplicating it.
    const messageId = operationId();
    const now = Math.floor(Date.now() / 1000);
    const seqNo = Math.max(0, ...recordsRef.current.map((record) => record.seq_no)) + 1;
    try {
      const response = isGroup
        ? await chatService.sendGroup(recipientId, sentContent, attachmentId, messageId)
        : await chatService.sendDirect(recipientId, sentContent, attachmentId, messageId);
      setMessage("");
      setRecords((current) => current.some((record) => record.message_id === response.message_id) ? current : [...current, {
        message_id: response.message_id,
        sender_did: localDid || "local",
        recipient_did: recipientId,
        ...(isGroup ? { group_id: circleId } : {}),
        timestamp: now,
        seq_no: seqNo,
        encrypted_payload: JSON.stringify({ content: sentContent, attachment_id: attachmentId }),
        status: acceptedStatus(response.status),
        read_by: [],
      }]);
      // Sending is complete once /chat/send responds. History refresh must not
      // keep the composer locked if storage or synchronization is slow.
      void loadHistory();
    } catch (cause) {
      if (isQueueableSendFailure(cause)) {
        const pendingRecord: ChatMessageRecord = {
          message_id: messageId,
          sender_did: localDid || "local",
          recipient_did: recipientId,
          ...(isGroup ? { group_id: circleId } : {}),
          timestamp: now,
          seq_no: seqNo,
          encrypted_payload: JSON.stringify({ content: sentContent, attachment_id: attachmentId }),
          status: "pending_local",
          read_by: [],
        };
        await messageRepository.saveAndQueue({
          id: messageId,
          conversationId,
          timestamp: now,
          sequence: seqNo,
          status: "pending_local",
          value: pendingRecord,
        }, {
          id: messageId,
          kind: "chat.send",
          value: {
            mode: isGroup ? "group" : "direct",
            recipientId,
            content: sentContent,
            attachmentId,
          },
        });
        setQueuedMessageIds((current) => new Set([...current, messageId]));
        window.dispatchEvent(new CustomEvent("sgx:pending-operation"));
        setRecords((current) => current.some((record) => record.message_id === messageId) ? current : [...current, pendingRecord]);
        setMessage("");
        toast.info("Message queued", { description: "It will send when Guardian reconnects." });
        return;
      }
      toast.error("Message was not sent", { description: cause instanceof Error ? cause.message : undefined });
    } finally {
      setSending(false);
    }
  };

  const cancelQueuedMessage = async (messageId: string) => {
    await pendingRepository.cancel(messageId);
    await messageRepository.markCancelled(messageId);
    setRecords((current) => current.map((record) => record.message_id === messageId ? { ...record, status: "cancelled" } : record));
    refreshQueuedMessages();
    window.dispatchEvent(new CustomEvent("sgx:pending-operation"));
  };

  const retryQueuedMessage = async (messageId: string) => {
    await pendingRepository.retry(messageId);
    await messageRepository.updateStatus(messageId, "pending_local");
    setRecords((current) => current.map((record) => record.message_id === messageId ? { ...record, status: "pending_local" } : record));
    refreshQueuedMessages();
    window.dispatchEvent(new CustomEvent("sgx:pending-operation"));
  };

  const attach = async (file: File) => {
    setSending(true);
    setUploadProgress(0);
    try {
      const uploaded = await chatService.upload(file, (loaded, total) => setUploadProgress(total ? Math.round((loaded / total) * 100) : 0));
      await send(file.name, uploaded.attachment_id);
      toast.success("File shared securely");
    } catch (cause) {
      toast.error("File could not be shared", { description: cause instanceof Error ? cause.message : undefined });
    } finally {
      setSending(false);
      setUploadProgress(null);
    }
  };

  const callPeer = async (media: MediaType[]) => {
    if (isGroup || !peerDid) return;
    if (call || group) {
      toast.error("Guardian is busy", { description: "End or leave the current call before starting another." });
      return;
    }
    if (!peer) {
      toast.error("Peer is unavailable for calls");
      return;
    }
    // Browser Circle members are routed by DID; peer.peerId for a browser
    // member is a display label (see useCommunicationPeers), not a call
    // target, so it must never be sent to the call API.
    const target = peer.memberType === "browser" ? (peer.did || peerDid) : (peer.peerId || peerDid);
    if (target === currentDevice) {
      toast.info("This is the current Guardian");
      return;
    }
    const mode = media.includes("video") ? "video" : "audio";
    setStartingCall(mode);
    try {
      await startCall(target, media, peer.online);
    } catch (cause) {
      toast.error("Call could not start", { description: cause instanceof Error ? cause.message : "The peer may be unavailable." });
    } finally {
      setStartingCall(null);
    }
  };

  const messages = useMemo(() => records.map((record) => {
    const payload = parseChatPayload(record);
    const isMe = record.sender_did === "local" || (localDid ? record.sender_did === localDid : (isGroup ? false : record.sender_did !== peerDid));
    const senderMember = circle?.members?.find((item: any) => item.did === record.sender_did);
    const attachment = payload.attachment_id ? {
      name: payload.content || `Attachment ${payload.attachment_id.slice(0, 8)}`,
      sizeBytes: 0,
      mime: "application/octet-stream",
      kind: "file" as const,
      url: chatService.downloadUrl(payload.attachment_id),
    } : undefined;
    const queue = queuedMessages.get(record.message_id);
    return {
      id: record.message_id,
      sender: isMe ? "You" : (contactNameForDid(record.sender_did) || senderMember?.name || member?.name || record.sender_did),
      content: attachment ? "" : (payload.content || ""),
      timestamp: timeLabel(record.timestamp),
      isMe,
      read: record.status === "read" || record.read_by.length > 0,
      status: record.status === "pending" && isMe && !queuedMessageIds.has(record.message_id) ? "accepted_by_guardian" : record.status,
      queueState: queue?.state,
      queueError: queue?.lastError,
      attachment,
    };
  }).filter((item) => {
    const query = search.trim().toLowerCase();
    if (!query) return true;
    return [item.sender, item.content, item.status, item.queueError].join(" ").toLowerCase().includes(query);
  }), [records, localDid, isGroup, peerDid, circle, member, contactNameForDid, queuedMessageIds, queuedMessages, search]);

  const files = useMemo<SharedFile[]>(() => messages.filter((item) => item.attachment).map((item) => ({
    id: item.id,
    ...item.attachment!,
    sharedBy: item.sender,
    sharedAt: item.timestamp,
  })).reverse(), [messages]);

  if ((isGroup && circlesLoading) || (!isGroup && peersLoading)) return <div className="grid h-full place-items-center"><Loader2 className="animate-spin" /></div>;
  if ((isGroup && !circle) || (!isGroup && !peer && !member)) return <div className="grid h-full place-items-center p-6 text-sm text-muted-foreground">Conversation not found.</div>;

  const peerContactName = !isGroup ? (contactNameForDid(peerDid) || contactNameForDid(peer?.did)) : undefined;
  const title = isGroup ? circle.name : (peerContactName || member?.name || peer?.peerId || peerDid);
  const subtitle = `${isGroup ? `Secure group chat · ${circle.members?.length || 0} members` : "Private peer-to-peer chat"} · ${liveConnected ? "Live" : "Reconnecting…"}`;
  const peerComposerName = peerContactName || member?.name || peer?.peerId || "peer";
  return (
    <div className="flex h-full flex-col">
      <PageHeader title={title} subtitle={subtitle} onBack={() => navigate(isGroup ? `/network/${circleId}?tab=members` : "/chats")} right={
        <div className="flex items-center gap-1">
          {!isGroup && <>
            <button aria-label={`Voice call ${title}`} title="Voice call" disabled={startingCall !== null || !peer} onClick={() => void callPeer(["audio"])} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted disabled:cursor-not-allowed disabled:opacity-35">{startingCall === "audio" ? <Loader2 size={18} className="animate-spin" /> : <Phone size={18} />}</button>
            <button aria-label={`Video call ${title}`} title="Video call" disabled={startingCall !== null || !peer} onClick={() => void callPeer(["audio", "video"])} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted disabled:cursor-not-allowed disabled:opacity-35">{startingCall === "video" ? <Loader2 size={18} className="animate-spin" /> : <Video size={18} />}</button>
          </>}
          <button aria-label="Refresh messages" onClick={() => void loadHistory()} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted"><RefreshCw size={18} /></button>
        </div>
      } />
      <div className="flex shrink-0 border-b border-border bg-card">
        {(["chat", "files"] as View[]).map((item) => (
          <button key={item} onClick={() => setSearchParams(item === "files" ? { view: "files" } : {})} className="flex flex-1 items-center justify-center gap-2 py-3 text-sm font-medium capitalize" style={{ color: view === item ? "var(--primary)" : "var(--muted-foreground)", borderBottom: view === item ? "2px solid var(--primary)" : "2px solid transparent" }}>
            {item === "chat" ? <MessageSquare size={16} /> : <FileText size={16} />}{item}
          </button>
        ))}
      </div>
      {view === "files" ? <FilesTab files={files} /> : <>
        <div className="shrink-0 border-b border-border bg-card px-3 py-2 md:px-6">
          <div className="mx-auto flex max-w-2xl items-center gap-2 rounded-full border border-border bg-input-background px-3">
            <Search size={16} className="shrink-0 text-muted-foreground" />
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search messages" className="h-10 flex-1 bg-transparent text-sm outline-none" />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col gap-3 p-4 md:p-6">
            {loading && <div className="flex flex-1 items-center justify-center gap-2 text-sm text-muted-foreground"><Loader2 size={18} className="animate-spin" /> Loading secure conversation…</div>}
            {!loading && messages.length === 0 && <div className="flex flex-1 flex-col items-center justify-center gap-3 text-center text-muted-foreground"><MessageSquare size={36} /><p className="text-sm font-medium text-foreground">No messages yet</p><p className="max-w-xs text-xs">Start this secure {isGroup ? "Circle conversation" : "peer-to-peer conversation"}.</p></div>}
            {messages.map((item) => <div key={item.id} className={`flex flex-col ${item.isMe ? "items-end" : "items-start"}`}>
              {!item.isMe && <span className="mb-1 ml-1 max-w-[78%] truncate text-xs text-muted-foreground">{item.sender}</span>}
              <div className="max-w-[78%] overflow-hidden rounded-2xl border border-border px-4 py-2.5" style={{ background: item.isMe ? "var(--primary)" : "var(--card)", borderColor: item.isMe ? "transparent" : undefined }}>
                {item.attachment ? <MessageAttachment attachment={item.attachment} isMe={item.isMe} /> : <p className="text-sm leading-6" style={{ color: item.isMe ? "var(--primary-foreground)" : "var(--foreground)" }}>{item.content}</p>}
              </div>
              <div className="mx-1 mt-1 flex max-w-[78%] items-center gap-1 text-[10px] text-muted-foreground">
                <span className="truncate">{item.timestamp}{item.isMe ? ` · ${statusLabel(item.status, item.read)}` : ""}</span>
                {item.isMe && (item.queueState === "queued" || item.queueState === "sending" || item.queueState === "failed_permanent" || item.status === "failed_permanent") && (
                  <>
                    {(item.queueState === "failed_permanent" || item.status === "failed_permanent") && <button type="button" aria-label="Retry message" title={item.queueError || "Retry message"} onClick={() => void retryQueuedMessage(item.id)} className="grid h-6 w-6 place-items-center rounded-full hover:bg-muted"><RotateCcw size={12} /></button>}
                    {(item.queueState === "queued" || item.queueState === "sending") && <button type="button" aria-label="Cancel queued message" title={item.queueError || "Cancel queued message"} onClick={() => void cancelQueuedMessage(item.id)} className="grid h-6 w-6 place-items-center rounded-full hover:bg-muted"><XCircle size={12} /></button>}
                  </>
                )}
              </div>
            </div>)}
            <div ref={bottomRef} />
          </div>
        </div>
        <div className="shrink-0 border-t border-border bg-card px-3 py-3 md:px-6">
          {uploadProgress !== null && <div className="mx-auto mb-2 max-w-2xl text-xs text-muted-foreground">Uploading file… {uploadProgress}%</div>}
          <div className="mx-auto flex max-w-2xl items-center gap-2">
            <AttachmentMenu onPick={(file) => void attach(file)} disabled={sending} />
            <input value={message} onChange={(event) => setMessage(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void send(message); }} disabled={sending} placeholder={isGroup ? "Secure Circle message…" : `Message ${peerComposerName}…`} className="h-11 flex-1 rounded-full border border-border bg-input-background px-4 text-sm outline-none" />
            <button type="button" aria-label="Send message" onClick={() => void send(message)} disabled={sending || !message.trim()} className="grid h-11 w-11 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground disabled:opacity-40">{sending ? <Loader2 size={18} className="animate-spin" /> : <Send size={18} />}</button>
          </div>
        </div>
      </>}
    </div>
  );
}
