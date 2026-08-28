import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Info, Loader2, MessageSquare, Phone, RefreshCw, RotateCcw, Search, Send, UserPlus, Video, X, XCircle } from "lucide-react";
import { useNavigate, useParams, useSearchParams } from "react-router";
import * as Dialog from "@radix-ui/react-dialog";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { AttachmentMenu } from "../../components/circle/AttachmentMenu";
import { MessageAttachment } from "../../components/circle/MessageAttachment";
import { useCircles, useCommunicationPeers } from "../../hooks/useApiData";
import { didService } from "../../services/didService";
import chatService, { openChatSocket, parseChatPayload, type ChatMessageRecord } from "../../services/chatService";
import { useCall } from "../../../features/calls/CallContext";
import { useGroupCall } from "../../../features/calls/GroupCallContext";
import type { MediaType } from "../../../features/calls/call.types";
import { useChatUnread } from "../../contexts/ChatUnreadContext";
import { useChatPaneMode } from "../../contexts/ChatPaneModeContext";
import { useAuth } from "../../contexts/AuthContext";
import { isMemberRole } from "../../utils/authorization";
import { peerService, type Peer } from "../../services/peerService";
import { useContactNames } from "../../contexts/ContactNameContext";
import { messageRepository } from "../../../pwa/db/messageRepository";
import { pendingRepository } from "../../../pwa/db/pendingRepository";
import { decryptValue } from "../../../pwa/crypto/vault";
import { contactRepository } from "../../../pwa/db/contactRepository";
import { ApiError } from "../../services/api";
import contactService from "../../services/contactService";

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

function readBy(record: Pick<ChatMessageRecord, "read_by">) {
  return Array.isArray(record.read_by) ? record.read_by : [];
}

function conversationIdForRoute(isGroup: boolean, circleId?: string, peerDid?: string, guardianDid?: string, browserMemberDid?: string) {
  if (isGroup) return `circle:${circleId}`;
  const canonicalPeerDid = peerDid && guardianDid && browserMemberDid && peerDid === guardianDid
    ? browserMemberDid
    : peerDid;
  return `peer:${canonicalPeerDid}`;
}

function PeerDetailsDialog({
  open,
  onOpenChange,
  peer,
  title,
  saved,
  saving,
  onAddContact,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  peer?: Peer | null;
  title: string;
  saved: boolean;
  saving: boolean;
  onAddContact: () => void;
}) {
  if (!peer) return null;
  const rows = [
    { label: "DID", value: peer.did, mono: true },
    { label: "Device", value: peer.deviceName || peer.peerId },
    { label: "Peer ID", value: peer.peerId, mono: true },
    { label: "IP Address", value: peer.ip || "Hidden", mono: true },
    { label: "Role", value: peer.role },
    { label: "Type", value: peer.memberType },
    { label: "Presence", value: peer.presenceStatus || (peer.online ? "online" : "offline") },
  ];
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[60] bg-background/80 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-[70] flex w-[calc(100%-40px)] max-w-md -translate-x-1/2 -translate-y-1/2 flex-col gap-4 rounded-lg border border-border bg-card p-5 shadow-xl">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <Dialog.Title className="truncate text-base font-semibold">{title}</Dialog.Title>
              <Dialog.Description className="mt-1 text-xs text-muted-foreground">Verified communication device</Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <button aria-label="Close device details" className="grid h-9 w-9 shrink-0 place-items-center rounded-full hover:bg-muted"><X size={17} /></button>
            </Dialog.Close>
          </div>
          <dl className="divide-y divide-border overflow-hidden rounded-lg border border-border">
            {rows.map((row) => (
              <div key={row.label} className="flex items-center justify-between gap-4 px-3 py-2.5">
                <dt className="text-xs text-muted-foreground">{row.label}</dt>
                <dd className={`min-w-0 truncate text-right text-xs font-medium ${row.mono ? "font-mono" : ""}`} title={row.value || undefined}>{row.value || "Unavailable"}</dd>
              </div>
            ))}
          </dl>
          <button
            type="button"
            onClick={onAddContact}
            disabled={saved || saving}
            className="flex h-11 items-center justify-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground disabled:cursor-default disabled:opacity-50"
          >
            {saving ? <Loader2 size={16} className="animate-spin" /> : <UserPlus size={16} />}
            {saved ? "Contact saved" : "Save contact"}
          </button>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function ContactSaveDialog({
  open,
  onOpenChange,
  peer,
  defaultName,
  saving,
  onSave,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  peer?: Peer | null;
  defaultName: string;
  saving: boolean;
  onSave: (fields: { name: string; alias: string; notes: string }) => void;
}) {
  const [name, setName] = useState(defaultName);
  const [alias, setAlias] = useState("");
  const [notes, setNotes] = useState("");

  useEffect(() => {
    if (!open) return;
    setName(defaultName);
    setAlias(peer?.deviceName && peer.deviceName !== defaultName ? peer.deviceName : "");
    setNotes("");
  }, [defaultName, open, peer?.deviceName]);

  if (!peer?.did) return null;
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[80] bg-background/80 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-[90] flex w-[calc(100%-40px)] max-w-md -translate-x-1/2 -translate-y-1/2 flex-col gap-4 rounded-lg border border-border bg-card p-5 shadow-xl">
          <div className="flex items-start justify-between gap-3">
            <div>
              <Dialog.Title className="text-base font-semibold">Save contact</Dialog.Title>
              <Dialog.Description className="mt-1 text-xs text-muted-foreground">Add a trusted identity by DID.</Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <button aria-label="Close save contact" className="grid h-9 w-9 shrink-0 place-items-center rounded-full hover:bg-muted"><X size={17} /></button>
            </Dialog.Close>
          </div>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">DID</span>
            <input value={peer.did} disabled className="h-11 w-full rounded-md border border-border bg-muted px-3 font-mono text-xs outline-none opacity-80" />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">Name</span>
            <input autoFocus value={name} onChange={(event) => setName(event.target.value)} disabled={saving} placeholder="Display name" className="h-11 w-full rounded-md border border-border bg-input-background px-3 text-sm outline-none" />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">Alias</span>
            <input value={alias} onChange={(event) => setAlias(event.target.value)} disabled={saving} placeholder="Optional alias" className="h-11 w-full rounded-md border border-border bg-input-background px-3 text-sm outline-none" />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">Notes</span>
            <textarea value={notes} onChange={(event) => setNotes(event.target.value)} disabled={saving} placeholder="Optional notes" rows={3} className="w-full resize-none rounded-md border border-border bg-input-background px-3 py-2 text-sm outline-none" />
          </label>
          <button
            type="button"
            onClick={() => onSave({ name, alias, notes })}
            disabled={saving || !name.trim()}
            className="flex h-11 items-center justify-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground disabled:cursor-default disabled:opacity-50"
          >
            {saving ? <Loader2 size={16} className="animate-spin" /> : <UserPlus size={16} />}
            Save contact
          </button>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function ChatConversationScreen() {
  const { circleId, peerDid } = useParams<{ circleId: string; peerDid?: string }>();
  const navigate = useNavigate();
  const { session } = useAuth();
  const paneMode = useChatPaneMode();
  const [searchParams] = useSearchParams();
  const { data: circlesData, loading: circlesLoading } = useCircles();
  const { data: peersData, loading: peersLoading, error: peersError } = useCommunicationPeers();
  const circle = (Array.isArray(circlesData) ? circlesData : []).find((item: any) => item.id === circleId);
  const member = circle?.members?.find((item: any) => item.did === peerDid);
  const [cachedPeer, setCachedPeer] = useState<any>(null);
  const memberPeer = member?.did ? {
    peerId: member.did,
    did: member.did,
    online: member.presenceStatus ? member.presenceStatus === "online" : member.status === "active",
    callAvailable: member.status === "active",
    callUnavailableReason: member.status === "active" ? undefined : "The member browser is inactive.",
  } : undefined;
  const peer = (Array.isArray(peersData) ? peersData : []).find((item: any) => item.did === peerDid) || cachedPeer || memberPeer;
  const isGroup = Boolean(circleId && !peerDid);
  const { startCall, call, currentDevice } = useCall();
  const groupCalling = useGroupCall();
  const { group } = groupCalling;
  const { clearPeerUnread, clearCircleUnread, refresh: refreshUnread } = useChatUnread();
  const { contacts, contactNameForDid, upsertContact, refreshContacts } = useContactNames();
  const [records, setRecords] = useState<ChatMessageRecord[]>([]);
  const [localDid, setLocalDid] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [search, setSearch] = useState("");
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [startingCall, setStartingCall] = useState<"audio" | "video" | null>(null);
  const [liveConnected, setLiveConnected] = useState(false);
  const [typingSenderDid, setTypingSenderDid] = useState<string | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [contactDialogOpen, setContactDialogOpen] = useState(false);
  const [savingContact, setSavingContact] = useState(false);
  const [queuedMessageIds, setQueuedMessageIds] = useState<Set<string>>(new Set());
  const [queuedMessages, setQueuedMessages] = useState<Map<string, { state: string; lastError?: string }>>(new Map());
  const bottomRef = useRef<HTMLDivElement>(null);
  const recordsRef = useRef<ChatMessageRecord[]>(records);
  const loadRequestRef = useRef(0);
  // Messages the server has already accepted (a real message_id came back
  // from POST /chat/send) but that a subsequent GET /chat/history has not
  // yet reflected — e.g. a receiving/reading node whose peer-identity
  // resolution takes another pass, or plain eventual-consistency lag. Kept
  // here and re-merged into every history refresh until the server itself
  // reports the message, so a fetch racing right behind a send can never
  // make the just-sent message flash and vanish from the sender's own view.
  const confirmedSendsRef = useRef<Map<string, ChatMessageRecord>>(new Map());
  const markedReadRef = useRef<Set<string>>(new Set());
  const unreadRefreshTimerRef = useRef<number | undefined>(undefined);
  const peerTypingTimeoutRef = useRef<number | undefined>(undefined);
  const typingSendTimeoutRef = useRef<number | undefined>(undefined);
  const isTypingSentRef = useRef(false);
  const openedFromChats = isGroup && searchParams.get("from") === "chats";

  const circleMembers = useMemo(() => Array.isArray(circle?.members) ? circle.members : [], [circle?.members]);
  const nodeIdsForMember = useCallback((circleMember: any) => {
    const explicit = [
      circleMember?.nodeHint, circleMember?.node_hint, circleMember?.device_id,
      circleMember?.deviceId, circleMember?.peerId, circleMember?.peer_id,
    ].map((value) => String(value || "").trim().toLowerCase()).filter(Boolean);
    if (explicit.length) return explicit;
    const memberDid = String(circleMember?.did || "").trim().toLowerCase();
    if (!memberDid) return [];
    return (Array.isArray(circlesData) ? circlesData : [])
      .flatMap((candidateCircle: any) => Array.isArray(candidateCircle?.members) ? candidateCircle.members : [])
      .filter((candidateMember: any) => String(candidateMember?.did || "").trim().toLowerCase() === memberDid)
      .flatMap((candidateMember: any) => [candidateMember?.nodeHint, candidateMember?.node_hint])
      .map((value: unknown) => String(value || "").trim().toLowerCase())
      .filter(Boolean);
  }, [circlesData]);

  const peerForMember = useCallback((circleMember: any) => {
    if (String(circleMember?.memberType || circleMember?.member_type || "").toLowerCase() === "browser") return undefined;
    const candidates = nodeIdsForMember(circleMember);
    const explicitNodeMatch = candidates.length
      ? (Array.isArray(peersData) ? peersData : []).find((candidate: any) => candidates.includes(String(candidate.peerId || "").trim().toLowerCase()))
      : undefined;
    if (explicitNodeMatch) return explicitNodeMatch;
    const memberDid = String(circleMember?.did || "").trim().toLowerCase();
    return memberDid
      ? (Array.isArray(peersData) ? peersData : []).find((candidate: any) => String(candidate.did || "").trim().toLowerCase() === memberDid)
      : undefined;
  }, [nodeIdsForMember, peersData]);

  const callableGroupMemberIds = useMemo(() => Array.from(new Set(
    circleMembers
      .map((circleMember: any) => {
        const memberDid = String(circleMember?.did || "").trim();
        const isBrowserMember = String(circleMember?.memberType || circleMember?.member_type || "").toLowerCase() === "browser";
        if (isBrowserMember) return memberDid || undefined;
        const memberPeer = peerForMember(circleMember);
        return memberPeer?.callAvailable ? memberPeer.peerId : undefined;
      })
      .filter((id): id is string => Boolean(id))
      .filter((id) => id !== currentDevice && id !== session?.browserMemberDid),
  )), [circleMembers, currentDevice, peerForMember, session?.browserMemberDid]);

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
    // Several independent triggers can call loadHistory for the same
    // conversation in quick succession (initial mount, the socket-driven
    // refresh, offline-replay reconciliation) and their responses can land
    // out of order. A token guard makes only the most recently *issued*
    // call allowed to touch state, so a slow/failed stale call can never
    // stomp a newer, already-rendered good result — this was the source of
    // messages briefly showing then flashing to "No messages yet".
    const requestToken = ++loadRequestRef.current;
    const isStale = () => loadRequestRef.current !== requestToken;
    setLoading(true);
    try {
      const response = isGroup
        ? await chatService.groupHistory(circleId!)
        : await chatService.directHistory(peerDid!);
      if (isStale()) return;
      const fetched = [...response.messages]
        .map((record) => ({ ...record, read_by: readBy(record) }));
      // A message still tracked here means the server accepted it (we hold
      // a real message_id from its /chat/send response) but this fetch's
      // list doesn't include it yet — keep showing it rather than let it
      // vanish. Once the server does report it, drop the held copy so the
      // server's version (status/read receipts) takes over.
      for (const record of fetched) confirmedSendsRef.current.delete(record.message_id);
      const sorted = [...fetched, ...confirmedSendsRef.current.values()]
        .sort((a, b) => a.seq_no - b.seq_no || a.timestamp - b.timestamp);
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
      if (isStale()) return;
      try {
        const cached = await messageRepository.list(conversationId);
        const restored = await Promise.all(cached.map((record) => decryptValue<ChatMessageRecord>(record.payload)));
        if (isStale()) return;
        if (restored.length) {
          setRecords(restored);
          toast.info("Showing encrypted cached messages");
        } else if (!recordsRef.current.length) {
          // Only clear to empty when nothing was ever successfully shown —
          // a transient fetch failure must never wipe an already-loaded
          // conversation back to "No messages yet".
          setRecords([]);
        }
      } catch {
        if (!isStale() && !recordsRef.current.length) setRecords([]);
        console.warn("Conversation history unavailable", cause);
      }
    } finally {
      if (!isStale()) setLoading(false);
    }
  }, [circleId, isGroup, peerDid, session?.browserMemberDid, session?.guardianDid]);

  useEffect(() => {
    if (isMemberRole(session?.user.role) && session?.browserMemberDid) {
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
    let timer: number | undefined;
    const reconcileReplayedMessages = () => {
      refreshQueuedMessages();
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        void loadHistory();
        refreshUnread();
      }, 50);
    };
    window.addEventListener("sgx:chat-replayed", reconcileReplayedMessages);
    return () => {
      if (timer) window.clearTimeout(timer);
      window.removeEventListener("sgx:chat-replayed", reconcileReplayedMessages);
    };
  }, [loadHistory, refreshQueuedMessages, refreshUnread]);
  useEffect(() => {
    let refreshTimer: number | undefined;
    const close = openChatSocket((event) => {
      if (event?.event_type === "Typing") {
        const isThisConversation = isGroup
          ? event.conversation_id === circleId
          : event.sender_did === peerDid;
        if (!isThisConversation || event.sender_did === localDid) return;
        if (peerTypingTimeoutRef.current) window.clearTimeout(peerTypingTimeoutRef.current);
        if (event.is_typing) {
          setTypingSenderDid(event.sender_did ?? null);
          peerTypingTimeoutRef.current = window.setTimeout(() => setTypingSenderDid(null), 6_000);
        } else {
          setTypingSenderDid(null);
        }
        return;
      }
      if (refreshTimer) window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(() => void loadHistory(), 100);
    }, setLiveConnected);
    return () => {
      if (refreshTimer) window.clearTimeout(refreshTimer);
      if (peerTypingTimeoutRef.current) window.clearTimeout(peerTypingTimeoutRef.current);
      close();
    };
  }, [loadHistory, isGroup, circleId, peerDid, localDid]);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [records]);

  useEffect(() => { recordsRef.current = records; }, [records]);

  const scheduleUnreadRefresh = useCallback(() => {
    if (unreadRefreshTimerRef.current) window.clearTimeout(unreadRefreshTimerRef.current);
    unreadRefreshTimerRef.current = window.setTimeout(refreshUnread, 250);
  }, [refreshUnread]);

  useEffect(() => () => {
    if (unreadRefreshTimerRef.current) window.clearTimeout(unreadRefreshTimerRef.current);
  }, []);

  const markConversationRead = useCallback(() => {
    if (!localDid) return;
    const conversationId = conversationIdForRoute(isGroup, circleId, peerDid, session?.guardianDid, session?.browserMemberDid);
    const unread = recordsRef.current.filter((record) => (
      record.sender_did !== localDid
      && !readBy(record).includes(localDid)
      && (!markedReadRef.current.has(record.message_id))
    ));
    if (!unread.length) return;
    unread.forEach((record) => markedReadRef.current.add(record.message_id));
    setRecords((current) => current.map((entry) => {
      if (!unread.some((record) => record.message_id === entry.message_id)) return entry;
      return {
        ...entry,
        status: isGroup ? entry.status : "read",
        read_by: readBy(entry).includes(localDid) ? readBy(entry) : [...readBy(entry), localDid],
      };
    }));
    void messageRepository.markConversationRead(conversationId, localDid, isGroup)
      .finally(scheduleUnreadRefresh);
    void Promise.all(unread.map((record) =>
      chatService.markRead(record.message_id, record.sender_did, isGroup ? circleId : undefined)
        .catch(() => { markedReadRef.current.delete(record.message_id); }),
    )).finally(scheduleUnreadRefresh);
  }, [circleId, isGroup, localDid, peerDid, scheduleUnreadRefresh, session?.browserMemberDid, session?.guardianDid]);

  // Do not depend on the bottom sentinel for read receipts. It has zero height and
  // IntersectionObserver can miss it during the history-load/auto-scroll transition,
  // leaving a message visibly opened but still counted as unread on the list screen.
  useEffect(() => {
    if (!localDid) return;
    const isForeground = () => document.visibilityState === "visible" && document.hasFocus();
    const recheck = () => {
      if (!isForeground()) return;
      if (isGroup && circleId) clearCircleUnread(circleId);
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
  }, [localDid, records, isGroup, circleId, peerDid, clearPeerUnread, clearCircleUnread, markConversationRead]);

  const sendTypingSignal = useCallback((isTyping: boolean) => {
    if ((isGroup && !circleId) || (!isGroup && !peerDid)) return;
    if (isTypingSentRef.current === isTyping) return;
    isTypingSentRef.current = isTyping;
    const recipientId = isGroup ? circleId! : peerDid!;
    void chatService.setTyping(recipientId, isGroup, isTyping).catch(() => {
      // Best-effort: the receiver clears a dropped typing signal after a timeout.
    });
  }, [isGroup, circleId, peerDid]);

  const handleComposerChange = useCallback((value: string) => {
    setMessage(value);
    if (typingSendTimeoutRef.current) window.clearTimeout(typingSendTimeoutRef.current);
    if (value.trim()) {
      sendTypingSignal(true);
      typingSendTimeoutRef.current = window.setTimeout(() => sendTypingSignal(false), 3_000);
    } else {
      sendTypingSignal(false);
    }
  }, [sendTypingSignal]);

  useEffect(() => () => {
    if (typingSendTimeoutRef.current) window.clearTimeout(typingSendTimeoutRef.current);
    isTypingSentRef.current = false;
  }, [circleId, peerDid]);

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
      if (typingSendTimeoutRef.current) window.clearTimeout(typingSendTimeoutRef.current);
      sendTypingSignal(false);
      const acceptedRecord: ChatMessageRecord = {
        message_id: response.message_id,
        sender_did: localDid || "local",
        recipient_did: recipientId,
        ...(isGroup ? { group_id: circleId } : {}),
        timestamp: now,
        seq_no: seqNo,
        encrypted_payload: JSON.stringify({ content: sentContent, attachment_id: attachmentId }),
        status: acceptedStatus(response.status),
        read_by: [],
      };
      // The server just handed back a real message_id, so this send is
      // confirmed regardless of what the next history fetch shows.
      confirmedSendsRef.current.set(response.message_id, acceptedRecord);
      setRecords((current) => current.some((record) => record.message_id === response.message_id) ? current : [...current, acceptedRecord]);
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

  const peerSavedAsContact = !!peer?.did && contacts.some((contact) => contact.did.toLowerCase() === peer.did!.toLowerCase());
  const openContactDialog = () => {
    if (!peer?.did || peerSavedAsContact) return;
    setContactDialogOpen(true);
  };

  const savePeerContact = async ({ name, alias, notes }: { name: string; alias: string; notes: string }) => {
    if (!peer?.did || peerSavedAsContact || savingContact) return;
    setSavingContact(true);
    try {
      const response = await contactService.create({
        did: peer.did,
        name: name.trim() || undefined,
        alias: alias.trim() || undefined,
        notes: notes.trim() || undefined,
      });
      upsertContact(response.contact);
      void refreshContacts();
      setContactDialogOpen(false);
      toast.success("Contact saved");
    } catch (cause) {
      toast.error("Contact was not saved", { description: cause instanceof Error ? cause.message : undefined });
    } finally {
      setSavingContact(false);
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

  const callGroup = async (media: MediaType[]) => {
    if (!isGroup || !circleId) return;
    if (call || group) {
      toast.error("Guardian is busy", { description: "End or leave the current call before starting another." });
      return;
    }
    if (!callableGroupMemberIds.length) {
      toast.error("No callable Circle members were found.");
      return;
    }
    const mode = media.includes("video") ? "video" : "audio";
    setStartingCall(mode);
    try {
      await groupCalling.createGroup(callableGroupMemberIds, false, media, `${circle?.name || "Circle"} Circle call`);
      toast.success(`Calling ${callableGroupMemberIds.length} Circle member${callableGroupMemberIds.length === 1 ? "" : "s"}`);
    } catch (cause) {
      toast.error("Circle call could not start", { description: cause instanceof Error ? cause.message : "One or more members may be unavailable." });
    } finally {
      setStartingCall(null);
    }
  };

  const messages = useMemo(() => records.map((record) => {
    const payload = parseChatPayload(record);
    const isMe = record.sender_did === "local" || (localDid ? record.sender_did === localDid : (isGroup ? false : record.sender_did !== peerDid));
    const senderMember = circle?.members?.find((item: any) => item.did === record.sender_did);
    const attachment = payload.attachment_id ? {
      attachmentId: payload.attachment_id,
      name: payload.attachment_name || payload.content || `Attachment ${payload.attachment_id.slice(0, 8)}`,
      sizeBytes: payload.attachment_size || 0,
      mime: payload.attachment_mime || "application/octet-stream",
      kind: payload.attachment_mime?.startsWith("image/") ? "image" as const : "file" as const,
      url: chatService.downloadUrl(payload.attachment_id),
    } : undefined;
    const queue = queuedMessages.get(record.message_id);
    return {
      id: record.message_id,
      sender: isMe ? "You" : (contactNameForDid(record.sender_did) || senderMember?.name || member?.name || record.sender_did),
      content: attachment ? "" : (payload.content || ""),
      timestamp: timeLabel(record.timestamp),
      isMe,
      // For a group, a single reader shouldn't flip the sender's view to
      // "Read" — the backend only sets status to "read" once every circle
      // member has read it, so trust that instead of read_by.length > 0.
      read: record.status === "read",
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

  if ((isGroup && circlesLoading) || (!isGroup && peersLoading)) return <div className="grid h-full place-items-center"><Loader2 className="animate-spin" /></div>;
  if ((isGroup && !circle) || (!isGroup && !peer && !member)) return <div className="grid h-full place-items-center p-6 text-sm text-muted-foreground">Conversation not found.</div>;

  const peerContactName = !isGroup ? (contactNameForDid(peerDid) || contactNameForDid(peer?.did)) : undefined;
  const title = isGroup ? circle!.name : (peerContactName || member?.name || peer?.peerId || peerDid);
  const subtitle = `${isGroup ? `Secure group chat · ${circle!.members?.length || 0} members` : "Private peer-to-peer chat"} · ${liveConnected ? "Live" : "Reconnecting…"}`;
  const peerComposerName = peerContactName || member?.name || peer?.peerId || "peer";
  return (
    <div className="flex h-full flex-col">
      <PageHeader showBack={paneMode === "standalone"} title={title} subtitle={subtitle} onBack={() => navigate(isGroup ? (openedFromChats ? "/chats" : `/network/${circleId}?tab=members`) : "/chats")} right={
        <div className="flex items-center gap-1">
          {isGroup ? <>
            <button aria-label={`Voice call ${title}`} title={callableGroupMemberIds.length ? "Voice call Circle" : "No callable Circle members"} disabled={startingCall !== null || callableGroupMemberIds.length === 0} onClick={() => void callGroup(["audio"])} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted disabled:cursor-not-allowed disabled:opacity-35">{startingCall === "audio" ? <Loader2 size={18} className="animate-spin" /> : <Phone size={18} />}</button>
            <button aria-label={`Video call ${title}`} title={callableGroupMemberIds.length ? "Video call Circle" : "No callable Circle members"} disabled={startingCall !== null || callableGroupMemberIds.length === 0} onClick={() => void callGroup(["audio", "video"])} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted disabled:cursor-not-allowed disabled:opacity-35">{startingCall === "video" ? <Loader2 size={18} className="animate-spin" /> : <Video size={18} />}</button>
          </> : <>
            <button aria-label={`Voice call ${title}`} title="Voice call" disabled={startingCall !== null || !peer} onClick={() => void callPeer(["audio"])} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted disabled:cursor-not-allowed disabled:opacity-35">{startingCall === "audio" ? <Loader2 size={18} className="animate-spin" /> : <Phone size={18} />}</button>
            <button aria-label={`Video call ${title}`} title="Video call" disabled={startingCall !== null || !peer} onClick={() => void callPeer(["audio", "video"])} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted disabled:cursor-not-allowed disabled:opacity-35">{startingCall === "video" ? <Loader2 size={18} className="animate-spin" /> : <Video size={18} />}</button>
          </>}
          <button aria-label="Refresh messages" onClick={() => void loadHistory()} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted"><RefreshCw size={18} /></button>
        </div>
      } />
      {!isGroup && peer && (
        <div className="shrink-0 border-b border-border bg-card px-3 py-2 md:px-6">
          <div className="mx-auto flex max-w-2xl items-center justify-between gap-3">
            <button
              type="button"
              onClick={() => setDetailsOpen(true)}
              className="flex min-w-0 items-center gap-2 rounded-full border border-border bg-input-background px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted"
              title={peer.ip || "Device details"}
            >
              <Info size={14} className="shrink-0" />
              <span className="truncate">Device info</span>
            </button>
            <button
              type="button"
              onClick={openContactDialog}
              disabled={peerSavedAsContact || savingContact}
              className="flex h-8 shrink-0 items-center gap-1.5 rounded-full border border-border px-3 text-xs font-medium hover:bg-muted disabled:cursor-default disabled:opacity-45"
            >
              {savingContact ? <Loader2 size={14} className="animate-spin" /> : <UserPlus size={14} />}
              {peerSavedAsContact ? "Saved" : "Save contact"}
            </button>
          </div>
        </div>
      )}
      <div className="shrink-0 border-b border-border bg-card px-3 py-2 md:px-6">
        <div className="mx-auto flex max-w-2xl items-center gap-2 rounded-full border border-border bg-input-background px-3">
          <Search size={16} className="shrink-0 text-muted-foreground" />
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search messages" className="h-10 flex-1 bg-transparent text-sm outline-none" />
          {search && <button type="button" aria-label="Clear search" onClick={() => setSearch("")} className="grid h-5 w-5 shrink-0 place-items-center rounded-full hover:bg-muted"><X size={14} className="text-muted-foreground" /></button>}
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
        {typingSenderDid && (
          <div className="mx-auto mb-2 max-w-2xl text-xs italic text-muted-foreground">
            {isGroup ? contactNameForDid(typingSenderDid) : peerComposerName} is typing…
          </div>
        )}
        {uploadProgress !== null && <div className="mx-auto mb-2 max-w-2xl text-xs text-muted-foreground">Uploading file… {uploadProgress}%</div>}
        <div className="mx-auto flex max-w-2xl items-center gap-2">
          <AttachmentMenu onPick={(file) => void attach(file)} disabled={sending} />
          <input value={message} onChange={(event) => handleComposerChange(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void send(message); }} disabled={sending} placeholder={isGroup ? "Secure Circle message…" : `Message ${peerComposerName}…`} className="h-11 flex-1 rounded-full border border-border bg-input-background px-4 text-sm outline-none" />
          <button type="button" aria-label="Send message" onClick={() => void send(message)} disabled={sending || !message.trim()} className="grid h-11 w-11 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground disabled:opacity-40">{sending ? <Loader2 size={18} className="animate-spin" /> : <Send size={18} />}</button>
        </div>
      </div>
      <PeerDetailsDialog
        open={detailsOpen}
        onOpenChange={setDetailsOpen}
        peer={peer as Peer | null}
        title={String(title || "Device")}
        saved={peerSavedAsContact}
        saving={savingContact}
        onAddContact={openContactDialog}
      />
      <ContactSaveDialog
        open={contactDialogOpen}
        onOpenChange={setContactDialogOpen}
        peer={peer as Peer | null}
        defaultName={String(peerContactName || member?.name || peer?.displayName || peer?.peerId || "")}
        saving={savingContact}
        onSave={(fields) => void savePeerContact(fields)}
      />
    </div>
  );
}
