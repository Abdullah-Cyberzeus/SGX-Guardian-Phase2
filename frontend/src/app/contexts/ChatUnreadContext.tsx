import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { peerService } from "../services/peerService";
import chatService, { openChatSocket, parseChatPayload, type ChatMessageRecord, type ChatSocketEvent } from "../services/chatService";
import { circleService } from "../services/circleService";
import { didService } from "../services/didService";
import { useAuth } from "./AuthContext";
import { useNotifications } from "./NotificationContext";
import { isMemberRole } from "../utils/authorization";
import { fetchCommunicationPeers } from "../hooks/useApiData";
import { isWithinDnd, loadLocalNotificationPrefs, playNotificationSound, vibrateForNotification } from "../lib/notificationLocalPrefs";

export interface ChatPreview {
  text: string;
  timestamp: number;
}

export interface CircleChatSummary {
  circleId: string;
  name: string;
  memberCount: number;
}

export interface MessageToast {
  toastId: string;
  messageId: string;
  mode: "direct" | "group";
  conversationId: string;
  title: string;
  sender: string;
  text: string;
}

interface ChatUnreadContextValue {
  /** peer DID -> count of messages from that peer not yet marked read */
  counts: Record<string, number>;
  /** peer DID -> latest message in that conversation, kept live off the same poll/socket */
  previews: Record<string, ChatPreview>;
  /** Circle ID -> count of unread group messages for the current local DID. */
  circleCounts: Record<string, number>;
  /** Circle ID -> latest group message. */
  circlePreviews: Record<string, ChatPreview>;
  /** Circles with at least one stored group message. */
  circleChats: CircleChatSummary[];
  /** sum of all per-peer unread counts, for the sidebar badge */
  total: number;
  /** immediately clears the badge for a conversation being actively viewed */
  clearPeerUnread(peerDid: string): void;
  clearCircleUnread(circleId: string): void;
  messageToasts: MessageToast[];
  dismissMessageToast(toastId: string): void;
  refresh(): void;
}

const offlineValue: ChatUnreadContextValue = {
  counts: {},
  previews: {},
  circleCounts: {},
  circlePreviews: {},
  circleChats: [],
  total: 0,
  clearPeerUnread: () => {},
  clearCircleUnread: () => {},
  messageToasts: [],
  dismissMessageToast: () => {},
  refresh: () => {},
};

// The fallback is intentional: during a disconnected startup Root omits this
// live polling/socket provider, while member screens still need to render their
// encrypted cached content and sidebar.
const Context = createContext<ChatUnreadContextValue>(offlineValue);

export function ChatUnreadProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const { prefs } = useNotifications();
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [previews, setPreviews] = useState<Record<string, ChatPreview>>({});
  const [circleCounts, setCircleCounts] = useState<Record<string, number>>({});
  const [circlePreviews, setCirclePreviews] = useState<Record<string, ChatPreview>>({});
  const [circleChats, setCircleChats] = useState<CircleChatSummary[]>([]);
  const [messageToasts, setMessageToasts] = useState<MessageToast[]>([]);
  const [localDid, setLocalDid] = useState(session?.browserMemberDid ?? "");
  const ownDid = session?.browserMemberDid || session?.guardianDid;
  const requestId = useRef(0);
  const localDidRef = useRef(localDid);
  const circleNamesRef = useRef<Record<string, string>>({});
  const peerNamesRef = useRef<Record<string, string>>({});
  const shownToastIdsRef = useRef<Set<string>>(new Set());

  useEffect(() => { localDidRef.current = localDid; }, [localDid]);

  useEffect(() => {
    if (isMemberRole(session?.user.role) && session?.browserMemberDid) {
      setLocalDid(session.browserMemberDid);
      return;
    }
    const identity = isMemberRole(session?.user.role) ? peerService.getLocalIdentity() : didService.getStatus();
    void identity.then((status) => setLocalDid(status.did)).catch(() => setLocalDid(""));
  }, [session?.browserMemberDid, session?.user.role]);

  const refresh = useCallback(() => {
    const thisRequest = ++requestId.current;
    // Guardian sessions must include browser Circle members here too — they
    // never appear in the Nebula trust registry (peerService.getAll alone),
    // so a member->guardian message would otherwise never move the unread
    // badge/preview until the conversation was opened directly.
    void Promise.all([
      fetchCommunicationPeers(isMemberRole(session?.user.role), session?.guardianDid),
      circleService.getAll().catch(() => []),
    ]).then(async ([peers, circles]) => {
      const verified = peers.filter((peer) => peer.status === "verified" && peer.did && peer.did !== localDid);
      peerNamesRef.current = Object.fromEntries([
        ...circles.flatMap((circle) => (circle.members ?? []).filter((member) => member.did).map((member) => [member.did!, member.name || member.did!] as const)),
        ...verified.map((peer) => [peer.did!, peer.peerId || peer.did!] as const),
      ]);
      circleNamesRef.current = Object.fromEntries(circles.map((circle) => [circle.id, circle.name]));
      const peerEntries = await Promise.all(verified.map(async (peer) => {
        try {
          const { messages } = await chatService.directHistory(peer.did!);
          // Never infer direction from the selected row. In shared Guardian
          // storage a replayed browser-member message can be visible from
          // multiple identities; only messages not authored by this session
          // may become unread for it.
          const unread = localDid
            ? messages.filter((record) => record.sender_did !== localDid
              && record.status !== "read"
              && !record.read_by.includes(localDid)).length
            : 0;
          // seq_no is the authoritative recency order: timestamps only have
          // second resolution, so a burst of messages (e.g. an offline queue
          // flushing several at once) can tie on timestamp and fall back to
          // array order, silently picking a stale "latest" message.
          const latest = [...messages].sort((a, b) => (b.seq_no - a.seq_no) || (b.timestamp - a.timestamp))[0];
          let preview: ChatPreview | undefined;
          if (latest) {
            const payload = parseChatPayload(latest);
            preview = { text: payload.attachment_id ? `File: ${payload.content || "Attachment"}` : (payload.content || "Message"), timestamp: latest.timestamp };
          }
          return [peer.did!, unread, preview] as const;
        } catch {
          return [peer.did!, 0, undefined] as const;
        }
      }));
      const groupEntries = await Promise.all(circles.map(async (circle) => {
        try {
          const { messages } = await chatService.groupHistory(circle.id);
          // An empty Circle is still a valid chat target — a newly added
          // member needs to see it and be able to send the first message,
          // not wait for someone else to message first.
          if (!messages.length) return [circle.id, circle.name, circle.members?.length ?? circle.memberCount ?? 0, 0, undefined, true] as const;
          const unread = localDid
            ? messages.filter((record) => record.sender_did !== localDid && !record.read_by.includes(localDid)).length
            : 0;
          // seq_no is the authoritative recency order: timestamps only have
          // second resolution, so a burst of messages (e.g. an offline queue
          // flushing several at once) can tie on timestamp and fall back to
          // array order, silently picking a stale "latest" message.
          const latest = [...messages].sort((a, b) => (b.seq_no - a.seq_no) || (b.timestamp - a.timestamp))[0];
          const payload = parseChatPayload(latest);
          const preview: ChatPreview = {
            text: payload.attachment_id ? `File: ${payload.content || "Attachment"}` : (payload.content || "Message"),
            timestamp: latest.timestamp,
          };
          return [circle.id, circle.name, circle.members?.length ?? circle.memberCount ?? 0, unread, preview, true] as const;
        } catch {
          return [circle.id, circle.name, circle.members?.length ?? circle.memberCount ?? 0, 0, undefined, false] as const;
        }
      }));
      if (requestId.current === thisRequest) {
        setCounts(Object.fromEntries(peerEntries.map(([did, unread]) => [did, unread])));
        setPreviews(Object.fromEntries(peerEntries.filter((entry): entry is [string, number, ChatPreview] => Boolean(entry[2])).map(([did, , preview]) => [did, preview])));
        setCircleCounts(Object.fromEntries(groupEntries.map(([id, , , unread]) => [id, unread])));
        setCirclePreviews(Object.fromEntries(groupEntries.filter((entry) => Boolean(entry[4])).map(([id, , , , preview]) => [id, preview!] as const)));
        setCircleChats(groupEntries.filter((entry) => entry[5]).map(([circleId, name, memberCount]) => ({ circleId, name, memberCount })));
      }
    }).catch(() => {});
  }, [localDid, session?.guardianDid, session?.user.role]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    const refreshAfterReplay = () => refresh();
    window.addEventListener("sgx:chat-replayed", refreshAfterReplay);
    return () => window.removeEventListener("sgx:chat-replayed", refreshAfterReplay);
  }, [refresh]);

  useEffect(() => {
    let refreshTimer: number | undefined;
    const close = openChatSocket((event) => {
      if (event) announceMessage(event);
      if (refreshTimer) window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(refresh, 150);
    });
    return () => { if (refreshTimer) window.clearTimeout(refreshTimer); close(); };
  // Reconnect when identity/history scope or the message-popup preference changes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh, prefs?.circles.new_message]);

  const clearPeerUnread = useCallback((peerDid: string) => {
    setCounts((current) => current[peerDid] > 0 ? { ...current, [peerDid]: 0 } : current);
  }, []);

  const clearCircleUnread = useCallback((circleId: string) => {
    setCircleCounts((current) => current[circleId] > 0 ? { ...current, [circleId]: 0 } : current);
  }, []);

  const dismissMessageToast = useCallback((toastId: string) => {
    setMessageToasts((current) => current.filter((toast) => toast.toastId !== toastId));
  }, []);

  const announceMessage = (event: ChatSocketEvent) => {
    const eventType = String(event.event_type ?? "").replace(/_/g, "").toLowerCase();
    if (eventType !== "newmessage" || !event.message_id || !event.sender_did || !localDidRef.current) return;
    if (event.sender_did === localDidRef.current || prefs?.circles.new_message === false || shownToastIdsRef.current.has(event.message_id)) return;
    const groupId = event.group_id || undefined;
    const conversationId = groupId || event.sender_did;
    const activePath = decodeURIComponent(window.location.pathname);
    const active = groupId
      ? activePath === `/network/${groupId}/chat`
      : activePath === `/chats/${event.sender_did}` || activePath.endsWith(`/members/${event.sender_did}/chat`);
    if (active && document.visibilityState === "visible" && document.hasFocus()) return;
    shownToastIdsRef.current.add(event.message_id);
    const payload = parseChatPayload(event as ChatMessageRecord);
    const text = payload.attachment_id ? `File: ${payload.content || "Attachment"}` : (payload.content || "New message");
    const title = groupId ? (circleNamesRef.current[groupId] || "Circle chat") : (peerNamesRef.current[event.sender_did] || "New message");
    const sender = groupId ? (peerNamesRef.current[event.sender_did] || event.sender_did) : title;
    // This is the device-local delivery toggle (Settings > Notifications),
    // separate from the Guardian-enforced `prefs.circles.new_message`
    // category check above — both must allow it through.
    void loadLocalNotificationPrefs(ownDid).then((local) => {
      if (!local.masterEnabled) return;
      setMessageToasts((current) => [{
        toastId: `${event.message_id}-${Date.now()}`,
        messageId: event.message_id!,
        mode: groupId ? "group" as const : "direct" as const,
        conversationId,
        title,
        sender,
        text,
      }, ...current].slice(0, 6));
      if (!isWithinDnd(local)) {
        if (local.sound) playNotificationSound();
        if (local.vibration) vibrateForNotification();
      }
    });
  };

  const total = useMemo(() => [...Object.values(counts), ...Object.values(circleCounts)].reduce((sum, count) => sum + count, 0), [counts, circleCounts]);
  const value = useMemo(
    () => ({ counts, previews, circleCounts, circlePreviews, circleChats, total, clearPeerUnread, clearCircleUnread, messageToasts, dismissMessageToast, refresh }),
    [counts, previews, circleCounts, circlePreviews, circleChats, total, clearPeerUnread, clearCircleUnread, messageToasts, dismissMessageToast, refresh],
  );
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useChatUnread(): ChatUnreadContextValue {
  return useContext(Context);
}
