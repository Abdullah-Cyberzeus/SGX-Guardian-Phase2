import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { peerService } from "../services/peerService";
import chatService, { openChatSocket, parseChatPayload } from "../services/chatService";
import { useAuth } from "./AuthContext";
import { isMemberRole } from "../utils/authorization";

export interface ChatPreview {
  text: string;
  timestamp: number;
}

interface ChatUnreadContextValue {
  /** peer DID -> count of messages from that peer not yet marked read */
  counts: Record<string, number>;
  /** peer DID -> latest message in that conversation, kept live off the same poll/socket */
  previews: Record<string, ChatPreview>;
  /** sum of all per-peer unread counts, for the sidebar badge */
  total: number;
  /** immediately clears the badge for a conversation being actively viewed */
  clearPeerUnread(peerDid: string): void;
  refresh(): void;
}

const Context = createContext<ChatUnreadContextValue | null>(null);

export function ChatUnreadProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [previews, setPreviews] = useState<Record<string, ChatPreview>>({});
  const requestId = useRef(0);

  const refresh = useCallback(() => {
    const thisRequest = ++requestId.current;
    // The member-safe contacts endpoint exposes only communication identities;
    // it intentionally omits network addresses and policy/topology metadata.
    const loadPeers = isMemberRole(session?.user.role)
      ? peerService.getContacts
      : peerService.getAll;
    void loadPeers().then(async (peers) => {
      const verified = peers.filter((peer) => peer.status === "verified" && peer.did);
      const entries = await Promise.all(verified.map(async (peer) => {
        try {
          const { messages } = await chatService.directHistory(peer.did!);
          // This history is for exactly one remote contact. Messages carrying
          // that DID are incoming, so no administrative local-DID lookup is
          // needed to calculate unread state.
          const unread = messages.filter((record) => record.sender_did === peer.did && record.status !== "read").length;
          const latest = [...messages].sort((a, b) => b.timestamp - a.timestamp)[0];
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
      if (requestId.current === thisRequest) {
        setCounts(Object.fromEntries(entries.map(([did, unread]) => [did, unread])));
        setPreviews(Object.fromEntries(entries.filter((entry): entry is [string, number, ChatPreview] => Boolean(entry[2])).map(([did, , preview]) => [did, preview])));
      }
    }).catch(() => {});
  }, [session?.user.role]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    let refreshTimer: number | undefined;
    const close = openChatSocket(() => {
      if (refreshTimer) window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(refresh, 150);
    });
    return () => { if (refreshTimer) window.clearTimeout(refreshTimer); close(); };
  }, [refresh]);

  const clearPeerUnread = useCallback((peerDid: string) => {
    setCounts((current) => current[peerDid] > 0 ? { ...current, [peerDid]: 0 } : current);
  }, []);

  const total = useMemo(() => Object.values(counts).reduce((sum, count) => sum + count, 0), [counts]);
  const value = useMemo(
    () => ({ counts, previews, total, clearPeerUnread, refresh }),
    [counts, previews, total, clearPeerUnread, refresh],
  );
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useChatUnread(): ChatUnreadContextValue {
  const value = useContext(Context);
  if (!value) throw new Error("useChatUnread must be inside ChatUnreadProvider");
  return value;
}
