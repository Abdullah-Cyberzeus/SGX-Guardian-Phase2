import api from "./api";

export interface ChatMessageRecord {
  message_id: string;
  sender_did: string;
  recipient_did: string;
  group_id?: string;
  timestamp: number;
  seq_no: number;
  encrypted_payload: string;
  status: "pending" | "delivered" | "read" | "failed" | string;
  read_by: string[];
}

export interface ChatPayload {
  content: string | null;
  attachment_id: string | null;
}

export interface UploadChatAttachmentResponse {
  attachment_id: string;
  status: string;
}

export interface SendChatResponse {
  message_id: string;
  signature_base64: string;
  status: string;
}

export const chatService = {
  // Backward-compatible alias for callers that have not moved to the named mode yet.
  history: (peerDid: string) =>
    api.get<{ messages: ChatMessageRecord[] }>("/chat/history", { peer_did: peerDid }),
  directHistory: (peerDid: string) =>
    api.get<{ messages: ChatMessageRecord[] }>("/chat/history", { peer_did: peerDid }),
  groupHistory: (groupId: string) =>
    api.get<{ messages: ChatMessageRecord[] }>("/chat/history", { group_id: groupId }),
  sendDirect: (recipientDid: string, content: string | null, attachmentId: string | null = null) =>
    api.post<SendChatResponse>("/chat/send", {
      recipient_did: recipientDid,
      content,
      attachment_id: attachmentId,
      is_group: false,
    }),
  sendGroup: (groupId: string, content: string | null, attachmentId: string | null = null) =>
    api.post<SendChatResponse>("/chat/send", {
      recipient_did: groupId,
      content,
      attachment_id: attachmentId,
      is_group: true,
    }),
  upload: (file: File, onProgress?: (loaded: number, total: number) => void) => {
    const form = new FormData();
    form.append("file", file);
    return api.upload<UploadChatAttachmentResponse>("/chat/upload", form, { onProgress });
  },
  downloadUrl: (attachmentId: string) => api.publicUrl(`/chat/download/${encodeURIComponent(attachmentId)}`),
  markRead: (messageId: string, originalSenderDid: string, groupId?: string) =>
    api.post<{ status: string }>("/chat/read", {
      message_id: messageId,
      original_sender_did: originalSenderDid,
      ...(groupId ? { group_id: groupId } : {}),
    }),
  sync: () => api.post<{ status: string; peers_synced: number }>("/chat/sync"),
};

export function parseChatPayload(record: ChatMessageRecord): ChatPayload {
  try {
    const value = JSON.parse(record.encrypted_payload) as Partial<ChatPayload>;
    return {
      content: typeof value.content === "string" ? value.content : null,
      attachment_id: typeof value.attachment_id === "string" ? value.attachment_id : null,
    };
  } catch {
    return { content: record.encrypted_payload || null, attachment_id: null };
  }
}

export function openChatSocket(onChange: () => void, onState?: (connected: boolean) => void): () => void {
  let socket: WebSocket | null = null;
  let retryTimer: number | undefined;
  let heartbeatTimer: number | undefined;
  let stopped = false;
  let retryCount = 0;

  const connect = () => {
    if (stopped) return;
    const token = api.getToken();
    if (!token) {
      onState?.(false);
      return;
    }
    const endpoint = new URL(api.publicUrl("/chat/ws"));
    endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
    endpoint.searchParams.set("access_token", token);
    socket = new WebSocket(endpoint);
    socket.onopen = () => {
      retryCount = 0;
      onState?.(true);
      heartbeatTimer = window.setInterval(() => {
        if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "heartbeat" }));
      }, 20_000);
    };
    socket.onmessage = (event) => {
      try {
        if (JSON.parse(String(event.data))?.type === "heartbeat_ack") return;
      } catch {
        // Chat events are still handled by refreshing canonical history.
      }
      onChange();
    };
    socket.onerror = () => socket?.close();
    socket.onclose = () => {
      onState?.(false);
      if (heartbeatTimer) window.clearInterval(heartbeatTimer);
      if (!stopped) {
        const delay = Math.min(10_000, 500 * 2 ** retryCount++);
        retryTimer = window.setTimeout(connect, delay);
      }
    };
  };

  connect();
  return () => {
    stopped = true;
    if (retryTimer) window.clearTimeout(retryTimer);
    if (heartbeatTimer) window.clearInterval(heartbeatTimer);
    socket?.close();
  };
}

export default chatService;
