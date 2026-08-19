import api from "./api";

export interface ChatMessageRecord {
  message_id: string;
  sender_did: string;
  recipient_did: string;
  group_id?: string;
  timestamp: number;
  seq_no: number;
  encrypted_payload: string;
  status: "pending_local" | "accepted_by_guardian" | "delivered_to_remote_guardian" | "pending" | "delivered" | "read" | "failed" | "cancelled" | "failed_permanent" | string;
  read_by: string[];
}

export interface ChatPayload {
  content: string | null;
  attachment_id: string | null;
  attachment_name: string | null;
  attachment_mime: string | null;
  attachment_size: number | null;
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

export interface ChatSocketEvent extends Partial<ChatMessageRecord> {
  event_type?: "NewMessage" | "ReadReceipt" | "MessageStatus" | "Typing" | "new_message" | "read_receipt" | "message_status" | "typing" | string;
  type?: string;
  /** Present on ephemeral typing events. */
  conversation_id?: string;
  is_typing?: boolean;
}

export const chatService = {
  // Backward-compatible alias for callers that have not moved to the named mode yet.
  history: (peerDid: string) =>
    api.get<{ messages: ChatMessageRecord[] }>("/chat/history", { peer_did: peerDid }),
  directHistory: (peerDid: string) =>
    api.get<{ messages: ChatMessageRecord[] }>("/chat/history", { peer_did: peerDid }),
  groupHistory: (groupId: string) =>
    api.get<{ messages: ChatMessageRecord[] }>("/chat/history", { group_id: groupId }),
  sendDirect: (recipientDid: string, content: string | null, attachmentId: string | null = null, messageId?: string) =>
    api.request<SendChatResponse>("/chat/send", {
      method: "POST",
      idempotencyKey: messageId,
      body: JSON.stringify({
      recipient_did: recipientDid,
      content,
      attachment_id: attachmentId,
      is_group: false,
      message_id: messageId,
      }),
    }),
  sendGroup: (groupId: string, content: string | null, attachmentId: string | null = null, messageId?: string) =>
    api.request<SendChatResponse>("/chat/send", {
      method: "POST",
      idempotencyKey: messageId,
      body: JSON.stringify({
      recipient_did: groupId,
      content,
      attachment_id: attachmentId,
      is_group: true,
      message_id: messageId,
      }),
    }),
  upload: (file: File, onProgress?: (loaded: number, total: number) => void) => {
    const form = new FormData();
    form.append("file", file);
    return api.upload<UploadChatAttachmentResponse>("/chat/upload", form, { onProgress });
  },
  downloadUrl: (attachmentId: string) => api.publicUrl(`/chat/download/${encodeURIComponent(attachmentId)}`),
  download: async (attachmentId: string) => {
    const response = await api.raw(`/chat/download/${encodeURIComponent(attachmentId)}`);
    return response.blob();
  },
  downloadToBrowser: async (attachmentId: string, fileName: string) => {
    const blob = await chatService.download(attachmentId);
    const url = URL.createObjectURL(blob);
    try {
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = fileName;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
    } finally {
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
    }
  },
  markRead: (messageId: string, originalSenderDid: string, groupId?: string) =>
    api.post<{ status: string }>("/chat/read", {
      message_id: messageId,
      original_sender_did: originalSenderDid,
      ...(groupId ? { group_id: groupId } : {}),
    }),
  setTyping: (recipientDid: string, isGroup: boolean, isTyping: boolean) =>
    api.post<{ status: string }>("/chat/typing", {
      recipient_did: recipientDid,
      is_group: isGroup,
      is_typing: isTyping,
    }),
  sync: () => api.post<{ status: string; peers_synced: number }>("/chat/sync"),
};

export function parseChatPayload(record: ChatMessageRecord): ChatPayload {
  try {
    const value = JSON.parse(record.encrypted_payload) as Partial<ChatPayload>;
    return {
      content: typeof value.content === "string" ? value.content : null,
      attachment_id: typeof value.attachment_id === "string" ? value.attachment_id : null,
      attachment_name: typeof value.attachment_name === "string" ? value.attachment_name : null,
      attachment_mime: typeof value.attachment_mime === "string" ? value.attachment_mime : null,
      attachment_size: typeof value.attachment_size === "number" ? value.attachment_size : null,
    };
  } catch {
    return {
      content: record.encrypted_payload || null,
      attachment_id: null,
      attachment_name: null,
      attachment_mime: null,
      attachment_size: null,
    };
  }
}

export function openChatSocket(onChange: (event?: ChatSocketEvent) => void, onState?: (connected: boolean) => void): () => void {
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
      window.dispatchEvent(new CustomEvent("sgx:socket-state", { detail: { source: "chat", connected: false } }));
      return;
    }
    const endpoint = new URL(api.publicUrl("/chat/ws"));
    endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
    endpoint.searchParams.set("access_token", token);
    socket = new WebSocket(endpoint);
    socket.onopen = () => {
      retryCount = 0;
      onState?.(true);
      window.dispatchEvent(new CustomEvent("sgx:socket-state", { detail: { source: "chat", connected: true } }));
      heartbeatTimer = window.setInterval(() => {
        if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "heartbeat" }));
      }, 20_000);
    };
    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(String(event.data)) as ChatSocketEvent;
        if (payload.type === "heartbeat_ack") return;
        onChange(payload);
        return;
      } catch {
        // Chat events are still handled by refreshing canonical history.
      }
      onChange();
    };
    socket.onerror = () => socket?.close();
    socket.onclose = () => {
      onState?.(false);
      window.dispatchEvent(new CustomEvent("sgx:socket-state", { detail: { source: "chat", connected: false } }));
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
