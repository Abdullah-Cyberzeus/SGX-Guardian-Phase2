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

export interface SendChatResponse {
  message_id: string;
  signature_base64: string;
  status: string;
}

export const chatService = {
  history: (peerDid: string) =>
    api.get<{ messages: ChatMessageRecord[] }>("/chat/history", { peer_did: peerDid }),
  sendDirect: (recipientDid: string, content: string) =>
    api.post<SendChatResponse>("/chat/send", {
      recipient_did: recipientDid,
      content,
      attachment_id: null,
      is_group: false,
    }),
};

export default chatService;
