import api from "./api";

export interface TransferSummary {
  transfer_id?: string; id?: string; peer_did?: string; filename?: string; path?: string;
  direction?: "outbound" | "inbound"; sender_did?: string; file_path?: string;
  status?: string; size?: number; bytes_transferred?: number; bytes_sent?: number;
  created_at?: string; updated_at?: string; completed_at?: string | null;
  error?: string | null; last_error?: string | null;
  [key: string]: unknown;
}
export interface InboxFile {
  transfer_id: string; circle_id: string; sender_did: string; filename: string; size: number;
  completed: boolean; path: string | null; updated_at: string; completed_at: string | null;
  file_sha256: string; vault_id: string | null; download_path: string | null; vault_available: boolean;
}
export interface TransferListResponse {
  count: number; transfers: TransferSummary[]; transfers_sent: number;
  transfers_received: number; bytes_transferred: number; last_transfer: TransferSummary | null;
}
export type SendTransferRequest =
  | { peer_did: string; vault_id: string; path?: never }
  | { peer_did: string; path: string; vault_id?: never };

export const xferService = {
  send: (data: SendTransferRequest) =>
    api.post<{ status: string; transfer_id: string; message: string }>("/xfer/send", data),
  list: () => api.get<TransferListResponse>("/xfer/transfers"),
  detail: (id: string) => api.get<TransferSummary>(`/xfer/transfers/${encodeURIComponent(id)}`),
  cancel: (id: string) => api.post<{ status: string; transfer_id: string; message: string }>(
    `/xfer/transfers/${encodeURIComponent(id)}/cancel`,
  ),
  inbox: () => api.get<{ count: number; files: InboxFile[] }>("/xfer/inbox"),
};
