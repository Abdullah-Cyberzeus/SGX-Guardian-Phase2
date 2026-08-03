import api from "./api";

export interface VaultRecord {
  vault_id?: string; id?: string; filename?: string; name?: string; mime?: string;
  size_plain?: number; size?: number; namespace?: string; folder_id?: string | null;
  circle_id?: string | null; starred?: boolean; created_at?: string; updated_at?: string;
  sender_did?: string; path?: string; [key: string]: unknown;
}
export interface FolderNode {
  folder_id?: string; id?: string; name: string; namespace?: string;
  parent_id?: string | null; circle_id?: string; created_at?: string;
}
export interface VaultFolderListResponse { count: number; folders: FolderNode[] }
export interface VaultTreeResponse {
  namespace: string; folder_id: string;
  breadcrumbs: Array<{ folder_id: string; name: string }>;
  folders: FolderNode[]; files: VaultRecord[];
  file_count: number; folder_count: number;
}
export interface VaultQuotaResponse {
  used_bytes: number; quota_bytes: number; remaining_bytes: number; usage_percent: number;
}
export interface VaultOverviewResponse {
  file_count: number; folder_count: number; used_bytes: number; capacity_bytes: number;
  namespaces: Array<{ namespace: string; file_count: number; folder_count: number; used_bytes: number }>;
  timestamp: string;
}
export interface VaultSearchResponse {
  query: string; count: number;
  results: Array<{ namespace: string; breadcrumbs: Array<{ folder_id: string; name: string }>; file: VaultRecord }>;
}

const filePath = (id: string) => `/vault/files/${encodeURIComponent(id)}`;
export const vaultService = {
  list: (filters: Record<string, string | boolean> = {}) =>
    api.get<{ count: number; files: VaultRecord[] }>("/vault/files", filters),
  detail: (id: string) => api.get<VaultRecord>(filePath(id)),
  update: (id: string, data: { filename?: string; folder_id?: string }) =>
    api.patch<VaultRecord>(filePath(id), data),
  delete: (id: string) => api.delete<{ success: boolean; message: string }>(filePath(id)),
  upload: (
    file: File,
    options: {
      ns?: string; folder_id?: string; signal?: AbortSignal;
      onProgress?: (loaded: number, total: number) => void;
    } = {},
  ) => {
    const form = new FormData();
    form.append("file", file, file.name);
    return api.upload<{ record: VaultRecord; download_path: string }>("/vault/upload", form, {
      params: { ...(options.ns ? { ns: options.ns } : {}), ...(options.folder_id ? { folder_id: options.folder_id } : {}) },
      signal: options.signal,
      onProgress: options.onProgress,
    });
  },
  createFolder: (data: { namespace?: string; parent_id?: string; name: string }) =>
    api.post<FolderNode>("/vault/folders", data),
  listFolders: (filters: { namespace?: string; circle_id?: string; parent_id?: string } = {}) =>
    api.get<VaultFolderListResponse>("/vault/folders", filters),
  updateFolder: (
    id: string,
    data: { namespace?: string; name?: string; parent_id?: string },
  ) => api.patch<FolderNode>(`/vault/folders/${encodeURIComponent(id)}`, data),
  deleteFolder: (
    id: string,
    options: { ns?: string; recursive?: boolean } = {},
  ) => api.request<{ success: boolean; message: string }>(
    `/vault/folders/${encodeURIComponent(id)}`,
    { method: "DELETE", params: options },
  ),
  quota: (filters: { ns?: string; circle_id?: string } = {}) =>
    api.get<VaultQuotaResponse>("/vault/quota", filters),
  overview: () => api.get<VaultOverviewResponse>("/vault/overview"),
  tree: (filters: { ns?: string; folder?: string } = {}) =>
    api.get<VaultTreeResponse>("/vault/tree", filters),
  search: (q: string, limit = 50) => api.get<VaultSearchResponse>("/vault/search", { q, limit }),
  download: async (id: string) => (await api.raw(`${filePath(id)}/download`)).blob(),
  downloadPath: async (path: string) => {
    if (!path.startsWith("/api/")) {
      throw new Error("The server returned an invalid download path");
    }
    return (await api.raw(path)).blob();
  },
  preview: (id: string) => api.raw(`${filePath(id)}/preview`),
  star: (id: string, starred?: boolean) =>
    api.post<VaultRecord>(`${filePath(id)}/star`, starred === undefined ? undefined : { starred }),
};
