import api from "./api";

export type BackupComponent = "policy" | "config" | "credentials" | "crl";

export interface BackupRecord {
  id: string;
  created_at: string;
  source_node_id?: string;
  source_did?: string;
  portable?: boolean;
  components?: BackupComponent[];
  bundle_path?: string;
  size_bytes?: number;
}

export interface BackupHistoryResponse {
  records: BackupRecord[];
}

export interface CreateBackupRequest {
  passphrase: string;
  portable?: boolean;
}

export interface DeleteBackupResponse {
  status: string;
  id: string;
}

export interface BackupValidateRequest {
  id: string;
  passphrase: string;
}

export interface BackupValidateComponent {
  component: string;
  schema_version?: number;
  paths?: string[];
}

export interface BackupValidateResponse {
  status: string;
  backup_id: string;
  source_node_id?: string;
  source_did?: string;
  target_did?: string;
  same_device_identity?: boolean;
  portable?: boolean;
  components: BackupValidateComponent[];
  warnings: string[];
}

export interface RestoreValidateRequest {
  id: string;
  passphrase: string;
  components?: BackupComponent[];
  allow_policy_rollback?: boolean;
}

export interface RestorePlanStep {
  component: string;
  action: string;
  reason?: string;
  paths?: string[];
}

export interface RestoreValidateResponse {
  status: string;
  backup: BackupValidateResponse;
  mode: "same_device" | "cross_device" | string;
  plan: RestorePlanStep[];
  destructive_apply_enabled: boolean;
  warnings: string[];
}

export interface RestoreApplyRequest {
  id: string;
  passphrase: string;
  confirm: true;
  components?: BackupComponent[];
  allow_policy_rollback?: boolean;
}

export interface RestoreApplyResponse {
  status: "committed" | "committed_policy_skipped" | string;
  message: string;
  restart_required: boolean;
}

export interface RestoreJournal {
  restore_id: string;
  bundle_id: string;
  node_id?: string;
  phase: string;
  component_index: number | null;
  snapshot_path?: string | null;
  updated_at: string;
  message?: string;
}

export interface RestoreStatusResponse {
  status: "idle" | "journal_present" | string;
  journal_path?: string;
  journal: RestoreJournal | null;
}

export interface RestoreUndoResponse {
  status: string;
  message: string;
  restart_required: boolean;
}

export const ALL_BACKUP_COMPONENTS: BackupComponent[] = ["policy", "config", "credentials", "crl"];

export const backupService = {
  // POST /api/v1/backup/create
  create: (data: CreateBackupRequest) => api.post<BackupRecord>("/backup/create", data),

  // GET /api/v1/backup/history
  history: () => api.get<BackupHistoryResponse>("/backup/history"),

  // GET /api/v1/backup/download/{id}
  download: async (id: string) => (await api.raw(`/backup/download/${encodeURIComponent(id)}`)).blob(),

  // DELETE /api/v1/backup/{id}
  remove: (id: string) => api.delete<DeleteBackupResponse>(`/backup/${encodeURIComponent(id)}`),

  // POST /api/v1/backup/validate
  validate: (data: BackupValidateRequest) => api.post<BackupValidateResponse>("/backup/validate", data),

  // POST /api/v1/backup/restore (legacy; always 409s, kept for API completeness)
  legacyRestore: (data: BackupValidateRequest) => api.post<void>("/backup/restore", data),

  // POST /api/v1/restore/validate
  restoreValidate: (data: RestoreValidateRequest) => api.post<RestoreValidateResponse>("/restore/validate", data),

  // GET /api/v1/restore/status
  restoreStatus: () => api.get<RestoreStatusResponse>("/restore/status"),

  // POST /api/v1/restore/apply
  restoreApply: (data: RestoreApplyRequest) => api.post<RestoreApplyResponse>("/restore/apply", data),

  // POST /api/v1/restore/undo
  restoreUndo: () => api.post<RestoreUndoResponse>("/restore/undo", { confirm: true }),
};

export default backupService;
