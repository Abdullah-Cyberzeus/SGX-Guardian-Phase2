export const PWA_DB_NAME = "sgx-guardian-pwa";
export const PWA_DB_VERSION = 1;

export const stores = {
  membership: "membership",
  messages: "messages",
  contacts: "contacts",
  files: "files",
  calls: "calls",
  pending: "pending",
  settings: "settings",
  syncState: "sync_state",
} as const;

export type StoreName = typeof stores[keyof typeof stores];
export interface EncryptedRecord { version: 1; iv: string; ciphertext: string; }
export interface MembershipDetails { guardianDid: string; guardianFingerprint?: string; circleIds: string[]; actorId: string; role: string; browserRegistrationId?: string; sessionExpiresAt?: number; registrationExpiresAt?: number; }
export interface MembershipRecord { id: string; updatedAt: number; payload: EncryptedRecord; }
export interface MessageRecord { id: string; conversationId: string; timestamp: number; sequence: number; payload: EncryptedRecord; status: string; }
export interface ContactRecord { did: string; displayName: string; online: boolean; lastSeen?: string; updatedAt: number; }
export interface FileRecord { id: string; conversationId?: string; name: string; mime: string; size: number; updatedAt: number; encryptedBlob?: EncryptedRecord; }
export interface CallRecord { id: string; kind: "direct" | "group"; direction: string; outcome: string; media: string[]; participantIds: string[]; title: string; startedAt: number; endedAt: string; durationSeconds: number; circleId?: string; }
export interface PendingRecord { id: string; kind: string; createdAt: number; attempts: number; state: "queued" | "sending" | "failed"; payload: EncryptedRecord; }
export interface SettingRecord { key: string; value: unknown; updatedAt: number; }
export interface SyncStateRecord { key: string; cursor?: string; sequence?: number; lastSuccessfulSync?: number; value?: unknown; }

export interface StoreRecordMap {
  membership: MembershipRecord;
  messages: MessageRecord;
  contacts: ContactRecord;
  files: FileRecord;
  calls: CallRecord;
  pending: PendingRecord;
  settings: SettingRecord;
  sync_state: SyncStateRecord;
}
