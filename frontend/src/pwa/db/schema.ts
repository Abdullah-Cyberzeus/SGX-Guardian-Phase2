export const PWA_DB_NAME = "sgx-guardian-pwa";
export const PWA_DB_VERSION = 3;

export const stores = {
  membership: "membership",
  messages: "messages",
  contacts: "contacts",
  files: "files",
  calls: "calls",
  pending: "pending",
  settings: "settings",
  syncState: "sync_state",
  notifications: "notifications",
} as const;

export type StoreName = typeof stores[keyof typeof stores];
export interface EncryptedRecord { version: 1; iv: string; ciphertext: string; }
export interface MembershipDetails { guardianDid: string; guardianFingerprint?: string; circleIds: string[]; actorId: string; role: string; browserRegistrationId?: string; browserMemberDid?: string; sessionExpiresAt?: number; registrationExpiresAt?: number; }
export interface MembershipRecord { id: string; updatedAt: number; payload: EncryptedRecord; }
export type MessageDeliveryStatus = "pending_local" | "accepted_by_guardian" | "delivered_to_remote_guardian" | "read" | "failed_retryable" | "cancelled" | "failed_permanent" | "pending" | "delivered" | "failed" | string;
export interface MessageRecord { id: string; conversationId: string; timestamp: number; sequence: number; payload: EncryptedRecord; status: MessageDeliveryStatus; updatedAt?: number; searchText?: string; }
export interface ContactRecord { did: string; displayName: string; fullName?: string; deviceName?: string; role?: string; memberType?: string; joinDate?: string; online: boolean; presenceStatus?: string; presenceStale?: boolean; lastSeen?: string; updatedAt: number; }
export interface FileRecord { id: string; conversationId?: string; name: string; mime: string; size: number; updatedAt: number; encryptedBlob?: EncryptedRecord; }
export interface CallRecord { id: string; kind: "direct" | "group"; direction: string; outcome: string; media: string[]; participantIds: string[]; title: string; startedAt: number; endedAt: string; durationSeconds: number; circleId?: string; }
export interface PendingRecord { id: string; kind: string; createdAt: number; attempts: number; state: "queued" | "sending" | "failed" | "failed_permanent" | "cancelled"; payload: EncryptedRecord; lastAttemptAt?: number; lastError?: string; expiresAt?: number; }
export interface SettingRecord { key: string; value: unknown; updatedAt: number; }
export interface SyncStateRecord { key: string; cursor?: string; sequence?: number; lastSuccessfulSync?: number; value?: unknown; }
export interface NotificationRecord { id: string; kind: string; title: string; body: string; severity: string; refId?: string; createdAt: string; read: boolean; updatedAt: number; }

export interface StoreRecordMap {
  membership: MembershipRecord;
  messages: MessageRecord;
  contacts: ContactRecord;
  files: FileRecord;
  calls: CallRecord;
  pending: PendingRecord;
  settings: SettingRecord;
  sync_state: SyncStateRecord;
  notifications: NotificationRecord;
}
