import api, { ApiError } from "../../app/services/api";
import { callHistoryService } from "../../app/services/callHistoryService";
import chatService from "../../app/services/chatService";
import { peerService } from "../../app/services/peerService";
import { vaultService } from "../../app/services/vaultService";
import { notificationsApi } from "../../api/notifications";
import { messageRepository } from "../db/messageRepository";
import { contactRepository } from "../db/contactRepository";
import { fileRepository } from "../db/fileRepository";
import { notificationRepository } from "../db/notificationRepository";
import { syncStateRepository } from "../db/syncStateRepository";
import { registerPendingReplayHandler, replayPendingOperations } from "./pendingReplay";

export type SyncTrigger = "startup" | "health_recovered" | "manual" | "request_success";

export interface SyncResult {
  startedAt: number;
  completedAt: number;
  pendingReplayed: number;
  pendingSkipped: number;
}

let active: Promise<SyncResult> | null = null;

interface PendingChatSend {
  mode: "direct" | "group";
  recipientId: string;
  content: string | null;
  attachmentId: string | null;
}

function parsePendingChatSend(payload: unknown): PendingChatSend {
  const value = payload && typeof payload === "object" ? payload as Partial<PendingChatSend> : {};
  if ((value.mode !== "direct" && value.mode !== "group") || typeof value.recipientId !== "string" || !value.recipientId) {
    throw new Error("Invalid pending chat operation");
  }
  return {
    mode: value.mode,
    recipientId: value.recipientId,
    content: typeof value.content === "string" ? value.content : null,
    attachmentId: typeof value.attachmentId === "string" ? value.attachmentId : null,
  };
}

registerPendingReplayHandler("chat.send", async (record, payload) => {
  const operation = parsePendingChatSend(payload);
  // The pending record's ID is the canonical message ID chosen before the
  // first send attempt. Replaying with the same ID lets the backend
  // recognize an already-accepted message instead of creating a duplicate.
  const response = operation.mode === "group"
    ? await chatService.sendGroup(operation.recipientId, operation.content, operation.attachmentId, record.id)
    : await chatService.sendDirect(operation.recipientId, operation.content, operation.attachmentId, record.id);
  await messageRepository.updateStatus(record.id, response.status || "sent").catch(() => undefined);
});

// Only 401 means the credential itself is no longer valid. 403 is an
// ordinary authorization rejection for a specific operation (e.g. sending to
// a peer that hasn't completed attestation yet, or is currently offline) and
// must not be treated as session revocation — doing so previously showed a
// false "Guardian credentials revoked" banner whenever a single queued
// message target was unreachable.
async function stopIfRevoked(error: unknown) {
  if (error instanceof ApiError && error.status === 401) {
    window.dispatchEvent(new CustomEvent("sgx:sync-revoked"));
    throw error;
  }
}

async function optionalStep(name: string, work: () => Promise<{ cursor?: string; sequence?: number; value?: unknown } | void>) {
  try {
    const result = await work();
    await syncStateRepository.save({
      key: name,
      lastSuccessfulSync: Date.now(),
      cursor: result?.cursor,
      sequence: result?.sequence,
      value: result?.value,
    });
  } catch (error) {
    await stopIfRevoked(error);
    console.debug(`PWA sync step skipped: ${name}`, error);
  }
}

async function pullContacts() {
  const peers = await peerService.getContacts();
  await contactRepository.replaceAll(
    peers
      .filter((peer) => peer.did)
      .map((peer) => ({
        did: peer.did!,
        displayName: peer.peerId,
        online: peer.online,
        lastSeen: peer.lastSeenAgo,
        updatedAt: Date.now(),
      })),
  );
  const newest = peers
    .map((peer) => Date.parse(peer.lastSeen || ""))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => b - a)[0];
  return { cursor: newest ? String(newest) : undefined, value: { count: peers.length } };
}

async function pullFiles() {
  const { files } = await vaultService.list();
  await fileRepository.replaceAll(
    files.flatMap((file) => {
      const id = file.vault_id || file.id;
      if (!id) return [];
      return [{
        id,
        name: file.filename || file.name || "file",
        mime: file.mime || "application/octet-stream",
        size: file.size_plain ?? file.size ?? 0,
        updatedAt: (file.updated_at && Date.parse(file.updated_at)) || Date.now(),
      }];
    }),
  );
  const newest = files
    .map((file) => typeof file.updated_at === "string" ? Date.parse(file.updated_at) : 0)
    .filter((value) => Number.isFinite(value) && value > 0)
    .sort((a, b) => b - a)[0];
  return { cursor: newest ? String(newest) : undefined, value: { count: files.length } };
}

async function pullNotifications() {
  const notifications = await notificationsApi.history();
  await notificationRepository.replaceAll(notifications.map((item) => ({
    id: item.id,
    kind: String(item.kind),
    title: item.title,
    body: item.body,
    severity: String(item.severity),
    refId: item.refId,
    createdAt: item.createdAt,
    read: item.read,
    updatedAt: Date.now(),
  })));
  const newest = notifications
    .map((item) => Date.parse(item.createdAt))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => b - a)[0];
  return { cursor: notifications[0]?.id, sequence: newest, value: { count: notifications.length } };
}

async function run(trigger: SyncTrigger): Promise<SyncResult> {
  const startedAt = Date.now();
  window.dispatchEvent(new CustomEvent("sgx:sync-state", { detail: { running: true, trigger } }));

  try {
    try {
      await api.request("/auth/session", { method: "GET", suppressUnauthorizedEvent: true });
    } catch (error) {
      await stopIfRevoked(error);
      throw error;
    }
    let pending;
    try {
      pending = await replayPendingOperations();
    } catch (error) {
      await stopIfRevoked(error);
      throw error;
    }

    await optionalStep("chat.sync", async () => {
      const result = await chatService.sync();
      return { value: result };
    });
    await optionalStep("contacts", pullContacts);
    await optionalStep("files", pullFiles);
    // No server-persisted call history endpoint exists yet (Phase 8 backend
    // work); this reflects the local cache rather than pulling from Guardian.
    await optionalStep("calls", async () => {
      const calls = callHistoryService.list();
      const newest = calls
        .map((call) => Date.parse(call.endedAt || call.startedAt))
        .filter((value) => Number.isFinite(value))
        .sort((a, b) => b - a)[0];
      return { cursor: newest ? String(newest) : undefined, value: { count: calls.length } };
    });
    await optionalStep("notifications", pullNotifications);

    const completedAt = Date.now();
    await syncStateRepository.save({
      key: "global",
      lastSuccessfulSync: completedAt,
      value: { trigger, pending },
    });

    return {
      startedAt,
      completedAt,
      pendingReplayed: pending.replayed,
      pendingSkipped: pending.skipped,
    };
  } finally {
    window.dispatchEvent(new CustomEvent("sgx:sync-state", { detail: { running: false, trigger } }));
  }
}

export const syncCoordinator = {
  run(trigger: SyncTrigger = "manual") {
    if (!active) {
      active = run(trigger).finally(() => {
        active = null;
      });
    }
    return active;
  },
  isRunning() {
    return active !== null;
  },
};
