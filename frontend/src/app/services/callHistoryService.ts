import type { CallSession, GroupSession, MediaType } from "../../features/calls/call.types";
import { callRepository } from "../../pwa/db/callRepository";
import { callsApi } from "../../api/calls";

export type CallDirection = "incoming" | "outgoing";
export type CallOutcome = "completed" | "missed" | "declined" | "cancelled" | "failed";

export interface CallHistoryRecord {
  id: string;
  kind: "direct" | "group";
  direction: CallDirection;
  outcome: CallOutcome;
  media: MediaType[];
  participantIds: string[];
  title: string;
  startedAt: string;
  endedAt: string;
  durationSeconds: number;
  circleId?: string;
}

const EVENT_NAME = "sgx:call-history-changed";
const DEPLOYMENT_KEY_STORAGE = "sgx-call-history-deployment-key";
const DEPLOYMENT_RESET_AT_STORAGE = "sgx-call-history-reset-at";
let records: CallHistoryRecord[] = [];
let revision = 0;

function storage() {
  return typeof window !== "undefined" ? window.localStorage : null;
}

function currentResetAt() {
  const value = storage()?.getItem(DEPLOYMENT_RESET_AT_STORAGE);
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function normalizeDeploymentKey(value?: string | null) {
  const key = value?.trim();
  return key && key !== "N/A" && key !== "Unknown" ? key : null;
}

function isVisible(record: CallHistoryRecord) {
  const cutoff = currentResetAt();
  return !cutoff || new Date(record.endedAt).getTime() >= cutoff;
}

function visible(records: CallHistoryRecord[]) {
  return records.filter(isVisible);
}

function read(): CallHistoryRecord[] {
  return [...visible(records)];
}

function write(record: CallHistoryRecord) {
  revision += 1;
  const existing = records.findIndex((item) => item.id === record.id);
  if (existing >= 0) {
    const previous = records[existing];
    const keepExplicitOutcome = ["declined", "failed"].includes(previous.outcome)
      && ["missed", "cancelled"].includes(record.outcome);
    records[existing] = { ...previous, ...record, outcome: keepExplicitOutcome ? previous.outcome : record.outcome };
  }
  else records.push(record);
  records.sort((a, b) => new Date(b.endedAt).getTime() - new Date(a.endedAt).getTime());
  records = records.slice(0, 500);
  void callRepository.save({ ...record, media: record.media, startedAt: new Date(record.startedAt).getTime() });
  window.dispatchEvent(new CustomEvent(EVENT_NAME));
}

async function replaceFromGuardian(nextRecords: CallHistoryRecord[]) {
  revision += 1;
  records = visible([...nextRecords])
    .sort((a, b) => new Date(b.endedAt).getTime() - new Date(a.endedAt).getTime())
    .slice(0, 500);
  await callRepository.replaceAll(records.map((record) => ({
    ...record,
    media: record.media,
    startedAt: new Date(record.startedAt).getTime(),
  })));
  window.dispatchEvent(new CustomEvent(EVENT_NAME));
}

async function resetLocal() {
  await replaceFromGuardian([]);
}

async function resetForDeployment(deploymentKey?: string | null) {
  const normalized = normalizeDeploymentKey(deploymentKey);
  const store = storage();
  const storedKey = store?.getItem(DEPLOYMENT_KEY_STORAGE);

  if (normalized && storedKey !== normalized) {
    store?.setItem(DEPLOYMENT_KEY_STORAGE, normalized);
    store?.setItem(DEPLOYMENT_RESET_AT_STORAGE, String(Date.now()));
  }

  await resetLocal();
}

const initialRevision = revision;
void callRepository.list().then((cached) => {
  if (revision !== initialRevision) return;
  records = visible(cached.map((record) => ({ ...record, media: record.media as MediaType[], startedAt: new Date(record.startedAt).toISOString() })) as CallHistoryRecord[]);
  window.dispatchEvent(new CustomEvent(EVENT_NAME));
}).catch(() => {});

function directOutcome(session: CallSession, localDevice: string, explicit?: CallOutcome): CallOutcome {
  if (explicit) return explicit;
  if (session.started_at || session.duration_seconds > 0) return "completed";
  return session.receiver_device_id === localDevice ? "missed" : "cancelled";
}

export const callHistoryService = {
  eventName: EVENT_NAME,
  list: read,
  resetLocal,
  resetForDeployment,
  async syncFromGuardian() {
    const response = await callsApi.history();
    await replaceFromGuardian(response.calls.map((item) => ({
      id: item.id,
      kind: item.kind === "group" ? "group" : "direct",
      direction: "incoming",
      outcome: ["completed", "missed", "declined", "cancelled", "failed"].includes(item.outcome) ? item.outcome as CallOutcome : "completed",
      media: item.media,
      participantIds: item.participant_ids,
      title: item.kind === "group" ? "Group call" : item.participant_ids.join(" / "),
      startedAt: item.started_at,
      endedAt: item.ended_at,
      durationSeconds: item.duration_seconds,
    })));
    return read();
  },
  recordDirect(session: CallSession, localDevice: string, explicit?: CallOutcome) {
    const remote = session.initiator_device_id === localDevice ? session.receiver_device_id : session.initiator_device_id;
    const endedAt = session.ended_at || new Date().toISOString();
    const startedAt = session.started_at || session.created_at;
    write({
      id: session.session_id,
      kind: "direct",
      direction: session.initiator_device_id === localDevice ? "outgoing" : "incoming",
      outcome: directOutcome(session, localDevice, explicit),
      media: session.accepted_media.length ? session.accepted_media : session.requested_media,
      participantIds: [remote],
      title: remote,
      startedAt,
      endedAt,
      durationSeconds: session.duration_seconds || Math.max(0, Math.floor((new Date(endedAt).getTime() - new Date(startedAt).getTime()) / 1000)),
    });
  },
  recordGroup(session: GroupSession, localDevice: string, explicit?: CallOutcome, circleId?: string) {
    const local = session.participants[localDevice];
    const participants = Object.values(session.participants);
    const joinedTimes = participants.map((item) => item.joined_at).filter(Boolean) as string[];
    const startedAt = joinedTimes.sort()[0] || session.created_at;
    const endedAt = session.ended_at || new Date().toISOString();
    const outcome = explicit || (local?.state === "declined" ? "declined" : joinedTimes.length > 1 ? "completed" : local?.role === "member" ? "missed" : "cancelled");
    write({
      id: session.group_id,
      kind: "group",
      direction: session.host_device_id === localDevice ? "outgoing" : "incoming",
      outcome,
      media: session.requested_media,
      participantIds: participants.map((item) => item.device_id).filter((id) => id !== localDevice),
      title: session.title || "Group call",
      startedAt,
      endedAt,
      durationSeconds: outcome === "completed" ? Math.max(0, Math.floor((new Date(endedAt).getTime() - new Date(startedAt).getTime()) / 1000)) : 0,
      circleId,
    });
  },
};

export default callHistoryService;
