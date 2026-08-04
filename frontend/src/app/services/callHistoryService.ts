import type { CallSession, GroupSession, MediaType } from "../../features/calls/call.types";

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

const STORAGE_KEY = "sgx.call-history.v1";
const EVENT_NAME = "sgx:call-history-changed";

function read(): CallHistoryRecord[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

function write(record: CallHistoryRecord) {
  const records = read();
  const existing = records.findIndex((item) => item.id === record.id);
  if (existing >= 0) {
    const previous = records[existing];
    const keepExplicitOutcome = ["declined", "failed"].includes(previous.outcome)
      && ["missed", "cancelled"].includes(record.outcome);
    records[existing] = { ...previous, ...record, outcome: keepExplicitOutcome ? previous.outcome : record.outcome };
  }
  else records.push(record);
  records.sort((a, b) => new Date(b.endedAt).getTime() - new Date(a.endedAt).getTime());
  localStorage.setItem(STORAGE_KEY, JSON.stringify(records.slice(0, 500)));
  window.dispatchEvent(new CustomEvent(EVENT_NAME));
}

function directOutcome(session: CallSession, localDevice: string, explicit?: CallOutcome): CallOutcome {
  if (explicit) return explicit;
  if (session.started_at || session.duration_seconds > 0) return "completed";
  return session.receiver_device_id === localDevice ? "missed" : "cancelled";
}

export const callHistoryService = {
  eventName: EVENT_NAME,
  list: read,
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
