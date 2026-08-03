export type MediaType = "audio" | "video";
export type CallWireState = "idle" | "local_policy_check" | "offer_sent" | "offer_received" |
  "verifying" | "authorizing" | "accepted" | "media_negotiation" | "connected" | "ended";
export type SignalKind = "sdp_offer" | "sdp_answer" | "ice_candidate" | "ice_complete" |
  "media_ready" | "hangup" | "error";

export interface CallSession {
  session_id: string; state: CallWireState; terminal: boolean; media_connected: boolean;
  initiator_device_id: string; receiver_device_id: string;
  requested_media: MediaType[]; accepted_media: MediaType[];
  created_at: string; updated_at: string; started_at?: string; ended_at?: string;
  duration_seconds: number; local_media_ready: boolean; remote_media_ready: boolean;
}
export interface BrowserSignal { id: number; session_id: string; type: SignalKind; sender_device_id: string; payload: unknown; received_at: string; }
export interface Peer {
  peerId: string; ip: string; status: string; lastSeen: string;
  callAvailable: boolean; callUnavailableReason?: string;
  online: boolean;
}
export interface CallEvent { event: string; session: CallSession; }

export type GroupRole = "host" | "member";
export type GroupMemberState = "invited" | "joined" | "reconnecting" | "disconnected" |
  "declined" | "left" | "kicked";
export type GroupCallState = "ringing" | "active" | "ended";
export interface GroupParticipant {
  device_id: string; virtual_id: string; nebula_ip: string; role: GroupRole;
  state: GroupMemberState; audio_allowed: boolean; video_allowed: boolean;
  media_ready: boolean; joined_at?: string; last_seen_at?: string;
}
export interface GroupSession {
  group_id: string; title: string; host_device_id: string; requested_media: MediaType[];
  state: GroupCallState; participants: Record<string, GroupParticipant>;
  created_at: string; updated_at: string; ended_at?: string;
}
export interface GroupSignal extends BrowserSignal {}
export type GroupModerationAction =
  | { action: "kick"; device_id: string }
  | { action: "set_audio"; device_id: string; allowed: boolean }
  | { action: "set_video"; device_id: string; allowed: boolean };

