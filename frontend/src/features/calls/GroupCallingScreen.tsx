import { useEffect, useRef } from "react";
import { Mic, MicOff, MonitorUp, PhoneOff, Video, VideoOff } from "lucide-react";
import { useGroupCall } from "./GroupCallContext";
import { useCommunicationPeers, useGuardianInfo } from "../../app/hooks/useApiData";
import { useAuth } from "../../app/contexts/AuthContext";
import { useContactNames } from "../../app/contexts/ContactNameContext";
import { isMemberRole } from "../../app/utils/authorization";

function StreamTile({ peerId, stream }: { peerId: string; stream?: MediaStream }) {
  const ref = useRef<HTMLVideoElement>(null);
  useEffect(() => { if (ref.current) ref.current.srcObject = stream ?? null; }, [stream]);
  return <article className="group-tile">
    {stream ? <video ref={ref} autoPlay playsInline /> : <div className="avatar">{peerId.slice(0, 2).toUpperCase()}</div>}
    <strong>{peerId}</strong>
  </article>;
}

function rosterNameFor(identity: string, peers?: Array<{ did?: string; peerId?: string; displayName?: string; fullName?: string; deviceName?: string; ip?: string }>) {
  const peer = peers?.find((item) => item.did === identity || item.peerId === identity);
  return [peer?.displayName, peer?.fullName, peer?.deviceName]
    .map((value) => String(value || "").trim())
    .find((value) => value
      && value !== identity
      && value !== peer?.ip
      && !["browser", "pwa member device"].includes(value.toLowerCase())
      && !value.toLowerCase().startsWith("did:"));
}

export function GroupCallingScreen({ localDevice: fallbackLocalDevice }: { localDevice?: string }) {
  const {
    group, incoming, localStream, remoteStreams, error, muted, cameraEnabled, localDevice: resolvedLocalDevice,
    toggleMute, toggleCamera, shareScreen, leaveGroup, endGroup, moderate, rejoinGroup,
  } = useGroupCall();
  const localDevice = resolvedLocalDevice || fallbackLocalDevice;
  const { data: guardianInfo } = useGuardianInfo();
  const { data: communicationPeers } = useCommunicationPeers();
  const { session } = useAuth();
  const { displayForDid } = useContactNames();
  const localDeviceName = isMemberRole(session?.user.role)
    ? session?.user.name || rosterNameFor(localDevice || "", communicationPeers || undefined) || localDevice
    : guardianInfo?.deviceId || guardianInfo?.name || rosterNameFor(localDevice || "", communicationPeers || undefined) || localDevice;
  if (!group || incoming || !localDevice) return null;
  const local = group.participants[localDevice];
  if (!local || local.state === "kicked" || local.state === "declined") return null;
  const host = group.host_device_id === localDevice;
  const endOrLeave = () => (host ? endGroup() : leaveGroup()).catch(() => undefined);
  const endLabel = host ? "End call for everyone" : "Leave call";
  const displayForParticipant = (identity: string) => (
    identity === localDevice
      ? `${localDeviceName} (you)`
      : displayForDid(identity, rosterNameFor(identity, communicationPeers || undefined) || identity)
  );
  if (local.state !== "joined" || !localStream) {
    const starting = !error && (local.state === "joined" || local.state === "invited" || local.state === "reconnecting");
    if (starting) {
      return <div className="call-overlay group-call-overlay" role="dialog" aria-modal="true">
        <main className="group-stage reconnect-panel">
          <h2>Starting group call</h2>
          <p>Preparing secure media for {group.title || "this Circle"}.</p>
          <button className="group-call-end-button end-call" onClick={endOrLeave} aria-label={endLabel}>
            <PhoneOff size={18} />
            <span>{host ? "End call" : "Leave call"}</span>
          </button>
        </main>
      </div>;
    }
    return <div className="call-overlay group-call-overlay" role="dialog" aria-modal="true">
      <main className="group-stage reconnect-panel">
        <h2>Call connection interrupted</h2>
        <p>
          Reconnect if the call is still active, or {host ? "end it for every participant" : "leave the call"}.
        </p>
        {error && <div className="call-error" role="alert">{error}</div>}
        <div className="flex flex-wrap justify-center gap-2">
          <button onClick={() => rejoinGroup().catch(() => undefined)}>
            {local.state === "reconnecting" ? "Reconnect now" : "Rejoin call"}
          </button>
          <button
            className="end-call"
            onClick={endOrLeave}
          >
            {endLabel}
          </button>
        </div>
      </main>
    </div>;
  }
  const joined = Object.values(group.participants).filter((participant) => participant.state === "joined");
  return <div className="call-overlay group-call-overlay" role="dialog" aria-modal="true">
    <header className="call-header group-call-header">
      <div><strong>{group.title}</strong><span className="secure-label">◆ Trusted group · {joined.length} joined</span></div>
    </header>
    <main className="group-stage">
      <StreamTile peerId={displayForParticipant(localDevice)} stream={localStream} />
      {joined.filter((participant) => participant.device_id !== localDevice).map((participant) =>
        <article className="group-member-wrap" key={participant.device_id}>
          <StreamTile peerId={displayForParticipant(participant.device_id)} stream={remoteStreams[participant.device_id]} />
          {host && <div className="moderator-controls">
            <button onClick={() => moderate({ action: "set_audio", device_id: participant.device_id, allowed: !participant.audio_allowed })}>{participant.audio_allowed ? "Block mic" : "Allow mic"}</button>
            <button onClick={() => moderate({ action: "set_video", device_id: participant.device_id, allowed: !participant.video_allowed })}>{participant.video_allowed ? "Block camera" : "Allow camera"}</button>
            <button className="danger" onClick={() => moderate({ action: "kick", device_id: participant.device_id })}>Kick</button>
          </div>}
        </article>)}
      {error && <div className="call-error">{error}</div>}
    </main>
    <footer className="call-controls">
      <button title={!local.audio_allowed ? "The host disabled your microphone" : undefined} disabled={!local.audio_allowed} onClick={toggleMute}>
        {muted || !local.audio_allowed ? <MicOff size={18} /> : <Mic size={18} />}
        <span>{muted || !local.audio_allowed ? "Mic off" : "Mic"}</span>
      </button>
      <button title={!local.video_allowed ? "The host disabled your camera" : undefined} disabled={!local.video_allowed || !group.requested_media.includes("video")} onClick={toggleCamera}>
        {cameraEnabled && local.video_allowed ? <Video size={18} /> : <VideoOff size={18} />}
        <span>{cameraEnabled && local.video_allowed ? "Camera" : "Camera off"}</span>
      </button>
      <button disabled={!local.video_allowed || !group.requested_media.includes("video")} onClick={() => shareScreen()}>
        <MonitorUp size={18} />
        <span>Share screen</span>
      </button>
      <button
        className="end-call"
        onClick={endOrLeave}
      >
        <PhoneOff size={18} />
        <span>{host ? "End group" : "Leave group"}</span>
      </button>
    </footer>
  </div>;
}
