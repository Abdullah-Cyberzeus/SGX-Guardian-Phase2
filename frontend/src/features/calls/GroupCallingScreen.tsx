import { useEffect, useRef } from "react";
import { useGroupCall } from "./GroupCallContext";

function StreamTile({ peerId, stream }: { peerId: string; stream?: MediaStream }) {
  const ref = useRef<HTMLVideoElement>(null);
  useEffect(() => { if (ref.current) ref.current.srcObject = stream ?? null; }, [stream]);
  return <article className="group-tile">
    {stream ? <video ref={ref} autoPlay playsInline /> : <div className="avatar">{peerId.slice(0, 2).toUpperCase()}</div>}
    <strong>{peerId}</strong>
  </article>;
}

export function GroupCallingScreen({ localDevice: fallbackLocalDevice }: { localDevice?: string }) {
  const {
    group, incoming, localStream, remoteStreams, error, muted, cameraEnabled, localDevice: resolvedLocalDevice,
    toggleMute, toggleCamera, shareScreen, endGroup, moderate, rejoinGroup,
  } = useGroupCall();
  const localDevice = resolvedLocalDevice || fallbackLocalDevice;
  if (!group || incoming || !localDevice) return null;
  const local = group.participants[localDevice];
  if (!local || local.state === "kicked" || local.state === "declined") return null;
  if (local.state !== "joined" || !localStream) {
    return <div className="call-overlay group-call-overlay" role="dialog" aria-modal="true">
      <main className="group-stage reconnect-panel">
        <h2>Call connection interrupted</h2>
        <p>
          Reconnect if the call is still active, or end it for every participant.
        </p>
        {error && <div className="call-error" role="alert">{error}</div>}
        <div className="flex flex-wrap justify-center gap-2">
          <button onClick={() => rejoinGroup().catch(() => undefined)}>
            {local.state === "reconnecting" ? "Reconnect now" : "Rejoin call"}
          </button>
          <button
            className="end-call"
            onClick={() => endGroup().catch(() => undefined)}
          >
            End call for everyone
          </button>
        </div>
      </main>
    </div>;
  }
  const host = group.host_device_id === localDevice;
  const joined = Object.values(group.participants).filter((participant) => participant.state === "joined");
  return <div className="call-overlay group-call-overlay" role="dialog" aria-modal="true">
    <header className="call-header"><div><strong>{group.title}</strong><span className="secure-label">◆ Trusted group · {joined.length} joined</span></div></header>
    <main className="group-stage">
      <StreamTile peerId={`${localDevice} (you)`} stream={localStream} />
      {joined.filter((participant) => participant.device_id !== localDevice).map((participant) =>
        <article className="group-member-wrap" key={participant.device_id}>
          <StreamTile peerId={participant.device_id} stream={remoteStreams[participant.device_id]} />
          {host && <div className="moderator-controls">
            <button onClick={() => moderate({ action: "set_audio", device_id: participant.device_id, allowed: !participant.audio_allowed })}>{participant.audio_allowed ? "Block mic" : "Allow mic"}</button>
            <button onClick={() => moderate({ action: "set_video", device_id: participant.device_id, allowed: !participant.video_allowed })}>{participant.video_allowed ? "Block camera" : "Allow camera"}</button>
            <button className="danger" onClick={() => moderate({ action: "kick", device_id: participant.device_id })}>Kick</button>
          </div>}
        </article>)}
      {error && <div className="call-error">{error}</div>}
    </main>
    <footer className="call-controls">
      <button title={!local.audio_allowed ? "The host disabled your microphone" : undefined} disabled={!local.audio_allowed} onClick={toggleMute}>{muted || !local.audio_allowed ? "Mic off" : "Mic"}</button>
      <button title={!local.video_allowed ? "The host disabled your camera" : undefined} disabled={!local.video_allowed || !group.requested_media.includes("video")} onClick={toggleCamera}>{cameraEnabled && local.video_allowed ? "Camera" : "Camera off"}</button>
      <button disabled={!local.video_allowed || !group.requested_media.includes("video")} onClick={() => shareScreen()}>Share screen</button>
      <button className="end-call" onClick={() => endGroup()}>End group</button>
    </footer>
  </div>;
}
