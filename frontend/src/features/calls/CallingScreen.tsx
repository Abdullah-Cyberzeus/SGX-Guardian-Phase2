import { useEffect, useRef } from "react";
import { useCall } from "./CallContext";

const labels: Record<string, string> = { local_policy_check: "Checking call policy…", offer_sent: "Ringing…", verifying: "Verifying Guardian identity…", authorizing: "Checking permissions…", accepted: "Preparing secure media…", media_negotiation: "Establishing encrypted connection…", connected: "Secure connection" };

function Video({ stream, muted, className }: { stream?: MediaStream; muted?: boolean; className: string }) {
  const ref = useRef<HTMLVideoElement>(null); useEffect(() => { if (ref.current) ref.current.srcObject = stream ?? null; }, [stream]);
  return stream ? <video ref={ref} className={className} autoPlay playsInline muted={muted} /> : null;
}

export function CallingScreen() {
  const { call, peerId, localStream, remoteStream, error, muted, cameraEnabled, toggleMute, toggleCamera, sendTestTone, shareScreen, end } = useCall();
  if (!call) return null; const peer = peerId ?? "Remote Guardian";
  return <div className="call-overlay" role="dialog" aria-modal="true" aria-label="Active call">
    <header className="call-header"><div><strong>{peer}</strong><span className="secure-label">◆ {labels[call.state] ?? call.state}</span></div><div>{call.state === "connected" ? `${Math.floor(call.duration_seconds / 60)}:${String(call.duration_seconds % 60).padStart(2, "0")}` : ""}</div></header>
    <main className="video-stage">
      <Video stream={remoteStream} className="remote-video" />
      {!remoteStream && <div className="remote-placeholder"><div className="avatar large">{peer.slice(0, 2).toUpperCase()}</div><h2>{labels[call.state] ?? "Connecting…"}</h2><p>Identity and policy checks remain active</p></div>}
      <Video stream={localStream} muted className="local-video" />
      {error && <div className="call-error" role="alert">{error}</div>}
    </main>
    <footer className="call-controls">
      <button aria-label={muted ? "Unmute microphone" : "Mute microphone"} aria-pressed={muted} onClick={toggleMute}>{muted ? "Mic off" : "Mic"}</button>
      <button aria-label={cameraEnabled ? "Turn camera off" : "Turn camera on"} aria-pressed={!cameraEnabled} onClick={toggleCamera}>{cameraEnabled ? "Camera" : "Camera off"}</button>
      <button aria-label="Send test audio to remote peer" disabled={call.state !== "connected" || !call.requested_media.includes("audio")} onClick={() => sendTestTone().catch(() => undefined)}>Test audio</button>
      <button aria-label="Share screen" onClick={() => shareScreen().catch(() => undefined)}>Share</button>
      <button className="end-call" aria-label="End call" onClick={() => end()}>End</button>
    </footer>
  </div>;
}

