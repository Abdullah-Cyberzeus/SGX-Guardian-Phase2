import { useEffect, useRef, useState } from "react";
import { useCall } from "./CallContext";
import type { CallSession } from "./call.types";

const labels: Record<string, string> = { local_policy_check: "Checking call policy…", offer_sent: "Calling…", offer_received: "Calling…", verifying: "Verifying Guardian identity…", authorizing: "Checking permissions…", accepted: "Preparing secure media…", media_negotiation: "Establishing encrypted connection…", connected: "Secure connection" };

// offer_sent (device-to-device, via Nebula) and offer_received (local browser
// member calls skip Nebula and land straight in offer_received on the shared
// session) both mean the offer was delivered and we're waiting on the callee.
// Whether that reads as "Ringing…" or "Calling…" depends on whether the peer
// was known to be online when the call was placed. Note: when this screen
// renders, offer_received always means WE are the caller — the incoming-call
// gate (`incoming`) already claims that state for the receiver's own view.
function stateLabel(state: string, peerOnline?: boolean): string {
  if (state === "offer_sent" || state === "offer_received") return peerOnline ? "Ringing…" : "Calling…";
  return labels[state] ?? state;
}

function Video({ stream, muted, className }: { stream?: MediaStream; muted?: boolean; className: string }) {
  const ref = useRef<HTMLVideoElement>(null); useEffect(() => { if (ref.current) ref.current.srcObject = stream ?? null; }, [stream]);
  return stream ? <video ref={ref} className={className} autoPlay playsInline muted={muted} /> : null;
}

// The backend only pushes `duration_seconds` on discrete call-state events, not
// once a second, so a WhatsApp-style live counter has to be ticked locally —
// anchored to `started_at` so it stays correct regardless of push cadence.
function useCallDuration(call?: CallSession) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!call || call.state !== "connected") { setElapsed(0); return; }
    const anchor = call.started_at ? new Date(call.started_at).getTime() : Date.now() - call.duration_seconds * 1000;
    const tick = () => setElapsed(Math.max(0, Math.floor((Date.now() - anchor) / 1000)));
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [call?.state, call?.session_id, call?.started_at]);
  return elapsed;
}

export function CallingScreen() {
  const { call, incoming, peerId, peerOnline, localStream, remoteStream, error, muted, cameraEnabled, toggleMute, toggleCamera, sendTestTone, shareScreen, end } = useCall();
  const elapsed = useCallDuration(call);
  // While a call is still ringing (offer_received), the incoming toast owns the UI —
  // the full-screen overlay must only appear once the callee has accepted.
  if (!call || incoming) return null; const peer = peerId ?? "Remote Guardian";
  const label = stateLabel(call.state, peerOnline);
  return <div className="call-overlay" role="dialog" aria-modal="true" aria-label="Active call">
    <header className="call-header"><div><strong>{peer}</strong><span className="secure-label">◆ {label}</span></div><div>{call.state === "connected" ? `${Math.floor(elapsed / 60)}:${String(elapsed % 60).padStart(2, "0")}` : ""}</div></header>
    <main className="video-stage">
      <Video stream={remoteStream} className="remote-video" />
      {!remoteStream && <div className="remote-placeholder"><div className="avatar large">{peer.slice(0, 2).toUpperCase()}</div><h2>{label}</h2><p>Identity and policy checks remain active</p></div>}
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
