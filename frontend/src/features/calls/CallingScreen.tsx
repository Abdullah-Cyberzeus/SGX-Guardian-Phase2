import { useEffect, useRef, useState } from "react";
import {
  AudioLines,
  LockKeyhole,
  Mic,
  MicOff,
  MonitorUp,
  PhoneOff,
  ShieldCheck,
  Video as VideoIcon,
  VideoOff,
} from "lucide-react";
import { useContactNames } from "../../app/contexts/ContactNameContext";
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

function formatDuration(seconds: number) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;
  return hours > 0
    ? `${hours}:${String(minutes).padStart(2, "0")}:${String(remainingSeconds).padStart(2, "0")}`
    : `${String(minutes).padStart(2, "0")}:${String(remainingSeconds).padStart(2, "0")}`;
}

function peerInitials(name: string) {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length > 1) return `${words[0][0]}${words[words.length - 1][0]}`.toUpperCase();
  return (words[0] || "GX").slice(0, 2).toUpperCase();
}

function compactIdentity(identity: string) {
  return identity.length > 32 ? `${identity.slice(0, 15)}…${identity.slice(-10)}` : identity;
}

function ControlButton({
  label,
  active = false,
  danger = false,
  disabled = false,
  onClick,
  children,
}: {
  label: string;
  active?: boolean;
  danger?: boolean;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="direct-call-control-wrap">
      <button
        type="button"
        className={`direct-call-control${active ? " is-active" : ""}${danger ? " is-danger" : ""}`}
        aria-label={label}
        aria-pressed={active || undefined}
        title={label}
        disabled={disabled}
        onClick={onClick}
      >
        {children}
      </button>
      <span>{label}</span>
    </div>
  );
}

export function CallingScreen() {
  const { call, incoming, peerId, peerOnline, localStream, remoteStream, error, muted, cameraEnabled, qualityLabel, toggleMute, toggleCamera, sendTestTone, shareScreen, end } = useCall();
  const { displayForDid } = useContactNames();
  const elapsed = useCallDuration(call);
  const [testingAudio, setTestingAudio] = useState(false);
  // While a call is still ringing (offer_received), the incoming toast owns the UI —
  // the full-screen overlay must only appear once the callee has accepted.
  if (!call || incoming) return null;

  const peer = peerId ?? "Remote Guardian";
  const displayName = displayForDid(peer, compactIdentity(peer));
  const showIdentity = displayName !== peer;
  const label = stateLabel(call.state, peerOnline);
  const connected = call.state === "connected";
  const supportsAudio = call.requested_media.includes("audio") || call.accepted_media.includes("audio");
  const supportsVideo = call.requested_media.includes("video") || call.accepted_media.includes("video");
  const remoteHasVideo = supportsVideo && Boolean(remoteStream?.getVideoTracks().some((track) => track.readyState === "live"));
  const localHasVideo = supportsVideo && Boolean(localStream?.getVideoTracks().some((track) => track.readyState === "live"));

  const testAudio = () => {
    if (testingAudio) return;
    setTestingAudio(true);
    sendTestTone()
      .catch(() => undefined)
      .finally(() => window.setTimeout(() => setTestingAudio(false), 1250));
  };

  return <div className="call-overlay direct-call-overlay" role="dialog" aria-modal="true" aria-label={`${supportsVideo ? "Video" : "Audio"} call with ${displayName}`}>
    <header className="direct-call-header">
      <div className="direct-call-brand">
        <span className="direct-call-brand-icon"><LockKeyhole size={15} /></span>
        <div>
          <strong>SG-X Secure Call</strong>
          <span>End-to-end protected</span>
        </div>
      </div>
      <div className={`direct-call-network${connected ? " is-connected" : ""}`}>
        <span className="direct-call-network-dot" />
        {connected ? `Connected${qualityLabel ? ` · ${qualityLabel}` : ""}` : label}
      </div>
    </header>

    <main className={`video-stage direct-call-stage${remoteHasVideo ? " has-video" : " is-audio"}`}>
      {remoteHasVideo && <Video stream={remoteStream} className="remote-video" />}
      {!remoteHasVideo && <div className="direct-audio-scene">
        <div className="direct-call-ambient direct-call-ambient-one" />
        <div className="direct-call-ambient direct-call-ambient-two" />

        <div className={`direct-call-avatar-shell${connected && !muted ? " is-speaking" : ""}`}>
          <span className="direct-call-pulse pulse-one" />
          <span className="direct-call-pulse pulse-two" />
          <div className="direct-call-avatar">{peerInitials(displayName)}</div>
          <span className="direct-call-verified" title="Verified Guardian identity"><ShieldCheck size={18} /></span>
        </div>

        <div className="direct-call-person">
          <p className="direct-call-kicker">{supportsVideo ? "Camera unavailable" : "Audio call"}</p>
          <h1>{displayName}</h1>
          {showIdentity && <p className="direct-call-peer-id" title={peer}>{compactIdentity(peer)}</p>}
        </div>

        <div className={`direct-call-status${connected ? " is-live" : ""}`}>
          {connected ? <>
            <div className="direct-call-equalizer" aria-hidden="true">
              <i /><i /><i /><i /><i />
            </div>
            <time>{formatDuration(elapsed)}</time>
          </> : <>
            <span className="direct-call-spinner" aria-hidden="true" />
            <span>{label}</span>
          </>}
        </div>

        <p className="direct-call-security-note"><ShieldCheck size={14} /> Identity and call policy verified continuously</p>
        {call.encryption_verified && <p className="direct-call-security-note"><ShieldCheck size={14} /> Encryption verified</p>}
      </div>}

      {remoteHasVideo && <div className="direct-video-info">
        <div><strong>{displayName}</strong>{showIdentity && <span>{compactIdentity(peer)}</span>}</div>
        <time>{connected ? `${formatDuration(elapsed)}${qualityLabel ? ` · ${qualityLabel}` : ""}` : label}</time>
      </div>}
      {localHasVideo && <Video stream={localStream} muted className="local-video" />}
      {error && <div className="call-error" role="alert">{error}</div>}
    </main>

    <footer className="call-controls direct-call-controls">
      <ControlButton label={muted ? "Unmute" : "Mute"} active={muted} onClick={toggleMute}>
        {muted ? <MicOff size={22} /> : <Mic size={22} />}
      </ControlButton>
      <ControlButton label={testingAudio ? "Testing…" : "Audio test"} active={testingAudio} disabled={!connected || !supportsAudio} onClick={testAudio}>
        <AudioLines size={22} />
      </ControlButton>
      <ControlButton label={!supportsVideo ? "Audio only" : cameraEnabled ? "Camera off" : "Camera on"} active={supportsVideo && !cameraEnabled} disabled={!supportsVideo} onClick={toggleCamera}>
        {supportsVideo && cameraEnabled ? <VideoIcon size={22} /> : <VideoOff size={22} />}
      </ControlButton>
      {supportsVideo && <ControlButton label="Share screen" disabled={!connected} onClick={() => { void shareScreen().catch(() => undefined); }}>
        <MonitorUp size={22} />
      </ControlButton>}
      <ControlButton label="End call" danger onClick={() => { void end(); }}>
        <PhoneOff size={24} />
      </ControlButton>
    </footer>
  </div>;
}
