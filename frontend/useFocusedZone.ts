import { useEffect, useRef, useState } from "react";
import { Loader2, PhoneOff } from "lucide-react";
import { useCall } from "../../../features/calls/CallContext";
import { useGroupCall } from "../../../features/calls/GroupCallContext";
import type { CallMode, CallRecord } from "./types";

interface CallParticipant {
  id: string;
  name: string;
}

interface CallScreenProps {
  mode: CallMode;
  title: string;
  participants: CallParticipant[];
  group?: boolean;
  onEnd: (record: CallRecord) => void;
}

/**
 * Compatibility bridge for the existing Circle screens. The actual media UI
 * is mounted globally by Root so incoming calls work from every route.
 */
export function CallScreen({ mode, title, participants, group: groupMode = false, onEnd }: CallScreenProps) {
  const direct = useCall();
  const group = useGroupCall();
  const started = useRef(false);
  const becameActive = useRef(false);
  const [error, setError] = useState<string>();
  const media = mode === "video" ? (["audio", "video"] as const) : (["audio"] as const);
  const isGroup = groupMode;
  const active = isGroup ? group.group : direct.call;

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const run = isGroup
      ? group.createGroup(participants.map((participant) => participant.id), false, [...media], title)
      : participants[0]
        ? direct.startCall(participants[0].id, [...media])
        : Promise.reject(new Error("No online Guardian selected"));
    run.catch((cause) => {
      setError(cause instanceof Error ? cause.message : "Unable to start call");
    });
  }, []);

  useEffect(() => {
    if (active) becameActive.current = true;
    if (becameActive.current && !active) {
      onEnd({ type: mode, participant: isGroup ? "All Members" : title, duration: "Completed" });
    }
  }, [active, isGroup, mode, onEnd, title]);

  if (active) return null;
  return (
    <div className="call-launch-overlay" role="dialog" aria-modal="true">
      <div className="call-launch-card">
        {error ? <PhoneOff size={32} /> : <Loader2 className="animate-spin" size={32} />}
        <h2>{error ? "Call could not start" : `Calling ${title}…`}</h2>
        <p>{error ?? "Preparing secure microphone and camera access"}</p>
        {error && <button onClick={() => onEnd({ type: mode, participant: title, duration: "Failed" })}>Close</button>}
      </div>
    </div>
  );
}
