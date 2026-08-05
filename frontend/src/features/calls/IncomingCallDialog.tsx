import { Phone, Video, X } from "lucide-react";
import { useState } from "react";
import { useCall } from "./CallContext";

export function IncomingCallDialog() {
  const { incoming, accept, decline } = useCall();
  const [working, setWorking] = useState(false);
  const [failure, setFailure] = useState<string>();
  if (!incoming) return null;
  const video = incoming.requested_media.includes("video");
  const act = async (action: "accept" | "decline") => {
    if (working) return;
    setWorking(true);
    setFailure(undefined);
    try {
      if (action === "accept") await accept();
      else await decline();
    } catch (cause) {
      setFailure(cause instanceof Error ? cause.message : "Call action failed");
    } finally {
      setWorking(false);
    }
  };
  return (
    <aside className="incoming-call-toast" role="alertdialog" aria-labelledby="incoming-call-title">
      <div className="incoming-call-icon">{video ? <Video size={20} /> : <Phone size={20} />}</div>
      <div className="min-w-0 flex-1">
        <strong id="incoming-call-title">Incoming {video ? "video" : "voice"} call</strong>
        <span>{incoming.initiator_device_id}</span>
        <small className={failure ? "call-toast-error" : undefined}>{failure || "Verified Guardian"}</small>
      </div>
      <button className="incoming-decline-icon" disabled={working} onClick={() => void act("decline")} aria-label="Decline call"><X size={17} /></button>
      <div className="incoming-call-actions">
        <button disabled={working} onClick={() => void act("decline")}>Decline</button>
        <button className="accept" disabled={working} onClick={() => void act("accept")}>{working ? "Opening…" : "Accept"}</button>
      </div>
    </aside>
  );
}
