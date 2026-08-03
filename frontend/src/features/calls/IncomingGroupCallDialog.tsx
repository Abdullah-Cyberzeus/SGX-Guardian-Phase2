import { Users, X } from "lucide-react";
import { useState } from "react";
import { useGroupCall } from "./GroupCallContext";

export function IncomingGroupCallDialog() {
  const { incoming, acceptGroup, declineGroup, error } = useGroupCall();
  const [working, setWorking] = useState(false);
  const [failure, setFailure] = useState<string>();
  if (!incoming) return null;
  const joined = Object.keys(incoming.participants).length;
  const act = async (action: "accept" | "decline") => {
    if (working) return;
    setWorking(true);
    setFailure(undefined);
    try {
      if (action === "accept") await acceptGroup();
      else await declineGroup();
    } catch (cause) {
      setFailure(cause instanceof Error ? cause.message : "Group call action failed");
    } finally {
      setWorking(false);
    }
  };
  return (
    <aside className="incoming-call-toast incoming-group-toast" role="alertdialog" aria-labelledby="incoming-group-title">
      <div className="incoming-call-icon"><Users size={20} /></div>
      <div className="min-w-0 flex-1">
        <strong id="incoming-group-title">{incoming.title || "Incoming group call"}</strong>
        <span>{incoming.host_device_id} · {joined} invited</span>
        <small className={failure || error ? "call-toast-error" : undefined}>{failure || error || "Trusted group invitation"}</small>
      </div>
      <button className="incoming-decline-icon" disabled={working} onClick={() => void act("decline")} aria-label="Decline group call"><X size={17} /></button>
      <div className="incoming-call-actions">
        <button disabled={working} onClick={() => void act("decline")}>Decline</button>
        <button className="accept" disabled={working} onClick={() => void act("accept")}>{working ? "Joining…" : "Join"}</button>
      </div>
    </aside>
  );
}
