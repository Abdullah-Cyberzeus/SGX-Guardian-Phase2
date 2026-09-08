import { Users, X } from "lucide-react";
import { useState } from "react";
import { useContactNames } from "../../app/contexts/ContactNameContext";
import { useCommunicationPeers } from "../../app/hooks/useApiData";
import { useGroupCall } from "./GroupCallContext";

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

export function IncomingGroupCallDialog() {
  const { incoming, acceptGroup, declineGroup, error } = useGroupCall();
  const { data: communicationPeers } = useCommunicationPeers();
  const { displayForDid } = useContactNames();
  const [working, setWorking] = useState(false);
  const [failure, setFailure] = useState<string>();
  if (!incoming) return null;
  const joined = Object.keys(incoming.participants).length;
  const hostName = displayForDid(
    incoming.host_device_id,
    rosterNameFor(incoming.host_device_id, communicationPeers || undefined) || incoming.host_device_id,
  );
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
        <span>{hostName} · {joined} invited</span>
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
