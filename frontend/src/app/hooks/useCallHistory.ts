import { useEffect, useState } from "react";
import callHistoryService from "../services/callHistoryService";
import { useAuth } from "../contexts/AuthContext";

export function useCallHistory() {
  const { session } = useAuth();
  const sessionKey = session
    ? session.browserMemberDid || session.guardianDid || session.user.id || "authenticated"
    : "signed-out";
  const [records, setRecords] = useState(callHistoryService.list);
  useEffect(() => {
    const refresh = () => setRecords(callHistoryService.list());
    void callHistoryService.resetLocal()
      .then(() => session ? callHistoryService.syncFromGuardian() : undefined)
      .catch(() => undefined);
    window.addEventListener(callHistoryService.eventName, refresh);
    window.addEventListener("storage", refresh);
    return () => { window.removeEventListener(callHistoryService.eventName, refresh); window.removeEventListener("storage", refresh); };
  }, [sessionKey]);
  return records;
}
