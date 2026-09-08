import { useEffect, useState } from "react";
import callHistoryService, { type CallHistoryRecord } from "../services/callHistoryService";
import { useBootStatus } from "./useApiData";
import { useAuth } from "../contexts/AuthContext";

export function useCallHistory() {
  const { session } = useAuth();
  const { data: bootStatus } = useBootStatus();
  const sessionKey = session
    ? session.browserMemberDid || session.guardianDid || session.user.id || "authenticated"
    : "signed-out";
  const deploymentKey = bootStatus?.binaryHash && bootStatus.binaryHash !== "N/A"
    ? bootStatus.binaryHash
    : __APP_VERSION__;
  const [records, setRecords] = useState<CallHistoryRecord[]>([]);

  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      if (!cancelled) {
        setRecords(callHistoryService.list());
      }
    };

    void (async () => {
      try {
        await callHistoryService.resetForDeployment(deploymentKey);
        if (cancelled) return;
        if (session) {
          await callHistoryService.syncFromGuardian();
        }
        if (!cancelled) refresh();
      } catch {
        if (!cancelled) refresh();
      }
    })();

    window.addEventListener(callHistoryService.eventName, refresh);
    window.addEventListener("storage", refresh);
    return () => {
      cancelled = true;
      window.removeEventListener(callHistoryService.eventName, refresh);
      window.removeEventListener("storage", refresh);
    };
  }, [sessionKey, deploymentKey]);
  return records;
}
