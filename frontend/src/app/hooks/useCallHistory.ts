import { useEffect, useState } from "react";
import callHistoryService from "../services/callHistoryService";

export function useCallHistory() {
  const [records, setRecords] = useState(callHistoryService.list);
  useEffect(() => {
    const refresh = () => setRecords(callHistoryService.list());
    window.addEventListener(callHistoryService.eventName, refresh);
    window.addEventListener("storage", refresh);
    return () => { window.removeEventListener(callHistoryService.eventName, refresh); window.removeEventListener("storage", refresh); };
  }, []);
  return records;
}
