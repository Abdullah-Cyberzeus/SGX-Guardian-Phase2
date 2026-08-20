import { useEffect, useRef } from "react";
import { useEventLog, type LogRow } from "./hooks/useEventLog";

function cotClass(cot: string): string {
  switch (cot) {
    case "ALPHA":           return "topo-cot-alpha";
    case "BRAVO":           return "topo-cot-bravo";
    case "CHARLIE":         return "topo-cot-charlie";
    case "DELTA":           return "topo-cot-delta";
    case "ALPHA ∩ BRAVO":   return "topo-cot-alpha-bravo";
    case "BRAVO ∩ CHARLIE": return "topo-cot-bravo-charlie";
    case "CHARLIE ∩ DELTA": return "topo-cot-charlie-delta";
    case "MESH":            return "topo-cot-mesh";
    case "POLICY":          return "topo-cot-policy";
    default:                return "topo-cot-other";
  }
}

function LogRows({ rows, onDeviceClick }: { rows: LogRow[]; onDeviceClick: (n: string) => void }) {
  return (
    <div className="topo-log">
      {rows.map((r) => (
        <div key={r.id} className={`topo-log-row ${r.lvl.toLowerCase()}`}>
          <span className="topo-event-node"><i /></span>
          <span className="topo-log-ts">{r.ts}</span>
          <span className={`topo-log-lvl ${r.lvl.toLowerCase()}`}>{r.lvl}</span>
          <span className="topo-ev-tags">
            <span className={`topo-ev-tag cot ${cotClass(r.cot)}`}>{r.cot}</span>
            <span
              className="topo-ev-tag dev"
              onClick={() => onDeviceClick(r.device)}
              role="button"
              tabIndex={0}
            >
              {r.device}
            </span>
          </span>
          <span className="topo-log-msg">{r.msg}</span>
          <span className="topo-event-framework">{r.lvl === "ERR" ? "MITRE TA0001 · NIST SI-4" : r.lvl === "WARN" ? "MITRE TA0006 · NIST AC-7" : "NIST CA-7"}</span>
          <span className="topo-log-src">{r.src}</span>
        </div>
      ))}
    </div>
  );
}

export function TopologyLogBar({ onDeviceClick }: { onDeviceClick: (name: string) => void }) {
  const { rows, count, flashTick } = useEventLog();
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!flashTick || !ref.current) return;
    ref.current.classList.remove("err-flash");
    void ref.current.offsetWidth;
    ref.current.classList.add("err-flash");
  }, [flashTick]);

  const info = rows.filter((r) => r.lvl === "INFO").length;
  const warn = rows.filter((r) => r.lvl === "WARN").length;
  const err = rows.filter((r) => r.lvl === "ERR").length;

  return (
    <footer className="topo-logbar" ref={ref} onClick={(e) => e.stopPropagation()}>
      <div className="topo-log-h">
        <span className="topo-log-live">LIVE SECURITY EVENT LOG</span>
        <span className="topo-log-stat">EVENTS / 5min · <span>{count}</span></span>
        <span className="topo-log-counts">
          <span className="topo-ev-tag info">INFO {86 + info}</span>
          <span className="topo-ev-tag warn">WARN {37 + warn}</span>
          <span className="topo-ev-tag err">ERR {5 + err}</span>
        </span>
        <span className="topo-log-stat" style={{ marginLeft: "auto" }}>CHANNEL · sgx.events.v1</span>
      </div>
      <LogRows rows={rows} onDeviceClick={onDeviceClick} />
    </footer>
  );
}
