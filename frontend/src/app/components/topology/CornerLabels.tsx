import { useEffect, useState } from "react";
import type { Guardian, Zone } from "./lib/topology";

const pad = (n: number) => (n < 10 ? `0${n}` : `${n}`);
function utc() {
  const d = new Date();
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

export function CornerTL() {
  return (
    <div className="topo-corner topo-corner-tl">
      <div><b>OPS-CENTER · TIER-1</b></div>
      <div>CLASSIFICATION · INTERNAL</div>
    </div>
  );
}

export function CornerBL() {
  return (
    <div className="topo-corner topo-corner-bl">
      <div className="topo-corner-live">TELEMETRY STREAM ACTIVE</div>
      <div>LATENCY 38ms · DRIFT &lt; 4σ</div>
    </div>
  );
}

export function CornerBR() {
  const [t, setT] = useState<string>("");
  useEffect(() => {
    setT(utc());
    const id = setInterval(() => setT(utc()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="topo-corner topo-corner-br">
      <div><b>SYS · {t}</b></div>
      <div>POLICY a1f3…c92e · MESH HEALTHY</div>
    </div>
  );
}

export function ZoneFocusLabel({ focus }: { focus: { zone: Zone; guardian: Guardian } | null }) {
  return (
    <div
      className="topo-zone-focus"
      data-active={focus ? "true" : "false"}
      aria-live="polite"
      style={focus ? { borderColor: focus.zone.color, color: focus.zone.text } : undefined}
    >
      {focus && (
        <>
          <span className="topo-zf-eyebrow">Edge devices connected to</span>
          <span className="topo-zf-line">
            <b>{focus.guardian.label}</b>
            <span className="topo-zf-sep">·</span>
            <span className="topo-zf-zone" style={{ color: focus.zone.text }}>{focus.zone.id}</span>
            <span className="topo-zf-tail">Circle of Trust</span>
          </span>
        </>
      )}
    </div>
  );
}
