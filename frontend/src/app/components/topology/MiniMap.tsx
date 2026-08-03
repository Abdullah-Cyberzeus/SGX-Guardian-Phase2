import { useEffect, useRef } from "react";
import { ZONES, GUARDIANS, THREATS, VIEW_BOX } from "./lib/topology";
import type { PanZoomSubscribe } from "./hooks/usePanZoom";
import { useZoomPercent } from "./hooks/useZoomPercent";

export function MiniMap({ subscribe }: { subscribe: PanZoomSubscribe }) {
  const rectRef = useRef<SVGRectElement | null>(null);
  const pct = useZoomPercent(subscribe);

  useEffect(() => {
    return subscribe((t) => {
      const el = rectRef.current;
      if (!el) return;
      const w = VIEW_BOX.w / t.k;
      const h = VIEW_BOX.h / t.k;
      const x = -t.x / t.k;
      const y = -t.y / t.k;
      el.setAttribute("x", String(x));
      el.setAttribute("y", String(y));
      el.setAttribute("width", String(w));
      el.setAttribute("height", String(h));
    });
  }, [subscribe]);

  return (
    <div className="topo-minimap" aria-label="Mini-map">
      <div className="topo-mm-h">
        <span>▣ GLOBAL OVERVIEW</span>
        <span>{pct}%</span>
      </div>
      <svg viewBox={`0 0 ${VIEW_BOX.w} ${VIEW_BOX.h}`} preserveAspectRatio="xMidYMid meet">
        {ZONES.map((z) => (
          <ellipse key={z.id} cx={z.cx} cy={z.cy} rx={z.rx} ry={z.ry}
            fill={z.color === "#14B8A6" ? "rgba(20,184,166,0.16)" :
                  z.color === "#9333EA" ? "rgba(147,51,234,0.16)" :
                  z.color === "#F59E0B" ? "rgba(245,158,11,0.16)" : "rgba(59,130,246,0.16)"}
            stroke={z.color} strokeOpacity=".6" />
        ))}
        {GUARDIANS.map((g) => (
          <g key={g.id}>
            <circle cx={g.cx} cy={g.cy} r={11} fill={g.health === "offline" ? "rgba(100,116,139,.16)" : g.health === "degraded" ? "rgba(255,176,32,.14)" : "rgba(40,240,165,.12)"} />
            <path d={`M${g.cx},${g.cy - 6} l5,2 v4 c0,3 -2,5 -5,6 c-3,-1 -5,-3 -5,-6 v-4z`} fill={g.health === "offline" ? "#64748b" : g.health === "degraded" ? "#ffb020" : "#28f0a5"} />
          </g>
        ))}
        {THREATS.map((t) => <g key={t.id}><circle cx={t.cx} cy={t.cy} r={9} fill="rgba(255,69,103,.12)" stroke="#ff4567" strokeWidth="1" /><path d={`M${t.cx},${t.cy - 4}v5M${t.cx},${t.cy + 4}v.2`} stroke="#ffb3c0" strokeWidth="1.4" /></g>)}
        <rect ref={rectRef} className="topo-mm-vp" x={0} y={0} width={VIEW_BOX.w} height={VIEW_BOX.h} />
      </svg>
    </div>
  );
}
