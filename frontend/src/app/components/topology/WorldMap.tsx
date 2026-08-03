import { useEffect, useState } from "react";
import { WORLD_PATHS } from "./lib/world-map";

const D_UNION = WORLD_PATHS.join(" ");

export function WorldMap({ detail = "full" }: { detail?: "full" | "light" }) {
  const [dots, setDots] = useState<{ x: number; y: number }[]>([]);

  useEffect(() => {
    if (detail === "light") return;
    const NS = "http://www.w3.org/2000/svg";
    const probe = document.createElementNS(NS, "svg") as SVGSVGElement;
    probe.setAttribute("viewBox", "0 0 1600 720");
    probe.style.position = "absolute";
    probe.style.left = "-99999px";
    probe.style.width = "200px";
    probe.style.height = "112px";
    const probePath = document.createElementNS(NS, "path");
    probePath.setAttribute("d", D_UNION);
    probePath.setAttribute("fill-rule", "nonzero");
    probe.appendChild(probePath);
    document.body.appendChild(probe);

    const out: { x: number; y: number }[] = [];
    const STEP = 10;
    const pt = probe.createSVGPoint();
    for (let y = 60; y < 820; y += STEP) {
      for (let x = 0; x < 1600; x += STEP) {
        pt.x = x; pt.y = y;
        pt.y = y / 0.8;
        if (probePath.isPointInFill(pt)) out.push({ x, y });
      }
    }
    document.body.removeChild(probe);
    setDots(out);
  }, [detail]);

  return (
    <g id="usmap" pointerEvents="none" opacity={0.30} style={{ filter: "drop-shadow(0 0 4px rgba(56,189,248,0.28))" }}>
      <path
        d={D_UNION}
        transform="scale(1 .8)"
        fill="rgba(56,189,248,0.05)"
        stroke="rgba(56,189,248,0.55)"
        strokeWidth="0.7"
        strokeLinejoin="round"
      />
      {detail === "full" && <g fill="rgba(125,211,252,0.45)">
        {dots.map((d, i) => (
          <circle key={i} cx={d.x} cy={d.y} r={0.9} />
        ))}
      </g>}
      {detail === "full" && <g stroke="rgba(56,189,248,0.05)" strokeWidth="0.5" fill="none">
        {Array.from({ length: 7 }).map((_, i) => {
          const x = 1600 * ((i + 1) / 8);
          return <line key={`gv${i}`} x1={x} y1={0} x2={x} y2={720} />;
        })}
        {Array.from({ length: 4 }).map((_, i) => {
          const y = 720 * ((i + 1) / 5);
          return <line key={`gh${i}`} x1={0} y1={y} x2={1600} y2={y} />;
        })}
      </g>}
    </g>
  );
}
