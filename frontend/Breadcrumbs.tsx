import { useEffect, useState } from "react";
import { GUARDIANS, VIEW_BOX, ZONES, type Guardian, type Zone } from "../lib/topology";
import type { PanZoomSubscribe, PanZoomState } from "./usePanZoom";

const ZOOM_THRESHOLD = 1.2;

interface FocusedZone { zone: Zone; guardian: Guardian; }

function compute(t: PanZoomState): FocusedZone | null {
  if (t.k < ZOOM_THRESHOLD) return null;
  const cx = (VIEW_BOX.w / 2 - t.x) / t.k;
  const cy = (VIEW_BOX.h / 2 - t.y) / t.k;
  let best: { zone: Zone; d: number } | null = null;
  for (const z of ZONES) {
    const dx = (cx - z.cx) / z.rx;
    const dy = (cy - z.cy) / z.ry;
    const d = dx * dx + dy * dy;
    if (d <= 1 && (!best || d < best.d)) best = { zone: z, d };
  }
  if (!best) return null;
  const guardian = GUARDIANS.find((g) => g.zone === best!.zone.id)!;
  return { zone: best.zone, guardian };
}

export function useFocusedZone(subscribe: PanZoomSubscribe): FocusedZone | null {
  const [focus, setFocus] = useState<FocusedZone | null>(null);
  useEffect(() => {
    return subscribe((t) => {
      const next = compute(t);
      setFocus((cur) => {
        const sameId = cur?.zone.id === next?.zone.id;
        return sameId ? cur : next;
      });
    });
  }, [subscribe]);
  return focus;
}
