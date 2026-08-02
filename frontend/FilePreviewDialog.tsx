import { useEffect, useState } from "react";
import type { PanZoomSubscribe } from "./usePanZoom";

export function useZoomPercent(subscribe: PanZoomSubscribe): number {
  const [pct, setPct] = useState(100);
  useEffect(() => {
    return subscribe((t) => {
      const next = Math.round(t.k * 100);
      setPct((cur) => (cur === next ? cur : next));
    });
  }, [subscribe]);
  return pct;
}
