import { useEffect, useRef, useCallback } from "react";
import { select } from "d3-selection";
import "d3-transition";
import { zoom, zoomIdentity, type D3ZoomEvent, type ZoomBehavior, type ZoomTransform } from "d3-zoom";

export interface PanZoomState { k: number; x: number; y: number; }
export type PanZoomListener = (t: PanZoomState) => void;
export type PanZoomSubscribe = (cb: PanZoomListener) => () => void;

const initial: PanZoomState = { k: 1, x: 0, y: 0 };

export function usePanZoom(opts: { minScale?: number; maxScale?: number } = {}) {
  const { minScale = 0.5, maxScale = 6 } = opts;
  const svgRef = useRef<SVGSVGElement | null>(null);
  const groupRef = useRef<SVGGElement | null>(null);
  const zoomRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const transformRef = useRef<PanZoomState>(initial);
  const listenersRef = useRef<Set<PanZoomListener>>(new Set());

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = select(svgRef.current);
    const z = zoom<SVGSVGElement, unknown>()
      .scaleExtent([minScale, maxScale])
      .filter((event) => {
        if (event.type === "wheel") return true;
        if (event.button === 2) return false;
        return !event.ctrlKey;
      })
      .on("zoom", (e: D3ZoomEvent<SVGSVGElement, unknown>) => {
        const t: PanZoomState = { k: e.transform.k, x: e.transform.x, y: e.transform.y };
        transformRef.current = t;
        const g = groupRef.current;
        if (g) g.setAttribute("transform", `translate(${t.x},${t.y}) scale(${t.k})`);
        for (const cb of listenersRef.current) cb(t);
      });
    zoomRef.current = z;
    svg.call(z);
    svg.on("dblclick.zoom", null);
    return () => {
      svg.on(".zoom", null);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const subscribe = useCallback<PanZoomSubscribe>((cb) => {
    listenersRef.current.add(cb);
    cb(transformRef.current);
    return () => { listenersRef.current.delete(cb); };
  }, []);

  const setTo = useCallback((t: ZoomTransform, animate = true) => {
    if (!svgRef.current || !zoomRef.current) return;
    const sel = select(svgRef.current);
    const target = animate ? sel.transition().duration(420) : sel;
    target.call(zoomRef.current.transform, t);
  }, []);

  const zoomBy = useCallback((factor: number) => {
    if (!svgRef.current || !zoomRef.current) return;
    select(svgRef.current).transition().duration(220).call(zoomRef.current.scaleBy, factor);
  }, []);

  const reset = useCallback(() => setTo(zoomIdentity, true), [setTo]);

  const zoomToBox = useCallback(
    (box: { x: number; y: number; w: number; h: number }, viewportW: number, viewportH: number, padding = 60) => {
      const k = Math.min(viewportW / (box.w + padding * 2), viewportH / (box.h + padding * 2), maxScale);
      const tx = viewportW / 2 - (box.x + box.w / 2) * k;
      const ty = viewportH / 2 - (box.y + box.h / 2) * k;
      setTo(zoomIdentity.translate(tx, ty).scale(k), true);
    },
    [setTo, maxScale],
  );

  return { svgRef, groupRef, transformRef, subscribe, zoomBy, reset, zoomToBox };
}
