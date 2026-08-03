import { useEffect, useRef, useState } from "react";

interface VirtualRowsOptions {
  /** Total number of rows. */
  count: number;
  /** Fixed height of every row, in px. */
  rowHeight: number;
  /** Extra rows rendered above/below the viewport to mask fast scrolling. */
  overscan?: number;
}

interface VirtualRowsResult {
  /** Attach to the scrollable container. */
  scrollRef: React.RefObject<HTMLDivElement>;
  /** First row index to render (inclusive). */
  startIndex: number;
  /** Last row index to render (exclusive). */
  endIndex: number;
  /** Height of the full virtual list — keeps the scrollbar honest. */
  totalHeight: number;
  /** Pixel offset of the first rendered row. */
  offsetTop: number;
}

/**
 * Minimal fixed-height row virtualization — renders only the rows in view so
 * the browser stays smooth with thousands of files. No external dependency.
 */
export function useVirtualRows({
  count,
  rowHeight,
  overscan = 6,
}: VirtualRowsOptions): VirtualRowsResult {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(0);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const onScroll = () => setScrollTop(el.scrollTop);
    const ro = new ResizeObserver(() => setViewport(el.clientHeight));
    el.addEventListener("scroll", onScroll, { passive: true });
    ro.observe(el);
    setViewport(el.clientHeight);
    return () => {
      el.removeEventListener("scroll", onScroll);
      ro.disconnect();
    };
  }, []);

  const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const endIndex = Math.min(
    count,
    Math.ceil((scrollTop + viewport) / rowHeight) + overscan,
  );

  return {
    scrollRef,
    startIndex,
    endIndex,
    totalHeight: count * rowHeight,
    offsetTop: startIndex * rowHeight,
  };
}
