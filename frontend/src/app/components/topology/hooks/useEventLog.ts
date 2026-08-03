import { useEffect, useRef, useState } from "react";
import { SAMPLE_EVENTS, type SampleEvent } from "../lib/topology";

export interface LogRow extends SampleEvent { id: number; ts: string; }

const pad = (n: number) => (n < 10 ? `0${n}` : `${n}`);
const tnow = () => {
  const d = new Date();
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
};

export function useEventLog(intervalMs = 1800) {
  const [rows, setRows] = useState<LogRow[]>([]);
  const [count, setCount] = useState(128);
  const idRef = useRef(0);
  const flashRef = useRef(0);
  const [flashTick, setFlashTick] = useState(0);

  useEffect(() => {
    const seed: LogRow[] = [];
    for (let i = 0; i < 6; i++) {
      const e = SAMPLE_EVENTS[(SAMPLE_EVENTS.length - 1 - i) % SAMPLE_EVENTS.length];
      seed.unshift({ ...e, id: idRef.current++, ts: tnow() });
    }
    setRows(seed);

    const t = setInterval(() => {
      const e = SAMPLE_EVENTS[Math.floor(Math.random() * SAMPLE_EVENTS.length)];
      setRows((prev) => {
        const next = [{ ...e, id: idRef.current++, ts: tnow() }, ...prev];
        return next.slice(0, 40);
      });
      setCount((c) => c + 1);
      if (e.lvl === "ERR") {
        flashRef.current++;
        setFlashTick(flashRef.current);
      }
    }, intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);

  return { rows, count, flashTick };
}
