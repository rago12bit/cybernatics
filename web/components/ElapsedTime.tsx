"use client";

import { useEffect, useState } from "react";
import { formatDuration } from "@/lib/format";

/**
 * Ticking "1m 12s since it started" for a still-running scan (plan §28.2's live scan header).
 * Server-rendered as nothing (elapsed time from a `since` in the past is meaningless before
 * hydration) and filled in on mount, then re-rendered once a second -- same hydration-safe shape
 * as LocalTime, just counting instead of formatting a fixed instant.
 */
export function ElapsedTime({ since }: { since: string }) {
  const [seconds, setSeconds] = useState<number | null>(null);
  useEffect(() => {
    const start = Date.parse(since);
    if (Number.isNaN(start)) return;
    const tick = () => setSeconds(Math.max(0, Math.round((Date.now() - start) / 1000)));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [since]);
  if (seconds === null) return null;
  return <span className="elapsed">{formatDuration(seconds)}</span>;
}
