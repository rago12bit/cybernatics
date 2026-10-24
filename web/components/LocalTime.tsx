"use client";

import { useEffect, useState } from "react";
import { formatDateTime } from "@/lib/format";

const stable = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
};

/**
 * Renders a timestamp without hydration mismatches. Server and first client render both use the same
 * locale-independent UTC string; after mount it switches to the viewer's own locale and timezone.
 */
export function LocalTime({ iso, className }: { iso: string; className?: string }) {
  const [text, setText] = useState(() => stable(iso));
  useEffect(() => {
    const d = new Date(iso);
    if (!Number.isNaN(d.getTime())) setText(formatDateTime(d));
  }, [iso]);
  return <time dateTime={iso} className={className}>{text}</time>;
}
