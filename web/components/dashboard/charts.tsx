"use client";

import Link from "next/link";
import type { ReactElement } from "react";
import type { Chart } from "@/lib/dashboard-present";

/* Small charts drawn by hand (no chart library): bars are a list of links, so every bar opens the
 * Issues behind it; columns and lines are one SVG each, summarised in words for screen readers,
 * with the full numbers one click away under View as table. */

export function chartSummary(c: Chart): string {
  if (c.kind === "bars") {
    if (!c.items.length) return `${c.label}: nothing to show.`;
    return `${c.label}: ${c.items.map((i) => `${i.label} ${i.text}`).join(", ")}.`;
  }
  if (c.kind === "line") {
    const vals = c.items.filter((i) => i.value !== null) as { label: string; value: number }[];
    if (!vals.length) return `${c.label}: no data.`;
    const first = vals[0]!;
    const last = vals[vals.length - 1]!;
    const hi = vals.reduce((a, b) => (b.value > a.value ? b : a));
    const lo = vals.reduce((a, b) => (b.value < a.value ? b : a));
    const u = c.unit;
    return `${c.label}: ${first.value}${u} in the week of ${first.label}, ${last.value}${u} in the week of ${last.label}; highest ${hi.value}${u}, lowest ${lo.value}${u}.`;
  }
  const totals = c.keys.map((k, i) => `${c.items.reduce((s, it) => s + (it.values[i] ?? 0), 0)} ${k.toLowerCase()}`);
  return `${c.label}, over ${c.items.length} weeks: ${totals.join(", ")} in all.`;
}

function Bars({ c }: { c: Extract<Chart, { kind: "bars" }> }) {
  const max = Math.max(1, ...c.items.map((i) => i.value));
  return (
    <ul className="dash-bars" aria-label={c.label}>
      {c.items.map((i) => {
        const inner = (
          <>
            <span className="dash-bar-label">{i.label}</span>
            <span className="dash-bar-track" aria-hidden="true">
              <span className="dash-bar-fill" style={{ width: `${Math.max(2, (i.value / max) * 100)}%` }} />
            </span>
            <span className="dash-bar-value">{i.text}</span>
          </>
        );
        return (
          <li key={i.label}>
            {i.href ? (
              <Link href={i.href} className="dash-bar" aria-label={`${i.label}: ${i.text}. Show these issues`}>
                {inner}
              </Link>
            ) : (
              <span className="dash-bar">{inner}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

const W = 300;
const H = 90;

function Line({ c }: { c: Extract<Chart, { kind: "line" }> }) {
  const vals = c.items.map((i) => i.value);
  const max = Math.max(1, ...vals.map((v) => v ?? 0));
  const step = c.items.length > 1 ? W / (c.items.length - 1) : W;
  const segments: string[][] = [[]];
  vals.forEach((v, i) => {
    if (v === null) segments.push([]);
    else segments[segments.length - 1]!.push(`${(i * step).toFixed(1)},${(H - (v / max) * (H - 6) - 3).toFixed(1)}`);
  });
  return (
    <svg className="dash-chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={chartSummary(c)}>
      <line x1="0" y1={H - 1} x2={W} y2={H - 1} className="dash-axis" />
      {segments.filter((s) => s.length).map((s, i) =>
        s.length === 1 ? (
          <circle key={i} cx={s[0]!.split(",")[0]} cy={s[0]!.split(",")[1]} r="3" className="dash-dot" />
        ) : (
          <polyline key={i} points={s.join(" ")} className="dash-line" vectorEffect="non-scaling-stroke" />
        ),
      )}
    </svg>
  );
}

function Columns({ c }: { c: Extract<Chart, { kind: "columns" }> }) {
  const max = Math.max(1, ...c.items.flatMap((i) => i.values));
  const slot = W / Math.max(1, c.items.length);
  const bar = Math.max(1, (slot - 2) / c.keys.length);
  return (
    <figure className="dash-figure">
      <svg className="dash-chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={chartSummary(c)}>
        <line x1="0" y1={H - 1} x2={W} y2={H - 1} className="dash-axis" />
        {c.items.map((it, i) =>
          it.values.map((v, k) => {
            const h = (v / max) * (H - 4);
            return <rect key={`${i}-${k}`} x={i * slot + 1 + k * bar} y={H - 1 - h} width={bar} height={h} className={`dash-series-${k}`} />;
          }),
        )}
      </svg>
      <figcaption className="dash-legend">
        {c.keys.map((k, i) => (
          <span key={k}>
            <span className={`dash-swatch dash-series-${i}`} aria-hidden="true" /> {k}
          </span>
        ))}
      </figcaption>
    </figure>
  );
}

export function ChartView({ c }: { c: Chart }): ReactElement {
  if (c.kind === "bars") return <Bars c={c} />;
  if (c.kind === "line") return <Line c={c} />;
  return <Columns c={c} />;
}
