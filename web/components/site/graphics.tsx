// Decorative + explanatory SVG graphics in the blueprint style. Server components; every colour is a
// CSS class (never an inline style) so the strict CSP holds. Data-driven ones take real numbers.
import type { ReactNode } from "react";

function rng(seed: number) {
  let s = seed >>> 0;
  return () => (s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32;
}

const STRIPE_COLORS = ["f-teal", "f-mint", "f-khaki", "f-dark", "f-navy", "f-teal", "f-mint", ""];

/** Vertical striped "equalizer" blocks, like the reference's decorative bars. Deterministic per seed. */
export function Stripes({ seed = 1, groups = 12, rows = 4, className = "" }: { seed?: number; groups?: number; rows?: number; className?: string }) {
  const r = rng(seed);
  const bars: ReactNode[] = [];
  const barsPerGroup = 6, step = 10, groupW = barsPerGroup * step + 14, rowH = 60;
  for (let row = 0; row < rows; row++) {
    for (let g = 0; g < groups; g++) {
      const color = STRIPE_COLORS[Math.floor(r() * STRIPE_COLORS.length)];
      if (!color) continue;
      const h = rowH - 4 - Math.floor(r() * 3) * 6;
      for (let b = 0; b < barsPerGroup; b++) {
        // Static: single bars blinking at random read as a rendering glitch, not as motion.
        bars.push(<rect key={`${row}-${g}-${b}`} className={color} x={g * groupW + b * step} y={row * rowH} width={5} height={h} />);
      }
    }
  }
  return (
    <svg className={`art-svg ${className}`} viewBox={`0 0 ${groups * groupW} ${rows * rowH}`} preserveAspectRatio="xMidYMid slice" role="presentation" aria-hidden="true">
      {bars}
    </svg>
  );
}

const SHAPES: Record<string, [number, number, number, number][]> = {
  a: [[40, 10, 30, 36], [40, 50, 30, 36], [70, 50, 40, 20], [78, 30, 24, 20]],
  b: [[20, 20, 30, 30], [64, 10, 30, 40], [90, 40, 30, 36], [44, 54, 30, 30]],
  c: [[50, 10, 30, 50], [80, 20, 24, 44], [20, 60, 60, 24]],
  d: [[54, 12, 30, 34], [84, 12, 44, 50], [54, 50, 30, 34], [30, 26, 24, 20]],
  e: [[24, 30, 24, 40], [60, 12, 36, 50], [78, 56, 32, 26], [96, 12, 22, 24]],
};

/** Teal outlined blocks on a hairline grid: the reference's feature-cell illustrations. */
export function Blueprint({ shape = "a", uid }: { shape?: keyof typeof SHAPES; uid: string }) {
  return (
    <svg className="art-svg" viewBox="0 0 160 100" role="presentation" aria-hidden="true">
      <defs>
        <pattern id={`bp-${uid}`} width="10" height="10" patternUnits="userSpaceOnUse">
          <path d="M10 0H0V10" className="s-line" strokeWidth="0.5" />
        </pattern>
      </defs>
      <rect width="160" height="100" fill={`url(#bp-${uid})`} />
      {SHAPES[shape]!.map(([x, y, w, h], i) => (
        <rect key={i} className="bp-block" x={x} y={y} width={w} height={h} strokeWidth="1.2" />
      ))}
    </svg>
  );
}

/** Two scanners' reports converging into one merged finding: what the product does. */
export function DedupDiagram() {
  return (
    <svg className="art-svg" viewBox="0 0 560 400" role="img" aria-label="Bandit reports a SQL injection at line 6 and Semgrep at line 7; Bulwark merges them into one finding flagged by 2 of 2 code scanners.">
      <title>Two scanner reports merged into one finding</title>
      <g>
        <rect className="f-wash s-mint" x="30" y="70" width="220" height="92" strokeWidth="1" />
        <text className="t-mono" x="46" y="96" fontSize="11">bandit · B608</text>
        <text className="t-mono t-bright t-nocase" x="46" y="124" fontSize="13">src/users.py:6</text>
        <text className="t-mono" x="46" y="148" fontSize="10">severity MEDIUM</text>

        <rect className="f-wash s-mint" x="30" y="210" width="220" height="92" strokeWidth="1" />
        <text className="t-mono" x="46" y="236" fontSize="11">semgrep · sqlalchemy rule</text>
        <text className="t-mono t-bright t-nocase" x="46" y="264" fontSize="13">src/users.py:7</text>
        <text className="t-mono" x="46" y="288" fontSize="10">severity ERROR</text>
      </g>
      <g className="s-mint" strokeWidth="1">
        <path d="M250 116H290V186H330" />
        <path d="M250 256H290V206H330" />
      </g>
      <rect className="f-mint" x="246" y="112" width="8" height="8" />
      <rect className="f-mint" x="246" y="252" width="8" height="8" />
      <rect className="f-khaki blink" x="286" y="182" width="8" height="8" />
      <g>
        <rect className="f-wash s-teal" x="330" y="110" width="200" height="170" strokeWidth="1.4" />
        <rect className="s-teal" x="336" y="116" width="200" height="170" strokeWidth="0.6" opacity="0.5" />
        <text className="t-mono t-teal" x="348" y="142" fontSize="11">1 finding</text>
        <text className="t-bright" x="348" y="170" fontSize="15" fontFamily="var(--sans)">SQL injection</text>
        <text className="t-mono t-bright t-nocase" x="348" y="194" fontSize="12">src/users.py:7</text>
        <text className="t-mono" x="348" y="218" fontSize="10">HIGH · CWE-89</text>
        <path d="M348 232H514" className="s-line" strokeWidth="1" />
        <text className="t-mono t-teal" x="348" y="254" fontSize="10">flagged by 2 of 2</text>
        <text className="t-mono t-teal" x="348" y="268" fontSize="10">code scanners</text>
      </g>
      <text className="t-mono" x="30" y="372" fontSize="10">62 raw → 38 unique</text>
      <text className="t-mono" x="530" y="372" fontSize="10" textAnchor="end">merged, never dropped</text>
    </svg>
  );
}

/** Dotted-line chart of the dedup rate per repository (real benchmark data). */
export function DedupChart({ repos }: { repos: { name: string; dedup: number }[] }) {
  const W = 520, H = 300, top = 56, bottom = 250, left = 30, right = 500;
  const max = 0.6;
  const xs = repos.map((_, i) => left + ((right - left) * (i + 0.5)) / repos.length);
  const ys = repos.map((r) => bottom - ((bottom - top) * r.dedup) / max);
  const area = `M${xs[0]} ${bottom} ` + xs.map((x, i) => `L${x} ${ys[i]}`).join(" ") + ` L${xs[xs.length - 1]} ${bottom} Z`;
  return (
    <svg className="chart-svg" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={"Deduplication rate per repository: " + repos.map((r) => `${r.name} ${(r.dedup * 100).toFixed(0)}%`).join(", ")}>
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <line key={i} className="s-line" x1={left} x2={right} y1={top + ((bottom - top) * i) / 5} y2={top + ((bottom - top) * i) / 5} strokeWidth="0.5" />
      ))}
      <path d={area} fill="rgba(236,235,228,0.04)" />
      {xs.map((x, i) => (
        <g key={i}>
          <line className="s-text" x1={x} x2={x} y1={top - 14} y2={ys[i]} strokeWidth="2" strokeDasharray="1.5 4" />
          <line className="s-khaki" x1={x} x2={x} y1={ys[i]} y2={bottom} strokeWidth="1.5" />
          <rect className="f-khaki" x={x - 5} y={ys[i]! - 5} width="10" height="10" />
          <text className="t-mono t-bright" x={x + 4} y={top - 22} fontSize="11" transform={`rotate(-90 ${x + 4} ${top - 22})`}>{(repos[i]!.dedup * 100).toFixed(1)}%</text>
          <text className="t-mono" x={x} y={bottom + 22} fontSize="10" textAnchor="middle">{repos[i]!.name}</text>
        </g>
      ))}
    </svg>
  );
}

/** Stepped line with two square nodes (the reference's small chart cells). */
export function StepChart({ seed = 3 }: { seed?: number }) {
  const r = rng(seed);
  const pts: [number, number][] = [[24, 78]];
  let y = 78;
  for (let x = 24; x < 140; x += 30) { y = Math.max(20, y - Math.floor(r() * 3) * 12); pts.push([x + 30, y], [x + 30, y]); }
  const d = "M" + pts.map(([x, yy], i) => (i && i % 2 === 1 ? `L${x} ${pts[i - 1]![1]}` : `L${x} ${yy}`)).join(" ").slice(1);
  return (
    <svg className="art-svg" viewBox="0 0 160 100" role="presentation" aria-hidden="true">
      <defs><pattern id={`sg-${seed}`} width="14" height="14" patternUnits="userSpaceOnUse"><path d="M14 0H0V14" className="s-line" strokeWidth="0.5" /></pattern></defs>
      <rect width="160" height="100" fill={`url(#sg-${seed})`} />
      <path className="s-teal draw" d={d} strokeWidth="1.2" />
      <rect className="f-teal" x={pts[0]![0] - 3} y={pts[0]![1] - 3} width="6" height="6" />
      <rect className="f-teal" x={pts[pts.length - 1]![0] - 3} y={pts[pts.length - 1]![1] - 3} width="6" height="6" />
    </svg>
  );
}

export function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 20 20" aria-hidden="true">
      <rect x="1" y="1" width="18" height="18" className="s-teal" strokeWidth="1.5" />
      <rect x="6" y="6" width="8" height="8" className="f-teal" />
    </svg>
  );
}
