import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Landing } from "../components/site/Landing";
import { BENCHMARK } from "../lib/benchmark";

describe("landing page", () => {
  const html = renderToStaticMarkup(<Landing />);

  it("emits no inline styles or scripts (the strict CSP would block them)", () => {
    expect(html).not.toMatch(/\sstyle=/i);
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/\son\w+\s*=/i);
  });

  it("shows the measured benchmark numbers, not invented ones", () => {
    expect(html).toContain(`${(BENCHMARK.dedupRate * 100).toFixed(1)}%`);
    expect(html).toContain(BENCHMARK.raw.toLocaleString("en-US"));
    expect(html).toContain(BENCHMARK.unique.toLocaleString("en-US"));
    for (const r of BENCHMARK.repos) expect(html).toContain((r.dedup * 100).toFixed(1) + "%");
  });

  it("benchmark data is internally consistent", () => {
    expect(BENCHMARK.rawPerScanner.reduce((n, s) => n + s.raw, 0)).toBe(BENCHMARK.raw);
    expect(BENCHMARK.repos.reduce((n, r) => n + r.raw, 0)).toBe(BENCHMARK.raw);
    expect(BENCHMARK.repos.reduce((n, r) => n + r.unique, 0)).toBe(BENCHMARK.unique);
    expect(1 - BENCHMARK.unique / BENCHMARK.raw).toBeCloseTo(BENCHMARK.dedupRate, 3);
  });

  it("lists shipped v1.0 features under 'ships today', not 'Roadmap'", () => {
    const shipped = html.split("What ships today")[1]!.split("Roadmap")[0]!;
    const roadmap = html.split("Roadmap")[1]!;
    for (const done of ["EPSS", "KEV", "VS Code", "GitHub Action", "SBOM"]) {
      expect(shipped).toContain(done);
      expect(roadmap).not.toContain(done);
    }
  });
});
