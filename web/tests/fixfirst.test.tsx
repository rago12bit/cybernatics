// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FixFirst } from "../components/FixFirst";
import { FindingDetail } from "../components/FindingDetail";
import type { Finding, FindingsPage } from "../lib/types";
import demo from "../lib/demo-data.json";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const all = demo.findings as unknown as Finding[];

const page = (items: Finding[]): FindingsPage => ({ total: items.length, limit: 10, offset: 0, items });
async function mount(node: React.ReactNode) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  const root = createRoot(host);
  await act(async () => root.render(node));
  await act(async () => { await Promise.resolve(); });
  return host;
}
const withRisk = (f: Finding, risk: number, extra: Partial<Finding["scoring"]> = {}): Finding => ({ ...f, scoring: { ...f.scoring, risk_score: risk, ...extra } });
afterEach(() => { document.body.innerHTML = ""; });

describe("Fix these first", () => {
  it("asks the API for the top 10 by risk, unfiltered, and shows rank, score and exploit signals", async () => {
    const items = [withRisk(all[0]!, 98, { in_cisa_kev: true, epss_score: 0.94 }), withRisk(all[1]!, 80, { epss_score: 0.31 }), withRisk(all[2]!, 40, { epss_score: 0.01 })];
    const fetchFindings = vi.fn(async () => page(items));
    const host = await mount(<FixFirst scanId="s1" version={0} fetchFindings={fetchFindings} onOpen={() => undefined} />);
    expect(fetchFindings).toHaveBeenCalledWith("s1", expect.objectContaining({ sort: "risk", severity: [], category: "", tool: "", path: "" }), 10);
    expect([...host.querySelectorAll(".rank")].map((n) => n.textContent)).toEqual(["1", "2", "3"]);
    expect(host.querySelector(".tag.kev")?.textContent).toBe("KEV");
    expect(host.textContent).toContain("EPSS 31%");
    expect(host.textContent).not.toContain("EPSS 1%"); // low EPSS is noise, not shown
    expect(host.querySelector("h2")?.textContent).toContain("Top 3");
  });

  it("renders nothing for scans without risk scores (older scans) or without findings", async () => {
    const old = all.map((f) => withRisk(f, 0)).map((f) => ({ ...f, scoring: { ...f.scoring, risk_score: null } }));
    expect((await mount(<FixFirst scanId="s" version={0} fetchFindings={async () => page(old.slice(0, 3))} onOpen={() => undefined} />)).innerHTML).toBe("");
    expect((await mount(<FixFirst scanId="s" version={0} fetchFindings={async () => page([])} onOpen={() => undefined} />)).innerHTML).toBe("");
    expect((await mount(<FixFirst scanId="s" version={0} fetchFindings={async () => { throw new Error("x"); }} onOpen={() => undefined} />)).innerHTML).toBe("");
  });

  it("opens the finding when a title is clicked", async () => {
    const onOpen = vi.fn();
    const f = withRisk(all[0]!, 70);
    const host = await mount(<FixFirst scanId="s" version={0} fetchFindings={async () => page([f])} onOpen={onOpen} />);
    await act(async () => host.querySelector<HTMLButtonElement>("button.row-title")!.click());
    expect(onOpen).toHaveBeenCalledWith(f, expect.any(HTMLElement));
  });

  it("renders hostile scanner text as text, and passes axe", async () => {
    const evil = withRisk({ ...all[0]!, title: "<img src=x onerror=alert(1)>" }, 60, { risk_factors: ["<script>alert(1)</script>"] });
    const host = await mount(<><FixFirst scanId="s" version={0} fetchFindings={async () => page([evil])} onOpen={() => undefined} /><FindingDetail finding={evil} scan={null} onClose={() => undefined} /></>);
    expect(host.querySelector("img, script")).toBeNull();
    expect(host.textContent).toContain("<script>alert(1)</script>"); // shown literally in the why-panel
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });

  it("the detail panel explains the score, and tolerates findings from before risk scoring", async () => {
    const f = withRisk(all[0]!, 91, { in_cisa_kev: true, risk_factors: ["CVSS 9.8", "In CISA KEV: exploited in the wild"] });
    const host = await mount(<FindingDetail finding={f} scan={null} onClose={() => undefined} />);
    expect(host.querySelector(".why")?.textContent).toContain("In CISA KEV");
    const legacy = { ...all[0]!, scoring: { ...all[0]!.scoring, risk_score: null, risk_factors: undefined } } as Finding;
    expect((await mount(<FindingDetail finding={legacy} scan={null} onClose={() => undefined} />)).querySelector(".why")).toBeNull();
  });
});
