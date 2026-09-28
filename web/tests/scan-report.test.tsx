// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";
import { ScanReport } from "../components/ScanReport";
import type { ScanView } from "../lib/types";
import demo from "../lib/demo-data.json";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const base = demo.scan as unknown as ScanView;
let root: Root | null = null;

async function mount(scan: ScanView) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<ScanReport scan={scan} connection="live" version={0} />));
  return host;
}
afterEach(async () => { await act(async () => root?.unmount()); root = null; document.body.innerHTML = ""; });

describe("live scan screen (plan §28.2)", () => {
  it("shows elapsed time and a raw, not-yet-deduplicated progress count while running, never the finished summary", async () => {
    const running: ScanView = {
      ...base,
      status: "running",
      finished_at: null,
      tool_status: {
        bandit: { status: "ok", findings: 6, exit_code: 0, duration_seconds: 2.4, error: null, raw_artifact: "withheld" },
        semgrep: { status: "ok", findings: 4, exit_code: 0, duration_seconds: 31.8, error: null, raw_artifact: "withheld" },
      },
    };
    const host = await mount(running);
    expect(host.textContent).toContain("2 of 5 scanners reported in, 10 raw findings so far");
    expect(host.textContent).toContain("aren't merged yet");
    // The finished summary (deduplicated "Unique findings") must not appear mid-scan.
    expect(host.textContent).not.toContain("Unique findings");
    expect(host.querySelector(".elapsed")).not.toBeNull();
  });

  it("names the scanner that failed and offers a new scan, not a generic message", async () => {
    const partial: ScanView = {
      ...base,
      status: "partial",
      tool_status: {
        ...base.tool_status,
        trivy: { status: "timeout", findings: 0, exit_code: null, duration_seconds: 900, error: "wall-clock timeout", raw_artifact: null },
      },
    };
    const host = await mount(partial);
    expect(host.textContent).toContain("trivy timed out, so its results may be incomplete.");
    expect(host.textContent).toContain("The other scanners finished.");
    const links = [...host.querySelectorAll<HTMLAnchorElement>("a[href='/app']")];
    expect(links.some((a) => a.textContent?.includes("Start a new scan"))).toBe(true);
  });

  it("shows no elapsed time or in-progress banner once the scan is done", async () => {
    const host = await mount(base); // base is "completed"
    expect(host.querySelector(".elapsed")).toBeNull();
    expect(host.textContent).not.toContain("reported in");
    expect(host.textContent).not.toContain("aren't merged yet");
    expect(host.textContent).toContain("Unique findings");
  });
});
