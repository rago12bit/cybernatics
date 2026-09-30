// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AttackPathsScreen } from "../components/AttackPathsScreen";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const SSRF_PATH = {
  id: "ap1",
  likelihood: "high",
  impact: "critical",
  rank_score: 12,
  cheapest_link: "iss_1",
  narrative: "GET /preview reaches the SSRF issue, which exposes the cloud metadata service.",
  nodes: [
    { id: "ep_1", kind: "entrypoint", label: "GET /preview", issue_id: null, detail: "flask" },
    { id: "iss_1", kind: "issue", label: "SSRF", issue_id: "iss1", detail: "" },
    { id: "res_1", kind: "cloud_resource", label: "cloud metadata service", issue_id: null, detail: "" },
  ],
  edges: [
    { kind: "reachable_from", source: "ep_1", target: "iss_1", rule_id: "ssrf-metadata-v1" },
    { kind: "exposes", source: "iss_1", target: "res_1", rule_id: "ssrf-metadata-v1" },
  ],
};

const SECRET_PATH = {
  ...SSRF_PATH,
  id: "ap2",
  likelihood: "medium",
  impact: "low",
  narrative: null,
  nodes: [
    { id: "iss_2", kind: "secret", label: "AWS Access Key ID", issue_id: "iss2", detail: "" },
    { id: "res_2", kind: "cloud_resource", label: "aws_s3_bucket.data", issue_id: "iss3", detail: "main.tf" },
  ],
  cheapest_link: "iss_2",
  edges: [{ kind: "grants_access_to", source: "iss_2", target: "res_2", rule_id: "secret-grants-resource-v1" }],
};

async function mount(assetId = "a1") {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<AttackPathsScreen assetId={assetId} />));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  return host;
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("AttackPathsScreen", () => {
  it("shows an empty state when there are no paths", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json([])));
    const host = await mount();
    expect(host.textContent).toContain("No attack paths found");
  });

  it("shows the first path with its likelihood, impact, nodes, and narrative", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json([SSRF_PATH, SECRET_PATH])));
    const host = await mount();
    const text = host.textContent ?? "";
    expect(text).toContain("Attack path 1 of 2");
    expect(text).toContain("Likelihood: high");
    expect(text).toContain("Impact: critical");
    expect(text).toContain("GET /preview");
    expect(text).toContain("SSRF");
    expect(text).toContain("cloud metadata service");
    expect(text).toContain("reaches the SSRF issue");
    expect(text).toContain("Fix this to break the chain");
  });

  it("Next moves to the second path, which has no narrative", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json([SSRF_PATH, SECRET_PATH])));
    const host = await mount();
    const next = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Next"))!;
    await act(async () => next.click());
    const text = host.textContent ?? "";
    expect(text).toContain("Attack path 2 of 2");
    expect(text).toContain("AWS Access Key ID");
    expect(text).toContain("No narrative available");
  });

  it("Previous is disabled on the first path and Next is disabled on the last", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json([SSRF_PATH])));
    const host = await mount();
    const prev = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Previous"))!;
    const next = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Next"))!;
    expect(prev.disabled).toBe(true);
    expect(next.disabled).toBe(true);
  });
});
