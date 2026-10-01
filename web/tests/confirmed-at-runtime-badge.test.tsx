// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";
import { ConfirmedAtRuntimeBadge } from "../components/Badges";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

async function mount(issue: Parameters<typeof ConfirmedAtRuntimeBadge>[0]["issue"]) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<ConfirmedAtRuntimeBadge issue={issue} />));
  return host;
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.innerHTML = "";
});

describe("ConfirmedAtRuntimeBadge", () => {
  it("renders nothing when the issue has no runtime confirmation", async () => {
    const host = await mount({ id: "i1", state: "open" });
    expect(host.textContent).toBe("");
  });

  it("renders nothing when there is no issue at all", async () => {
    const host = await mount(null);
    expect(host.textContent).toBe("");
  });

  it("shows the badge once confirmed_at_runtime_at is set", async () => {
    const host = await mount({
      id: "i1", state: "open", confirmed_at_runtime_at: "2026-10-01T00:00:00Z",
    });
    expect(host.textContent).toContain("Confirmed at runtime");
  });
});
