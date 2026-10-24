// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConfirmButton } from "../design-system/primitives/ConfirmButton";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
afterEach(() => { act(() => root?.unmount()); root = null; document.body.replaceChildren(); });

async function mount(onConfirm: () => void) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(
    <ConfirmButton className="idn-link" aria-label="Revoke CI" title="Revoke the token CI?" description="CI stops working." confirmLabel="Revoke" onConfirm={onConfirm}>Revoke</ConfirmButton>,
  ));
  return host;
}
const inDialog = (text: string) =>
  [...document.querySelectorAll<HTMLButtonElement>("[role=dialog] button")].find((b) => b.textContent === text)!;

describe("ConfirmButton", () => {
  it("asks first, and does nothing when cancelled", async () => {
    const onConfirm = vi.fn();
    const host = await mount(onConfirm);
    const trigger = host.querySelector("button")!;
    expect(trigger.className).toContain("idn-link");
    await act(async () => trigger.click());
    const dialog = document.querySelector("[role=dialog]")!;
    expect(dialog.textContent).toContain("Revoke the token CI?");
    expect(dialog.textContent).toContain("CI stops working.");
    expect(onConfirm).not.toHaveBeenCalled();
    await act(async () => inDialog("Cancel").click());
    expect(document.querySelector("[role=dialog]")).toBeNull();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("runs the action from the dialog's own button, then closes", async () => {
    const onConfirm = vi.fn();
    const host = await mount(onConfirm);
    await act(async () => host.querySelector("button")!.click());
    await act(async () => inDialog("Revoke").click());
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(document.querySelector("[role=dialog]")).toBeNull();
  });
});
