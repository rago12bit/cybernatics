// @vitest-environment jsdom
// The app header's More menu: every page it lists exists, each says what is there, and it opens
// as grouped, labelled sections with the current page marked.
import { existsSync } from "node:fs";
import { join } from "node:path";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MORE_GROUPS, MORE_LINKS, MoreMenu } from "../components/site/AppNav";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe("the More menu's pages", () => {
  it("lists only pages that exist, once each, each with a line saying what is there", () => {
    const hrefs = MORE_LINKS.map((l) => l.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
    for (const href of hrefs) expect(existsSync(join(__dirname, "..", "app", ...href.split("/").filter(Boolean), "page.tsx")), href).toBe(true);
    for (const g of MORE_GROUPS) for (const l of g.links) expect(l.hint.length, l.label).toBeGreaterThan(8);
  });
});

let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
});

describe("opening it", () => {
  it("shows the groups with their labels, marks the current page, and turns the chevron", async () => {
    await act(async () => root.render(<MoreMenu path="/app/costs/2026" />));
    const trigger = host.querySelector<HTMLButtonElement>(".nav-more")!;
    expect(trigger.dataset.current).toBe("true"); // a More page is open, so More is underlined
    await act(async () => { trigger.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })); });
    expect(trigger.getAttribute("data-state")).toBe("open");
    const menu = document.querySelector(".nav-more-menu")!;
    const groups = [...menu.querySelectorAll("[role=group]")];
    expect(groups.map((g) => document.getElementById(g.getAttribute("aria-labelledby")!)?.textContent)).toEqual(["Work", "Inventory", "Set up"]);
    const current = [...menu.querySelectorAll("a[aria-current=page]")];
    expect(current.map((a) => a.querySelector(".t")?.textContent)).toEqual(["Costs"]);
    expect(menu.querySelectorAll("[role=menuitem]")).toHaveLength(MORE_LINKS.length);
  });
});
