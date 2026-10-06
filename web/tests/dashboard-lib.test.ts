import { describe, expect, it } from "vitest";
import {
  addWidget, describePlace, drillHref, filterParams, moveWidget, pctWithCounts, readingOrder, resizeWidget,
  type Widget,
} from "../lib/dashboard";

const w = (id: string, x: number, y: number, ww = 6, h = 4): Widget => ({ id, metric: "open_issues", x, y, w: ww, h });
const at = (ws: Widget[], id: string) => { const x = ws.find((v) => v.id === id)!; return [x.x, x.y, x.w, x.h]; };

describe("keyboard moves follow the grid's own rules", () => {
  const two = [w("a", 0, 0), w("b", 6, 0), w("c", 0, 4, 12, 4)];
  it("moves right a column at a time and stops at the edge", () => {
    expect(at(moveWidget([w("a", 0, 0)], "a", 1, 0), "a")).toEqual([1, 0, 6, 4]);
    expect(at(moveWidget([w("a", 6, 0)], "a", 1, 0), "a")).toEqual([6, 0, 6, 4]);
    expect(at(moveWidget([w("a", 0, 0)], "a", -1, 0), "a")).toEqual([0, 0, 6, 4]);
  });
  it("moving down past a neighbour swaps the two; up swaps back", () => {
    const stack = [w("a", 0, 0), w("b", 6, 0), w("c", 0, 4)];
    const down = moveWidget(stack, "a", 0, 1);
    expect(at(down, "c")).toEqual([0, 0, 6, 4]);
    expect(at(down, "a")).toEqual([0, 4, 6, 4]);
    expect(at(down, "b")).toEqual([6, 0, 6, 4]);
    const up = moveWidget(down, "a", 0, -1);
    expect(at(up, "a")).toEqual([0, 0, 6, 4]);
    expect(at(up, "c")).toEqual([0, 4, 6, 4]);
  });
  it("a full-width neighbour that can't rise past the other column: the widget goes below it", () => {
    const down = moveWidget(two, "a", 0, 1);
    expect(at(down, "c")).toEqual([0, 4, 12, 4]);
    expect(at(down, "a")).toEqual([0, 8, 6, 4]);
    expect(at(moveWidget(down, "a", 0, -1), "a")[1]).toBeLessThan(8);
  });
  it("down with nothing below changes nothing", () => {
    expect(moveWidget(two, "c", 0, 1)).toEqual(two);
  });
  it("sliding into a neighbour's columns pushes it down", () => {
    const moved = moveWidget([w("a", 0, 0, 4), w("b", 6, 0, 6)], "a", 1, 0);
    expect(at(moved, "a")).toEqual([1, 0, 4, 4]);
    const twice = moveWidget(moveWidget(moved, "a", 1, 0), "a", 1, 0);
    expect(at(twice, "a")[0]).toBe(3);
    const b = at(twice, "b");
    expect(b[1]! >= 4 || b[0]! >= 7).toBe(true); // never overlapping
  });
  it("resizes within the grid, and others make room", () => {
    expect(at(resizeWidget(two, "a", 1, 0), "a")).toEqual([0, 0, 7, 4]);
    const r = resizeWidget(two, "a", 1, 0);
    expect(at(r, "b")[1]).toBeGreaterThanOrEqual(4); // b moved below
    expect(at(resizeWidget([w("a", 0, 0, 2, 2)], "a", -1, -1), "a")).toEqual([0, 0, 2, 2]); // minimum 2x2
    expect(at(resizeWidget([w("a", 6, 0)], "a", 3, 0), "a")[2]).toBe(6); // not past column 12
  });
  it("announces what happened", () => {
    expect(describePlace(w("a", 6, 4))).toBe("Open issues by priority moved to column 7 of 12, row 5, 6 columns wide, 4 rows tall.");
    expect(describePlace(w("a", 0, 0, 7), w("a", 0, 0))).toMatch(/^Open issues by priority resized to 7 columns wide/);
    expect(describePlace(w("a", 6, 0), w("a", 6, 0))).toMatch(/can't go further that way/);
  });
  it("adds at the bottom and reads top-to-bottom, left-to-right", () => {
    const added = addWidget(two, "past_sla", "p");
    expect(at(added, "p")).toEqual([0, 8, 12, 5]);
    expect(readingOrder([w("z", 6, 0), w("y", 0, 4), w("x", 0, 0)]).map((v) => v.id)).toEqual(["x", "z", "y"]);
  });
});

describe("filters and drill-downs", () => {
  it("turns the last N days into from/to ending today", () => {
    const p = filterParams({ days: 30, portfolios: ["p1"], tag: "pci", group: "portfolio" }, new Date("2026-10-06T12:00:00Z"));
    expect(p.toString()).toBe("portfolio=p1&tag=pci&from=2026-09-07&to=2026-10-06&group=portfolio");
  });
  it("links a number to its Issues with the widget's filters", () => {
    const href = drillHref({ kind: "open", band: "P1" }, { projects: ["a"], group: "portfolio" }, "Open P1");
    expect(href).toBe("/app/metrics/issues?project=a&kind=open&band=P1&label=Open+P1");
    expect(drillHref({ kind: "open", portfolio: "none", older_than: 90 })).toBe("/app/metrics/issues?kind=open&in_portfolio=none&older_than=90");
  });
  it("never shows a percentage without its counts", () => {
    expect(pctWithCounts(195, 214)).toBe("91% (195 of 214)");
    expect(pctWithCounts(0, 0)).toBe("No data");
  });
});
