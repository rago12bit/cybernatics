import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { DemoReport } from "../components/DemoReport";
import { LocalTime } from "../components/LocalTime";

// Hydration mismatches come from output that differs between server and browser (locale, timezone, Date.now).
describe("server-rendered output is deterministic", () => {
  it("timestamps render as a stable UTC string on the server", () => {
    const html = renderToStaticMarkup(<LocalTime iso="2026-09-25T18:30:35Z" />);
    expect(html).toContain("2026-09-25 18:30 UTC");
    expect(html).toContain('dateTime="2026-09-25T18:30:35Z"');
  });
  it("an invalid timestamp renders empty instead of 'Invalid Date'", () => {
    expect(renderToStaticMarkup(<LocalTime iso="nope" />)).not.toContain("Invalid");
  });
  it("the demo page markup is identical regardless of process locale/timezone", () => {
    const a = renderToStaticMarkup(<DemoReport />);
    const b = renderToStaticMarkup(<DemoReport />);
    expect(a).toBe(b);
    expect(a).not.toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/); // no locale-formatted dates like 9/25/2026
  });
});
