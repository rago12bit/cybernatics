import { describe, expect, it } from "vitest";
import { errorMessage } from "../lib/api";

describe("what a failed request says", () => {
  it("uses the API's own words when it sent some", () => {
    expect(errorMessage(409, { detail: "Sign in as yourself first." })).toBe("Sign in as yourself first.");
    expect(errorMessage(422, { detail: { message: "Pick a format.", candidates: [] } })).toBe("Pick a format.");
  });

  it("names the field a validation error is about, not just the status", () => {
    const body = { detail: [{ type: "missing", loc: ["query", "kind"], msg: "Field required", input: null }] };
    expect(errorMessage(422, body)).toBe("Some of what was sent was not valid. kind: Field required");
  });

  it("says something useful when there is no message at all (HTTP/2 has no status text)", () => {
    expect(errorMessage(403, null)).toBe("You do not have access to this.");
    expect(errorMessage(503, null)).toBe("The server ran into a problem. Try again in a moment.");
    expect(errorMessage(418, {})).toBe("The request failed (HTTP 418).");
    expect(errorMessage(404, { detail: "" })).toBe("Not found. It may have been removed.");
  });
});
