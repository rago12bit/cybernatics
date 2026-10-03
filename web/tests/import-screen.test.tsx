// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ImportScreen } from "../components/ImportScreen";
import type { ImportView } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ASSET = "11111111-1111-4111-8111-111111111111";
const IMPORT = "22222222-2222-4222-8222-222222222222";
const REOPENED = ["aaaaaaaa-0000-4000-8000-000000000001", "aaaaaaaa-0000-4000-8000-000000000002"];
const CLOSED = ["bbbbbbbb-0000-4000-8000-000000000001", "bbbbbbbb-0000-4000-8000-000000000002"];

const PARSERS = [
  { name: "sarif", label: "SARIF 2.1.0", formats: ["json"], categories: ["sast"] },
  { name: "cyclonedx", label: "CycloneDX", formats: ["json", "xml"], categories: ["sca"] },
];

function view(over: Partial<ImportView> = {}): ImportView {
  return {
    id: IMPORT, status: "previewed", mode: "preview", parser: "sarif", file_name: "scan.sarif",
    test_id: "t1", engagement_id: "e1",
    counts: { new: 38, unchanged: 212, reopened: 2, closed: 17, detached: 0 },
    reopened_issue_ids: REOPENED, closed_issue_ids: CLOSED, detached_issue_ids: [],
    ids_truncated: false, warnings: [], error: null, close_missing: true, scope: "test",
    dedup_complete: true, created_at: "2026-10-04T00:00:00Z", reverted_at: null, ...over,
  };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

type Call = { method: string; path: string; form?: FormData };

/** The API as the screen sees it: queued first, then a resting state, like a real worker. */
function api(opts: {
  preview?: ImportView;
  applied?: ImportView;
  ingest?: (form: FormData) => Response | undefined;
  tests?: unknown[];
} = {}) {
  const calls: Call[] = [];
  let polls = 0;
  let confirmed = false;
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const method = init?.method ?? "GET";
    const form = init?.body instanceof FormData ? init.body : undefined;
    calls.push({ method, path, form });
    if (path === "/v2/parsers") return json(PARSERS);
    if (path === `/v2/projects/${ASSET}/tests`) return json(opts.tests ?? []);
    if (path === "/assets") return json([{ id: ASSET, label: "payments-api" }]);
    if (path === "/v2/ingest") {
      const forced = opts.ingest?.(form!);
      if (forced) return forced;
      polls = 0;
      return json({ import_id: IMPORT, status: "queued", parser: form!.get("parser") ?? "sarif",
        confidence: form!.get("parser") ? null : 0.99, test_id: "t1", duplicate: false }, 202);
    }
    if (path === `/v2/imports/${IMPORT}` && method === "GET") {
      polls += 1;
      if (confirmed) {
        return json(opts.applied ?? view({ status: "applied", mode: "apply",
          counts: { new: 38, unchanged: 212, reopened: 2, closed: 17, detached: 0 } }));
      }
      return json(polls < 2 ? view({ status: "queued", counts: null }) : (opts.preview ?? view()));
    }
    if (path === `/v2/imports/${IMPORT}/confirm`) {
      confirmed = true;
      return json(view({ status: "queued", mode: "apply", counts: null }), 202);
    }
    if (path === `/v2/imports/${IMPORT}/cancel`) return json(view({ status: "cancelled" }));
    if (path === `/v2/imports/${IMPORT}/revert`)
      return json({ import_id: IMPORT, status: "reverted", restored: 21, deleted: 38, skipped: 0 });
    return json({}, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

let root: Root | null = null;
const flush = (ms = 40) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<ImportScreen assetId={ASSET} pollMs={5} />));
  await flush();
  return host;
}

async function pickFile(host: HTMLElement, name = "scan.sarif", content = '{"runs":[]}') {
  const input = host.querySelector("#import-file") as HTMLInputElement;
  const file = new File([content], name, { type: "application/json" });
  Object.defineProperty(input, "files", { value: [file], configurable: true });
  await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
  await flush(80);
}

const button = (host: HTMLElement, text: string) =>
  Array.from(host.querySelectorAll("button, a")).find((b) => b.textContent?.trim() === text) as HTMLElement;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

async function violations(el: Element) {
  const r = await axe.run(el, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
  return r.violations.map((v) => `${v.id}: ${v.nodes.slice(0, 2).map((n) => n.target.join(" ")).join(" | ")}`);
}

describe("ImportScreen", () => {
  it("asks for a file first and says nothing is saved until you import", async () => {
    api();
    const host = await mount();
    expect(host.querySelector("#import-file")).not.toBeNull();
    expect(host.textContent).toContain("Nothing is saved until you press Import");
    expect(host.textContent).not.toContain("If you import this file");
  });

  it("uploads for a preview, with the choices as form fields, and never saves on its own", async () => {
    const { calls } = api();
    const host = await mount();
    await pickFile(host);
    const post = calls.find((c) => c.path === "/v2/ingest")!;
    expect(post.method).toBe("POST");
    expect(post.form!.get("project")).toBe(ASSET);
    expect(post.form!.get("preview")).toBe("true");
    expect(post.form!.get("close_missing")).toBe("true");
    expect(post.form!.get("scope")).toBe("test");
    expect((post.form!.get("file") as File).name).toBe("scan.sarif");
    expect(calls.some((c) => c.path.endsWith("/confirm"))).toBe(false); // preview only
  });

  it("shows what was detected, where it goes, and the four counts before anything is saved", async () => {
    const host = await (async () => { api(); return mount(); })();
    await pickFile(host);
    const text = host.textContent!;
    expect(text).toContain("Import results");
    expect(text).toContain("looks like SARIF 2.1.0");
    expect(text).toContain("99% sure");
    expect(text).toContain("payments-api / Imports / SARIF 2.1.0");
    const counts = Array.from(host.querySelectorAll(".ds-import-counts li")).map((li) => li.textContent);
    expect(counts).toEqual(["38 new", "212 unchanged", "2 reopened", "17 closed"]);
    expect(text).toContain("Nothing is saved until you import.");
  });

  it("lists reopened issues by id as links, and the closed ones on request", async () => {
    api();
    const host = await mount();
    await pickFile(host);
    const links = Array.from(host.querySelectorAll("a.ds-import-id")) as HTMLAnchorElement[];
    expect(links.map((a) => a.textContent)).toEqual(REOPENED.map((i) => i.slice(0, 8)));
    expect(links[0]!.getAttribute("href")).toBe(`/app/projects/${ASSET}/issues/${REOPENED[0]}`);
    expect(host.textContent).toContain("17 issues this file no longer reports");
    expect(host.querySelector(".ds-import-ids")).toBeNull();
    await act(async () => button(host, "Show all").click());
    expect(host.querySelectorAll(".ds-import-ids li")).toHaveLength(2);
  });

  it("shows warnings under Check, and issues that stay open because another source reports them", async () => {
    api({ preview: view({ warnings: ["3 finding(s) use the severity 'moderate', which is not a known severity; imported as Info"],
      counts: { new: 1, unchanged: 0, reopened: 0, closed: 0, detached: 4 } }) });
    const host = await mount();
    await pickFile(host);
    expect(host.textContent).toContain("Check");
    expect(host.textContent).toContain("'moderate'");
    expect(host.textContent).toContain("4 more issues are no longer in this file but stay open");
  });

  it("Import file applies that upload and confirms in the same words and numbers", async () => {
    const { calls } = api();
    const host = await mount();
    await pickFile(host);
    await act(async () => button(host, "Import file").click());
    await flush(80);
    expect(calls.some((c) => c.path === `/v2/imports/${IMPORT}/confirm` && c.method === "POST")).toBe(true);
    // The confirmation uses the verb "Imported" and the preview's numbers (unchanged is not repeated).
    expect(host.querySelector(".ds-import-done")!.textContent).toBe("Imported: 38 new, 2 reopened, 17 closed");
    expect(host.textContent).not.toContain("differ from the preview");
    expect(button(host, "Import another file")).toBeTruthy();
  });

  it("says so when the numbers moved between the preview and the import", async () => {
    api({ applied: view({ status: "applied", mode: "apply",
      counts: { new: 40, unchanged: 210, reopened: 2, closed: 17, detached: 0 } }) });
    const host = await mount();
    await pickFile(host);
    await act(async () => button(host, "Import file").click());
    await flush(80);
    expect(host.querySelector(".ds-import-done")!.textContent).toBe("Imported: 40 new, 2 reopened, 17 closed");
    expect(host.textContent).toContain("differ from the preview (38 new, 2 reopened, 17 closed)");
  });

  it("changing 'Close issues missing' re-previews with the new choice and drops the old preview", async () => {
    const { calls } = api();
    const host = await mount();
    await pickFile(host);
    const no = host.querySelector('input[name="import-missing"][value="no"]') as HTMLInputElement;
    await act(async () => no.click());
    await flush(80);
    const posts = calls.filter((c) => c.path === "/v2/ingest");
    expect(posts).toHaveLength(2);
    expect(posts[1]!.form!.get("close_missing")).toBe("false");
    expect(calls.some((c) => c.path.endsWith("/cancel"))).toBe(true); // the first preview is discarded
    const eng = host.querySelector('input[name="import-missing"][value="engagement"]') as HTMLInputElement;
    await act(async () => eng.click());
    await flush(80);
    const last = calls.filter((c) => c.path === "/v2/ingest").at(-1)!;
    expect([last.form!.get("close_missing"), last.form!.get("scope")]).toEqual(["true", "engagement"]);
  });

  it("changing where it goes sends the test and a new assessment's name", async () => {
    const { calls } = api({ tests: [{ id: "t9", name: "Nessus export", parser: "sarif", engagement_id: "e1",
      engagement_name: "payments-api imports", engagement_type: "import", last_import: null }] });
    const host = await mount();
    await pickFile(host);
    const changeInto = Array.from(host.querySelectorAll("dd button")).find((b) => b.textContent === "Change" &&
      b.closest("div")?.textContent?.startsWith("Into")) as HTMLElement;
    await act(async () => changeInto.click());
    const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
    const typeInto = async (el: HTMLInputElement, v: string) =>
      act(async () => { setValue.call(el, v); el.dispatchEvent(new Event("input", { bubbles: true })); });
    await typeInto(host.querySelector("#import-test-name") as HTMLInputElement, "Nessus export");
    expect(host.querySelectorAll("#import-test-options option")).toHaveLength(1); // existing Tests offered
    await act(async () => (host.querySelector('input[name="import-engagement"]:not(:checked)') as HTMLElement).click());
    expect((button(host, "Update preview") as HTMLButtonElement).disabled).toBe(true); // a name is required
    await typeInto(host.querySelector("#import-engagement-name") as HTMLInputElement, "Q3 pentest");
    await act(async () => button(host, "Update preview").click());
    await flush(80);
    const last = calls.filter((c) => c.path === "/v2/ingest").at(-1)!;
    expect(last.form!.get("test")).toBe("Nessus export");
    expect(last.form!.get("engagement_type")).toBe("assessment");
    expect(last.form!.get("engagement_name")).toBe("Q3 pentest");
    expect(host.textContent).toContain("payments-api / Q3 pentest / Nessus export");
  });

  it("below the confidence threshold it asks for the format before showing any counts", async () => {
    const { calls } = api({
      ingest: (form) =>
        form.get("parser")
          ? undefined
          : json({ detail: { message: "could not identify the file's format with confidence; pass `parser`",
              detected: [{ parser: "cyclonedx", confidence: 0.62 }], available: ["cyclonedx", "sarif"] } }, 422),
    });
    const host = await mount();
    await pickFile(host, "mystery.json");
    expect(host.textContent).toContain("Which kind of file is this?");
    expect(host.textContent).toContain("Closest match: CycloneDX (62%)");
    expect(host.querySelector(".ds-import-counts")).toBeNull(); // no counts until it is confirmed
    expect((button(host, "Use this format") as HTMLButtonElement).disabled).toBe(true);
    const select = host.querySelector("#import-format") as HTMLSelectElement;
    await act(async () => {
      select.value = "cyclonedx";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await act(async () => button(host, "Use this format").click());
    await flush(80);
    expect(calls.filter((c) => c.path === "/v2/ingest").at(-1)!.form!.get("parser")).toBe("cyclonedx");
    expect(host.querySelector(".ds-import-counts")).not.toBeNull();
  });

  it("a file that cannot be read shows why, offers another file, and shows no counts", async () => {
    api({ preview: view({ status: "failed", counts: null,
      error: "not a valid SARIF 2.1.0 file (ValueError: not valid JSON (premature EOF))" }) });
    const host = await mount();
    await pickFile(host);
    const alert = host.querySelector('[role="alert"]')!;
    expect(alert.textContent).toContain("not valid JSON");
    expect(host.querySelector("#import-file")).not.toBeNull();
    expect(host.querySelector(".ds-import-counts")).toBeNull();
  });

  it("an API refusal (such as a file that is too large) is shown, not swallowed", async () => {
    api({ ingest: () => json({ detail: "the file exceeds the maximum upload size" }, 413) });
    const host = await mount();
    await pickFile(host);
    expect(host.querySelector('[role="alert"]')!.textContent).toContain("exceeds the maximum upload size");
  });

  it("Cancel discards the preview and returns to choosing a file", async () => {
    const { calls } = api();
    const host = await mount();
    await pickFile(host);
    await act(async () => button(host, "Cancel").click());
    await flush();
    expect(calls.some((c) => c.path === `/v2/imports/${IMPORT}/cancel` && c.method === "POST")).toBe(true);
    expect(host.querySelector("#import-file")).not.toBeNull();
    expect(host.querySelector(".ds-import-counts")).toBeNull();
  });

  it("Undo this import calls revert and reports what was restored", async () => {
    const { calls } = api();
    const host = await mount();
    await pickFile(host);
    await act(async () => button(host, "Import file").click());
    await flush(80);
    await act(async () => button(host, "Undo this import").click());
    await flush();
    expect(calls.some((c) => c.path === `/v2/imports/${IMPORT}/revert` && c.method === "POST")).toBe(true);
    expect(host.textContent).toContain("Import undone: 21 issue(s) restored");
    expect(button(host, "Undo this import")).toBeUndefined();
  });

  it("is accessible in each state (axe)", async () => {
    api({
      ingest: (form) =>
        form.get("parser") ? undefined : json({ detail: { message: "m", detected: [], available: ["sarif"] } }, 422),
    });
    let host = await mount();
    expect(await violations(host)).toEqual([]); // picking a file
    await pickFile(host);
    expect(await violations(host)).toEqual([]); // choosing a format
    await act(async () => root?.unmount());
    api({ preview: view({ warnings: ["w"], counts: { new: 1, unchanged: 1, reopened: 1, closed: 1, detached: 1 } }) });
    host = await mount();
    await pickFile(host);
    await act(async () => button(host, "Show all").click());
    expect(await violations(host)).toEqual([]); // the results, expanded
  });
});
