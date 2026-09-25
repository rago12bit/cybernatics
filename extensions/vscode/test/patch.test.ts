import { describe, expect, it } from "vitest";
import { parseHunks, planEdits } from "../src/patch";

const doc = ["import subprocess", "def run(cmd):", "    subprocess.call(cmd, shell=True)", "    return 1"];
const diff = (body: string, path = "app.py") => `--- a/${path}\n+++ b/${path}\n${body}`;
const oneLine = diff("@@ -3,1 +3,1 @@\n-    subprocess.call(cmd, shell=True)\n+    subprocess.call(cmd, shell=False)\n");

describe("planEdits", () => {
  it("plans an edit when the removed line matches", () => {
    expect(planEdits(doc, oneLine, "app.py")).toEqual([{ startLine: 2, oldCount: 1, newLines: ["    subprocess.call(cmd, shell=False)"] }]);
  });
  it("includes context lines in the match", () => {
    const p = diff("@@ -2,3 +2,3 @@\n def run(cmd):\n-    subprocess.call(cmd, shell=True)\n+    subprocess.call(cmd, shell=False)\n     return 1\n");
    expect(planEdits(doc, p, "app.py")?.[0]).toMatchObject({ startLine: 1, oldCount: 3 });
  });
  it("refuses when the file changed since the scan", () => {
    const edited = [...doc];
    edited[2] = "    subprocess.call(cmd, shell=True)  # edited";
    expect(planEdits(edited, oneLine, "app.py")).toBeNull();
  });
  it("finds a hunk that moved a few lines", () => {
    expect(planEdits(["# new", "# new", ...doc], oneLine, "app.py")?.[0]?.startLine).toBe(4);
  });
  it("refuses an ambiguous match", () => {
    const twice = ["x", "    subprocess.call(cmd, shell=True)", "y", "    subprocess.call(cmd, shell=True)", "z"];
    expect(planEdits(twice, diff("@@ -3,1 +3,1 @@\n-    subprocess.call(cmd, shell=True)\n+    a\n"), "app.py")).toBeNull();
  });
  it("refuses a hunk too far away", () => {
    expect(planEdits([...Array(30).fill("x"), ...doc], oneLine, "app.py")).toBeNull();
  });
  it("refuses a patch for another file", () => {
    expect(planEdits(doc, diff("@@ -3,1 +3,1 @@\n-a\n+b\n", "other.py"), "app.py")).toBeNull();
    expect(planEdits(doc, "--- a/app.py\n+++ b/evil.py\n@@ -3,1 +3,1 @@\n-a\n+b\n", "app.py")).toBeNull();
  });
  it.each([
    ["no hunks", "--- a/app.py\n+++ b/app.py\n"],
    ["not a diff", "just text"],
    ["garbage line", diff("@@ -1,1 +1,1 @@\n?what\n")],
    ["no-op", diff("@@ -3,1 +3,1 @@\n-    subprocess.call(cmd, shell=True)\n+    subprocess.call(cmd, shell=True)\n")],
    ["pure addition", diff("@@ -3,0 +3,1 @@\n+new\n")],
  ])("refuses %s", (_n, p) => expect(planEdits(doc, p, "app.py")).toBeNull());
  it("refuses overlapping hunks and applies two separate ones", () => {
    const two = diff("@@ -1,1 +1,1 @@\n-import subprocess\n+import subprocess, os\n@@ -3,1 +3,1 @@\n-    subprocess.call(cmd, shell=True)\n+    x\n");
    expect(planEdits(doc, two, "app.py")).toHaveLength(2);
    const overlap = diff("@@ -3,1 +3,1 @@\n-    subprocess.call(cmd, shell=True)\n+    x\n@@ -3,1 +3,1 @@\n-    subprocess.call(cmd, shell=True)\n+    y\n");
    expect(planEdits(doc, overlap, "app.py")).toBeNull();
  });
  it("caps the number of hunks", () => {
    const many = diff(Array.from({ length: 25 }, (_, i) => `@@ -${i + 1},1 +${i + 1},1 @@\n-a${i}\n+b${i}\n`).join(""));
    expect(parseHunks(many, "app.py")).toBeNull();
  });
  it("tolerates CRLF patches", () => {
    expect(planEdits(doc, oneLine.replace(/\n/g, "\r\n"), "app.py")).toHaveLength(1);
  });
});
