// Unmount every React root a test created, after each test. Most tests mount with createRoot and
// only clear document.body afterwards, which leaves the root alive with work still scheduled: once
// in CI (Oct 2026) React's scheduler ran after a11y.test.tsx's jsdom had been torn down and failed
// the whole run with "window is not defined", every test having passed.
import { act } from "react";
import type { Root } from "react-dom/client";
import { afterEach, vi } from "vitest";

const roots = new Set<Root>();

vi.mock("react-dom/client", async (importOriginal) => {
  const mod = await importOriginal<typeof import("react-dom/client")>();
  return {
    ...mod,
    createRoot: (...args: Parameters<typeof mod.createRoot>) => {
      const root = mod.createRoot(...args);
      roots.add(root);
      return root;
    },
  };
});

afterEach(() => {
  for (const root of roots) act(() => root.unmount()); // a no-op for a root the test unmounted itself
  roots.clear();
});
