import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: { "@": fileURLToPath(new URL(".", import.meta.url)) } },
  test: {
    include: ["tests/**/*.test.{ts,tsx}"],
    setupFiles: ["tests/setup.ts"],
    // After-hooks in the order they were defined, so setup.ts unmounts every root before a test
    // file's own afterEach empties document.body (reversed, React then removed portals already gone).
    sequence: { hooks: "list" },
    // GitHub Actions' hosted runners cap the actual cgroup CPU quota far below what Node's
    // os.cpus() reports for the underlying host (confirmed on this exact runner: a Docker
    // invocation in the same CI run hit "range of CPUs is from 0.01 to 2.00, as there are only
    // 2 CPUs available" -- see core/runner.py). Vitest's default forks pool sizes off os.cpus(),
    // not the cgroup quota, so with 17 test files it spawned 17 real worker processes competing
    // for 2 actual CPUs -- severe oversubscription that a correct, short async wait can still
    // lose to (a process scheduled off 2 cores shared 17-to-2 can be starved past a 2s deadline).
    // Capped only in CI; local dev keeps full parallelism. (`maxWorkers` is the top-level
    // Vitest 4+ option -- the older `poolOptions.forks.maxForks` was removed and is silently
    // a no-op on this project's Vitest 5.)
    maxWorkers: process.env.CI ? 2 : undefined,
    // The suite takes about a minute in CI, but a runner can be several times slower: one took
    // 8 minutes (Oct 2026) and axe audits and multi-step screen tests ran past the 5 s default,
    // failing code that passed everywhere else. The local default stays 5 s so slow tests show.
    testTimeout: process.env.CI ? 30_000 : undefined,
  },
});
