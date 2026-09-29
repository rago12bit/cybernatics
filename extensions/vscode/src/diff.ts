import type { BulwarkFinding } from "./types";

/** Same identity `core.ci.compare` uses server-side: the stable fingerprint when present, the raw
 * id otherwise (a finding a version of Bulwark without fingerprints produced, in an old cached
 * base scan) -- never just `id` alone, which is not guaranteed stable across two separate scans. */
function key(f: BulwarkFinding): string {
  return f.fingerprint || f.id;
}

/** Findings in `head` that don't match one in `base` (plan §36's "new since the base branch") --
 * the same fingerprint-based comparison `bulwark ci compare` runs in CI, so a developer's editor
 * and the pull request check agree on what counts as new. */
export function newSince(head: BulwarkFinding[], base: BulwarkFinding[]): Set<string> {
  const baseKeys = new Set(base.map(key));
  const result = new Set<string>();
  for (const f of head) if (!baseKeys.has(key(f))) result.add(f.id);
  return result;
}
