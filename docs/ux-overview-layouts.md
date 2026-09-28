# Two overview layout options (Week 31, plan §31)

Sketched at [claude.ai/artifact/KuunrLeog2Pa3omV5tfJat](https://claude.ai/artifact/KuunrLeog2Pa3omV5tfJat)
(private; share it from the page's Share menu if others need to see it). Both use the plan's own
§28.1 sample data (`acme/payments-api`, the SQL injection / leaked key / lodash CVE trio) so they're
directly comparable to the plan's own wireframe, not an invented example.

## Layout A — two column (the plan's own §28.1 direction)

Verdict full-width at top; below it, a wide "Fix first" column (primary) beside a narrower,
persistent sidebar: trend since last week, PR-gate status, and what was/wasn't scanned.

## Layout B — vertical stack (the alternative)

Same verdict. Below it, the trend/PR-gate/coverage info condenses into one slim horizontal stat
strip, then the "Fix first" list runs the full width underneath. Trades a persistent sidebar for
giving 100% of the width to the actionable list.

## Chosen: A, with B as a narrow-viewport fallback

Evaluated against the plan's own seven principles (§25):

| Principle | A (two column) | B (vertical stack) |
|---|---|---|
| 1. Verdict, not a list | Both: verdict is full-width, first, unboxed. Tied. |
| 2. Calm by default | A's persistent sidebar risks feeling like "another panel to scan." Slightly favors B. |
| 3. Every number has a reason | Both show the same numbers with the same context. Tied. |
| 4. Progressive disclosure | A wins clearly: the sidebar is a natural place to collapse/hide for novice mode (§30.4) without touching the fix-first list at all. B's stat strip has nowhere to go except off-screen entirely. |
| 5. Keyboard-first triage | A wins: the fix-first list's own column never changes width or position regardless of sidebar content length. In B, a longer "what was scanned" line could wrap the stat strip taller and shift the list down between renders. |
| 6. Honest about uncertainty | Both carry "Found by 2 scanners · Verified fix ready" identically. Tied. |
| 7. User's words | Layout-independent. Tied. |

**A wins on progressive disclosure and layout stability for keyboard triage — two principles this
project has stated it cares about explicitly (§25.4, §25.5) — and it's also what the security
engineer and team-lead personas (§26.1) most directly benefit from: persistent PR-gate and trend
visibility without scrolling.** This matches the plan's own §28.1 wireframe, which already committed
to this shape; this exercise is a real re-derivation against the stated principles, not just
adopting the plan's sketch on authority.

**B is not thrown away.** Its single-column shape is the right answer once the viewport gets narrow
(the plan's own performance/accessibility budgets, §31, don't set a breakpoint, but a tablet-width
overview shouldn't try to cram a 1.7:1 column split into 768px). The concrete recommendation for
Week 33 (App shell and overview): build A as the default, and collapse to B's stacked shape below
roughly 900px, rather than treating them as two competing final designs.

## What this doesn't settle

Both sketches use static, non-interactive markup with the plan's own sample numbers — neither has
been shown to a real person yet. The baseline usability study (docs/ux-study-protocol.md) tests the
*current* product, not these sketches (there's nothing to build yet); a "which one works for you"
comparison of A vs. B would be a natural addition to the Week 35 follow-up study once one is
actually implemented, not fabricated preference data now.
