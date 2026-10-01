# Week 52 verification -- Launch: benchmark v2, the landing page, the v2.0.0 release (plan §33)

Honest record of what was built, run, and measured. No new ADR this week -- unlike every other v2
week, Week 52 made no new architectural decisions; it compiled, measured, shipped, and wrote up what
the previous 25 weeks already built. The closest things to a design record this week produced are
[docs/release-notes-v2.0.0.md](release-notes-v2.0.0.md) (what shipped, by phase) and
[docs/technical-report-v2.md](technical-report-v2.md) (the three mechanisms the plan asked to be
written up: correlation, taint-based ranking, verified fixes).

## What was built

- **Task 1 -- Benchmark v2** (plan §34): [docs/evaluation-v2.md](evaluation-v2.md), compiling every
  row of the plan's own evaluation table. Four rows were real, already-measured work scattered across
  earlier weeks, collected here for the first time. One row (the taint engine) is new, real
  measurement work done this week. Five rows are explicitly marked not measured (need a live model),
  and the UX row has no before/after (the baseline study was never run) -- none of these are new
  findings, just a single place collecting what each feature's own week already disclosed.
- **Task 2 -- Launch landing page** (plan §33): the homepage now replays a real scan of the real,
  public OWASP Juice Shop (271 real findings), reusing the existing `ScanReport`/`ToolCards`
  components unchanged -- the same ones the authenticated app's real WebSocket-driven live scan uses.
- **Task 3 -- v2.0.0 release**: [docs/release-notes-v2.0.0.md](release-notes-v2.0.0.md) and
  [docs/demo-script-v2.md](demo-script-v2.md) (the video itself is explicitly the user's own task).
- **Task 4 -- Technical write-up**: [docs/blog-v2.0.0.md](blog-v2.0.0.md),
  [docs/technical-report-v2.md](technical-report-v2.md), and
  [docs/talk-outline-v2.md](talk-outline-v2.md) (giving the talk is the user's own task).
- Two small fixes found and closed along the way, before this week's own tasks: `docs/api.md` and
  `docs/openapi.json` had drifted stale for several weeks with nothing checking them, and the CLI's
  ignored-finding count was silently dropped from the pre-commit hook's output in one branch -- both
  already covered in Week 51/52's own earlier commits, not repeated here.

## Validated against real, live things -- not mocks

- **The taint-engine measurement**: a real `bulwark scan` run against two real, cached repositories
  from the project's own 25-repo corpus (NodeGoat, nodejs-goof), with every confirmed finding
  hand-verified by reading the actual source. NodeGoat's three confirmations are genuine true
  positives -- the file's own comment reads "Insecure use of eval() to parse inputs."
- **The landing page's live replay is a real scan, not synthetic data.** `scripts/
  gen-juiceshop-demo-data.py` converts a real `bulwark scan https://github.com/juice-shop/juice-shop`
  run; every finding, tool duration, and severity count a visitor sees is what Bulwark actually
  reported. Verified live in a real browser: the replay reveals scanners in their real finish order,
  reaches the real "271 unique findings, 287 raw, 6% fewer" summary, and a bug found live before
  shipping (`ElapsedTime` reading a stale generation timestamp, producing an ever-growing nonsensical
  counter) was fixed and re-verified in the same browser session.
- **Every cross-reference in the four new write-up documents was checked against the real
  filesystem** -- including catching one wrong citation before it shipped: a draft of the talk
  outline cited a local "ADR-015" for the Opengrep/hosted-mode decision that does not exist in this
  repository (that numbering is the external plan document's own scheme, not this repo's
  sequentially-assigned `docs/adr/` files); corrected to describe it as a planned, not-yet-written v3
  decision instead.

## Verified

- Backend: `ruff check .`, `black --check .`, `mypy` (216 source files) all clean after each task;
  full unit suite green throughout, no regressions.
- Frontend: 220 tests passing (up from 215 at the end of Week 51 -- 5 new, covering the live replay's
  initial state, its progression, its connection-label switch, its links, and that it never
  fabricates data), `tsc --noEmit` clean, `npm run build` clean (the production build's own stricter
  typecheck caught one test-file type error the editor-level typecheck had missed, fixed before
  committing).
- `scripts/gen-juiceshop-demo-data.py` is outside this project's checked mypy scope (`files = ["core",
  "api"]`) but was cleaned up anyway: a bare `dict` annotation tightened to `dict[str, Any]`.

## What this does NOT prove (read before relying on it)

- **Everything docs/evaluation-v2.md already discloses, disclosed again here rather than softened**:
  five evaluation rows need a live model and weren't measured; the UX row has no real before/after;
  the taint-engine result is a 3-case spot-check, not a corpus study; scale and platform-security
  numbers are a single developer machine's.
- **The landing page's "live" replay is exactly that -- a replay.** The underlying scan and every
  number in it are real; the on-screen pacing is compressed from the real ~20-second run into 6
  seconds for a visitor's sake, and the copy says "replaying," never "scanning right now." No new
  Juice Shop scan runs per visitor or per page load.
- **The demo video and the talk itself are not part of this week's work product** -- by the user's own
  explicit instruction, both are left to them; what's delivered here is the script and outline that
  would make recording/giving either one faster, not the recordings themselves.
- **No GitHub Release was created via the GitHub API or `gh` CLI** -- neither is available in this
  environment. `docs/release-notes-v2.0.0.md` is written so it can be pasted directly into a GitHub
  Release description once the `v2.0.0` tag is pushed.
