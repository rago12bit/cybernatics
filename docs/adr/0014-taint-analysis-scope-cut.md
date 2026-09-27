# ADR-0014: Taint analysis scope cut — intra-procedural, single language, prefer existing engines

Status: Accepted (2026-09-27). Design only; not yet implemented. Scopes down the v2 plan's tree-sitter code
intelligence + taint analysis phase before any of it is built, so the cut is on record before the pressure of a
slipping schedule makes it tempting to quietly cut it later instead.

## Context

The v2 plan calls for a taint analysis engine that propagates function summaries over a call graph, across
Python, JavaScript, and Go. That is a description of what CodeQL and Semgrep Pro's proprietary engines do, built
by dedicated teams over multiple years. Bulwark ships in weekly increments with no research team. Committing to
the full version as written risks the single most common failure mode of ambitious security tooling projects:
the taint engine never quite finishes, and it stalls every other v2 feature scheduled after it.

This ADR exists to make the scope decision explicit *before* that phase starts, not to record a retrospective
excuse after it has already slipped.

## Decision

Cut scope on three axes, in order of how much complexity each removes:

1. **Intra-procedural only, not interprocedural.** Track source → sink dataflow within a single function body.
   No function summaries, no call graph construction, no cross-function propagation. This is a materially
   different (and dramatically simpler) problem: no summary computation, no recursion/cycle handling in the call
   graph, no whole-program fixpoint analysis.
2. **One language first: Python.** Bandit already gives Bulwark a mature Python AST pipeline and tree-sitter's
   Python grammar is the most battle-tested of the three. JavaScript and Go are deferred to their own,
   separately-scoped weeks rather than built in parallel with Python — building three at once triples the
   surface area for the exact kind of subtle bug (wrong scope resolution, wrong sanitizer recognition) that a
   partially-working taint engine produces silently.
3. **Build vs. configure: check Semgrep's existing taint mode first.** Semgrep already ships bounded,
   intra-file taint tracking (`mode: taint`, source/sink/sanitizer rules) as a *configuration* surface, not
   something Bulwark has to implement. Before writing a custom engine, evaluate how much of the intra-procedural,
   single-language scope above is already covered by authoring Semgrep taint rules through the existing adapter.
   Only build custom tree-sitter-based analysis for what Semgrep's taint mode demonstrably cannot express for
   Bulwark's use cases — and record what that gap actually is, rather than assuming one exists.

Interprocedural analysis and the other two languages remain a real goal — they move to v3 (or a later, explicitly
re-scoped v2 week) once the intra-procedural, single-language, configure-before-build version has shipped and
proven the approach.

## Alternatives considered

- **Build the full cross-language interprocedural engine as originally planned.** Rejected for v2: correct
  long-term ambition, wrong thing to put on the critical path of a single release. Every other v2 feature
  scheduled after this phase inherits its risk of never finishing.
- **Drop taint analysis from v2 entirely, defer everything to v3.** Rejected: the intra-procedural,
  single-language, configure-first version above is small enough to actually ship, and shipping something real
  (even narrow) gives v3's more ambitious version a working baseline and real usage data to design against,
  instead of starting from zero.

## Consequences

- Whichever week implements this must budget time to first evaluate Semgrep taint-mode coverage before writing
  new analysis code — that evaluation is part of the week's scope, not a shortcut around it.
- Marketing/docs language about "taint analysis" for v2 must describe the actual shipped scope (intra-procedural,
  Python) accurately, the same way ADR-0012 documents where the Issue/Occurrence implementation differs from its
  original design — no silent over-claiming.
- JavaScript and Go taint support, and interprocedural analysis for any language, need their own future ADR (or
  an explicit amendment to this one) with real scoping before they start, not an assumption that "the engine
  already exists, just extend it."
