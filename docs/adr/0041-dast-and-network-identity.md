# ADR-0041: Where a DAST or network finding is, is its identity

Status: Accepted (2026-10-04), Week 57 (plan §22.4, §42.2). Amends
[ADR-0004](0004-fingerprinting-and-correlation.md) (correlation) and
[ADR-0012](0012-issue-occurrence-data-model.md) (Issue identity) for one category.

## Context

Week 57 ports the first DAST and network parsers (ZAP, Nuclei, then Burp, Nessus, OpenVAS) from
DefectDojo. Feeding a real ZAP report to the import path showed that Bulwark's identity rules,
written for source code, were wrong for findings with no file, no line and no snippet -- and had
been wrong for the native DAST campaigns (Week 49) all along, because nothing had put more than a
handful of alerts through them. Three independent mechanisms each got it wrong:

1. **Correlation merged different alerts.** `core.correlation.same_defect` compares code findings by
   path, CWE and line. A DAST finding has path `""` and line `0`, so *every* DAST finding was "in the
   same place". Two alerts that share a CWE (ZAP's X-Frame-Options and CSP rules are both CWE-1021)
   were folded into one finding, and which rule survived depended on input order. Every DAST finding
   also fell into one candidate bucket, so correlation was quadratic in the size of the scan.
2. **The fingerprint ignored the route.** It hashed CWE, path, snippet and rule. One alert fired on
   fifty URLs shared one fingerprint.
3. **The location-independent fallback key matched every URL to the first.** `fallback_key` exists so
   a function moved to another file is not "new" plus "fixed"; it deliberately omits the path. For
   DAST it omitted the only thing that distinguished findings, so 130 findings of a real ZAP report
   became 15 Issues.

## Decision

A DAST or network finding's **place is its identity**, and it is carried explicitly:

- `Location.host` (new, default `""`): `scheme://host[:port]` for a web target (lower-cased, the
  scheme's default port dropped), the bare host or IP for a network scan. `Location.route` is the URL
  path, or `port/protocol` (`443/tcp`, or `host` for a finding about the machine) when there is no URL.
  Query string and fragment are never part of it: scanners generate them on the fly.
- **DAST findings are never merged by `correlate()`**, and are never even compared (each gets its own
  candidate bucket). Cross-tool merging of dynamic findings is not defined by ADR-0004, and the
  obvious rule (same route and CWE) is wrong as soon as one tool reports two weaknesses with a CWE in
  common. The existing SAST-to-DAST confirmation (`core.dast.correlate`) is separate and unchanged.
- **The fingerprint of a DAST finding** is `dast | CWE | host | route | rule ids`. Tool names are
  deliberately not in it: ZAP run by Bulwark and a ZAP report uploaded later are one defect.
- **`fallback_key` is `None` for DAST**, as it already was for SCA: the primary fingerprint is
  already location-independent in the only sense that applies.
- **One Finding per instance (per URL or per host/port), not one per alert.** DefectDojo folds a
  ZAP alert hit at fifty URLs into one finding with fifty endpoints. Here each place is its own
  Finding and its own Issue: fixing `/a` closes that Issue and not `/b`, which a folded finding cannot
  express. `tests/unit/ddview.py` regroups our output by DefectDojo's folding key so the two can be
  compared like for like.
- The map from a tool's record to a Finding lives in `core/dast/mapping.py` and is shared by the
  native campaign adapters and the import parsers, so a defect has one reading however it arrives.

### Parsing policy for the batch

- **Burp's DOCTYPE.** Burp writes `<!DOCTYPE issues [<!ELEMENT ...>]>` at the top of every export,
  so refusing every DTD (the rule for all other XML) would refuse every real Burp file. `iter_xml`
  gains `allow_dtd`, used only by the Burp parser, which admits *an internal subset without entity
  declarations*: an `<!ENTITY>` (which is all XXE and entity expansion need) and an external DTD
  (`SYSTEM`/`PUBLIC`) are still errors.
- **A report must have reached something to close anything.** A scanner report that is a sample of a
  scan, not a complete one -- an OpenVAS scan that is not `Done`, a report with no hosts, a CSV with
  no rows, an empty Nuclei file -- imports what it has and closes nothing.
- **CSV truncation.** A row with fewer fields than the header, or an unterminated quoted field, is
  an error. A cut exactly between two rows is a valid shorter CSV and cannot be detected.

## Consequences

- **One-time churn for existing DAST Issues.** Native DAST Issues created before this change have
  route-free fingerprints. The next campaign (or import) against the same asset will not match
  them: they are closed as fixed and the same defects reappear as new Issues, one per place. Triage
  state recorded on the old Issues (false-positive marks, suppressions) does not carry over. This
  was judged better than carrying forward the bug (which would keep collapsing fifty places into one
  Issue); it only affects instances that ran a DAST campaign on v2.0.0 or v2.1.0, and a migration
  could not recover it because the old fingerprint never contained the route.
- The Issue list for a DAST scan is longer than DefectDojo's finding list for the same report -- by
  design (see above) -- and a Nuclei result on the same host at two ports is two Issues where
  DefectDojo folds on hostname alone.
- `Location` gains a field; stored findings are JSON, so existing rows are unaffected, but every
  golden `expected.json` gained `"host": ""`.

## What is NOT done here

- Request and response bodies are not stored. A ZAP "XML plus requests and responses" report is read;
  the finding keeps the method, parameter, attack, evidence and the response's status line, not
  kilobytes of HTTP. Evidence attachments belong with the manual-findings work (Week 59, §43.2).
- **Closing is scoped to the Test, not to the hosts a report covers.** A Nessus or OpenVAS report
  that covers fewer hosts than the last one lists the missing hosts' Issues as closed. The preview
  shows the count before it is saved, and the docs say to read it; making closure host-aware needs
  a coverage set on the parse result and a host column on stored findings, and is not done.
- Cross-tool merging of DAST findings (ZAP and Nuclei both seeing the same missing header) is not
  attempted. It would need per-weakness rules and is better done as an explicit, previewed
  deduplication strategy (Week 58, §42.3) than as an implicit merge.
