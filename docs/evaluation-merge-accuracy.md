# Merge accuracy: are merged reports really one defect? (plan §60)

The deduplication rate
([benchmarks/README.md](https://github.com/rago12bit/cybernatics/blob/main/benchmarks/README.md))
says how much shorter the list gets. It does not say whether the merges are right, or how many
duplicates were left unmerged. Every evaluation so far lists that as **not measured**. This page is
the study that measures it: the protocol, the rules a rater follows, and the results.

**Status: the protocol and tooling are built and tested; no labels have been collected yet.** The
results section is empty until a person has labelled the sample. Nothing below is a result.

## What is measured

| Question | Measure | From |
|---|---|---|
| When Bulwark merges reports, are they one defect? | **Merge precision**: merged groups that are one defect, of those judged | Pairs of raw reports that ended up in one finding |
| Which duplicates does it leave apart? | **Missed-merge rate among look-alikes**: left-apart pairs that are one defect, of those judged | Pairs from different tools that were not merged but resemble each other |

The second is not recall. Recall needs every true duplicate pair in the corpus, and that means
labelling every pair of reports in every file. Look-alikes are where a missed merge is most likely to
be, so the rate is an upper-end indicator for that neighbourhood, and says nothing about duplicates
that do not look alike under the rule below.

## Corpus

The 25 public repositories of `benchmarks/corpus/corpus.json`, each at its pinned commit: 12
deliberately vulnerable applications and 13 ordinary projects. The five default scanners run exactly
as in a scan, and every raw report is kept before correlation. The raw file stays outside the
repository (`~/.cache/bulwark-benchmarks/merge-study/`) because raw reports are not redacted; the
labelling material is redacted like any other Bulwark output.

## Units and strata

`core.correlation.partition` gives, for each finding Bulwark returns, the raw reports behind it. A
finding with two or more reports is a **merged group**. Groups fall into three strata:

| Stratum | A group of reports ... | Drawn |
|---|---|---|
| `code` | from two or more tools, on code, secrets, infrastructure or containers | all of them |
| `dependency` | from two or more tools, on a package | a random 100 |
| `same-tool` | from one tool: a repeat at one place, or two of its rules on one defect | a random 30 |

Code merges are few and are where a wrong merge is most likely, so all are labelled. Dependency
merges are many and rest on an exact rule (same package and version, a shared id), so a sample is
enough. From a larger group, up to three pairs are checked in `code` and one elsewhere; **a group is
right only if every checked pair is the same defect.**

**Look-alikes** are pairs from different tools that were not merged:

| Stratum | A pair ... | Drawn |
|---|---|---|
| `near-code` | in one file, either sharing a weakness (CWE) family within 10 lines, or on adjacent lines whatever the weakness | a random 50 |
| `near-dependency` | on one package, either sharing an id, or on one version where neither report was matched by another tool (an alias one tool does not list) | a random 50 |

Similar code alone is not a look-alike signal: with names, strings and numbers masked, most
statements overlap.

Sampling is simple random sampling within a stratum over the whole corpus, seed `20261111`. The
answer key records each stratum's size, so a draw can be repeated exactly.

## Blinding

The rater sees two reports side by side and answers one question: the same defect, different, or
unsure. Merged pairs and look-alikes are shuffled together, left and right are assigned at random,
and the labelling page contains nothing about what Bulwark did with a pair. The key that says so is
a separate file, which the rater does not open until scoring.

## The codebook

1. Answer one question: are these two reports the same defect? That is, the same flaw, with the same
   root cause, at the same place.
2. **Dependencies:** the same package, the same installed version and the same vulnerability,
   declared in the same manifest or lock file. One advisory under two ids (a CVE and a GHSA) is the
   same. Two different vulnerabilities are different, even when one upgrade fixes both.
3. The same vulnerable package version declared in two different manifests is two places to fix:
   different. Say so in the note.
4. **Code:** the same file and the same flaw, at one statement or at the statements that make the
   flaw together (a query built on one line and run on the next). The same kind of flaw at two
   separate places is different. Two different flaws on one line are different.
5. **Secrets:** a secret scanner and a code scanner pointing at the same hard-coded value are the
   same.
6. **Infrastructure and containers:** the same resource or instruction with the same
   misconfiguration is the same. Two different misconfigurations of one resource are different.
7. Open the source link when the reports alone do not settle it. Choose Unsure only if it still
   does not.
8. Judge the reports, not what a tool should have done. You are not told whether Bulwark merged the
   pair.

The codebook is fixed before labelling starts. A rule changed afterwards is recorded here with its
date, and the affected pairs are relabelled.

## Statistics

- **Per stratum:** the rate with a 95% Wilson interval. Unsure answers are left out of the rate and
  reported beside it, with the rate recomputed counting them against Bulwark (as wrong merges, or as
  missed ones).
- **Pooled over the corpus:** strata weighted by their size in the corpus. A stratum labelled in
  full is known exactly for this corpus; a sampled one contributes its interval's ends.
- **Two raters:** when a second person labels the same pairs, agreement and Cohen's kappa are
  reported, and every disagreement is listed for discussion. One rater's labels are one person's
  judgement, and the report says so.

## Running it

```bash
python -m benchmarks.merge_study collect --label v1      # needs Docker and the scanner images
python -m benchmarks.merge_study sample ~/.cache/bulwark-benchmarks/merge-study/<date>-v1.raw.json.gz
# open benchmarks/results/merge-study-<date>-v1.label.html, label, download the CSV
python -m benchmarks.merge_study score benchmarks/results/merge-study-<date>-v1.key.json --labels <name>=<labels.csv>
```

The labelling page is one file with no network access. It keeps progress in the browser, takes
answers from the keyboard (S, D, U, arrow keys) and shows scanner text only as text.

## Results

Not collected yet.

## Limits

- **The rater knows the project.** The first rater is its author. A second, independent rater is the
  remedy, and the scoring supports one.
- **Precision is per group, on checked pairs.** In a group of four or more reports, a wrong pair
  that was not drawn is not seen.
- **Look-alikes are a rule, not a census.** A duplicate reported eleven lines apart, or under two
  unrelated weaknesses three lines apart, is outside it.
- **"The same place" is a choice.** Rule 3 counts one package version in two manifests as two
  defects; Bulwark's dependency rule does not look at the manifest. Where that decides a label, the
  rater's note says so, so those pairs can be counted apart.
- **The corpus is half deliberately vulnerable applications.** Their merges are mostly dependency
  merges, the easy kind.
