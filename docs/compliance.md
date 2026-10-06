# Compliance mappings, the ASVS checklist and evidence packs

Bulwark shows where the evidence it holds supports a framework's controls. **It is not a
certification, an audit opinion or a statement of compliance**, and no screen or file says it is.
The design is [ADR-0053](adr/0053-vex-compliance-evidence.md).

## Mappings

One versioned file per framework in `core/compliance/frameworks/`, each citing its source, version
and terms, and mapping each control to the kinds of evidence Bulwark holds:

| Framework | Controls | Source and terms |
|---|---|---|
| OWASP Top 10:2021 | 10 categories, each with OWASP's own CWE list | OWASP, CC BY-SA 4.0 |
| OWASP ASVS 4.0.3 | 278 requirements with level and CWE | OWASP, CC BY-SA 4.0, not reworded |
| PCI DSS v4.0, Requirement 6 | 6.1.1 to 6.5.1 | PCI SSC; numbers and Bulwark's paraphrases only |
| ISO/IEC 27001:2022, Annex A 8.8 | "Management of technical vulnerabilities" | ISO/IEC; the control's name only |
| SOC 2 TSC (2017, rev. 2022), CC7.1 | Detection and monitoring of vulnerabilities | AICPA; Bulwark's paraphrase only |

The kinds of evidence: scan coverage, web (DAST) scans, SLA adherence, risk acceptances, open
Issues, open Issues of a control's CWEs, the audit-log extract, the component inventory, advisory
monitoring, VEX statements, assessments, and the policies in force. Some controls have none
(developer training, a web application firewall, payment-page scripts) and say so.

    GET /v2/compliance/frameworks
    GET /v2/compliance/frameworks/{id}

## The ASVS checklist of a project

**Project → ASVS**: every ASVS 4.0.3 requirement up to level 1, 2 or 3, with a status:

| Status | Set by | Means |
|---|---|---|
| Met / Not met / Not applicable | A person, with a note (required for met and not applicable) and links | What the person decided |
| Not met | An assessment that failed the requirement | A tester's result |
| Issues open | Open Issues of the requirement's CWE | Evidence against it |
| Passed a test | An assessment that passed it | Evidence for it, not "met" |
| Not assessed | Nothing | No evidence either way |

Bulwark never marks a requirement met: no findings is not evidence that a control works. A person's
"met" that open Issues or a failed test contradict is flagged.

    GET /v2/projects/{id}/asvs?level=2
    PUT /v2/projects/{id}/asvs/{requirement}   {"status": "met", "note": "...", "links": [...]}

## Evidence packs

**Evidence** in the top bar: pick a period (up to 400 days) and frameworks, see what will be included,
generate. The pack is a zip:

| File | What |
|---|---|
| `evidence.pdf` | The pack to read |
| `evidence.json` | The same, machine-readable |
| `audit-extract.json` | The audit log for the period: your entries in full, others' as hashes |
| `checkpoints/` | Each Rekor checkpoint's Sigstore bundle |
| `verify.py` | Checks it all without trusting Bulwark (Python 3, standard library only) |
| `manifest.json`, `manifest.json.sig` | Every file's SHA-256, and cosign's signature over it |
| `audit.pub`, `trusted-root.json` | When the deployment provides them: the checkpoint key and a private Rekor's trust root |

What it reports, and how:

- **SLA adherence**: Issues whose deadline fell in the period, under the SLA policy in force at its
  end. Met: fixed by the deadline. Missed: fixed after. Open past deadline: not fixed by the period's
  end. Exempt: marked not a risk or accepted (as triaged now). Adherence = met / (met + missed + open
  past deadline).
- **Risk acceptances** requested, decided or in force in the period, with requester, approver and
  expiry, and whether a second person approved.
- **Scan coverage** per project: full and pull-request scans, web scans and imported reports in the
  period, the tools, the last scan.
- **Open Issues** by priority, as of generation (not as of the period's end).
- Components, advisories, VEX, assessments and SLA/priority policies.
- For each framework, each control with the evidence in the pack for it.

### Checking a pack

    unzip evidence-pack.zip -d pack && cd pack && python3 verify.py

`verify.py` checks every file against `manifest.json`, recomputes the audit chain (every entry's
hash, every link), and checks that each checkpoint names a hash that is in the extract at that
position. It then prints the two cosign commands it cannot run itself: the signature on the manifest
(with the organization's public key, obtained from the organization, not only from the pack) and
each checkpoint's signature and Rekor entry.

### Signing and Rekor

- `BULWARK_EVIDENCE_SIGNING_KEY` (a cosign private key; its password in `COSIGN_PASSWORD`) signs
  packs. Without it, packs are generated and marked **unsigned**; with it, a signing failure
  produces no pack.
- `bulwark audit checkpoint --key cosign.key [--rekor-url URL]` publishes the chain's head to
  Rekor: Sigstore's public instance (permanent and public) by default, or a private one.
- `bulwark audit verify --pub cosign.pub [--trusted-root trusted-root.json]` checks the whole chain
  and every checkpoint's signature and Rekor entry; with a trusted root (`cosign trusted-root create`
  for a private Rekor) it needs no network.
- `BULWARK_AUDIT_CHECKPOINT_PUB` and `BULWARK_REKOR_TRUSTED_ROOT` add the checkpoint key and trust
  root to packs.

### Why another organization's entries are hashes

The audit log is one chain for the whole deployment. Since migration 0041 each entry's organization
is inside its hash, through a digest of the entry's body, so a pack can show its organization's
entries in full and every other entry as `(seq, prev_hash, body_digest, entry_hash)`: every hash
still recomputes, and nothing about the other entry is revealed except that it exists. Entries from
before 0041 have no organization; they are shown as hashes and checked by link only.
