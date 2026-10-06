"""The evidence pack's PDF (plan §47), from `pack.collect`'s evidence, with ReportLab like every
other Bulwark PDF (`core/export/pdf.py`): every string escaped and Latin-1 only."""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.export.pdf import _t

MAX_TABLE = 400


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v * 100:.1f}%"


def to_pdf(ev: dict[str, Any], *, signed: bool) -> bytes:
    buf = io.BytesIO()
    org = ev["organization"]["name"] or ev["organization"]["id"]
    period = f"{ev['period']['start']} to {ev['period']['end']}"
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
        bottomMargin=16 * mm, title=f"Evidence pack: {_t(org, 100)}, {period}", author="Bulwark",
    )  # fmt: skip
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle(
        "s", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#5b5c52")
    )
    cell = ParagraphStyle("c", parent=body, fontSize=8, leading=10.5)
    mono = ParagraphStyle("m", parent=cell, fontName="Courier", fontSize=7, leading=9)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=20, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=6)
    h3 = ParagraphStyle("h3", parent=ss["Heading3"], fontSize=10.5, spaceBefore=8, spaceAfter=4)
    w = doc.width

    def p(text: Any, style: ParagraphStyle = cell, limit: int = 600) -> Paragraph:
        return Paragraph(_t(text if text is not None else "", limit), style)

    def grid(head: list[str], rows: list[list[Any]], widths: list[float]) -> Table:
        data: list[list[Any]] = [[p(h.upper(), small) for h in head]]
        for r in rows[:MAX_TABLE]:
            data.append([c if isinstance(c, Paragraph) else p(c) for c in r])
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9d9d0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))  # fmt: skip
        return t

    def more(rows: list[Any]) -> list[Any]:
        if len(rows) > MAX_TABLE:
            return [p(f"{len(rows) - MAX_TABLE} more rows are in evidence.json.", small)]
        return []

    a = ev["audit_check"]
    story: list[Any] = [
        p("BULWARK EVIDENCE PACK", small),
        p(org, h1, 200),
        p(f"Period {period} (UTC). Generated {ev['generated_at'][:19]}Z by Bulwark "
          f"{ev['bulwark_version']}.", small),  # fmt: skip
        Spacer(1, 6),
        p(ev["disclaimer"], body),
        p(
            "This PDF is signed through manifest.json (see the last page)." if signed
            else "UNSIGNED: this deployment has no signing key, so nothing proves who made this "
            "pack. The audit-log extract can still be checked with verify.py.",
            body,
        ),
        Paragraph("At a glance", h2),
    ]  # fmt: skip
    sla = ev["sla"]
    glance = [
        ["Projects scanned in the period", f"{ev['scan_coverage']['scanned']} of {ev['scan_coverage']['projects']}"],  # noqa: E501
        ["SLA adherence", f"{_pct(sla['adherence'])} ({sla['met']} met, {sla['missed']} missed, {sla['open_past_deadline']} open past deadline, {sla['exempt']} exempt)"],  # noqa: E501
        ["Risk acceptances", str(ev["risk_acceptances"]["count"])],
        ["Open Issues (now)", str(ev["open_issues"]["total"])],
        ["VEX statements confirmed", str(ev["vex"]["confirmed"])],
        ["Assessments", str(ev["engagements"]["count"])],
        ["Audit log", f"{a['entries']} entries, {'chain intact' if a['ok'] else 'CHAIN BROKEN'}; "
                      f"{'anchored in Rekor' if a['anchored_at'] else 'no Rekor checkpoint'}"],
    ]  # fmt: skip
    story.append(grid(["", ""], glance, [60 * mm, w - 60 * mm]))

    story.append(Paragraph("Scan coverage", h2))
    rows = ev["scan_coverage"]["rows"]
    story.append(grid(
        ["Project", "Exposure", "Full scans", "PR scans", "Web scans", "Imported", "Last scan",
         "Tools"],
        [[r["project"], r["exposure"], r["full_scans"], r["pull_request_scans"], r["dast_scans"],
          r.get("imported_reports", 0), (r["last_scan_at"] or "never")[:10], ", ".join(r["tools"])]
         for r in rows],
        [38 * mm, 21 * mm, 14 * mm, 14 * mm, 14 * mm, 16 * mm, 20 * mm, w - 137 * mm],
    ))  # fmt: skip
    story += more(rows)

    story.append(Paragraph("SLA adherence", h2))
    story.append(p(
        "Issues whose SLA deadline fell in the period, under the SLA policy in force at its end. "
        "Met: fixed by the deadline. Missed: fixed after it. Open past deadline: not fixed by the "
        "period's end. Exempt: marked not a risk or accepted (as triaged now). Adherence = met / "
        "(met + missed + open past deadline).", small))  # fmt: skip
    rows = [r for r in sla["rows"] if r["policy"]]
    story.append(grid(
        ["Project", "Policy", "Met", "Missed", "Open past deadline", "Exempt"],
        [[r["project"], f"v{r['policy']['version']} by {r['policy']['basis']}", r.get("met", 0),
          r.get("missed", 0), r.get("open_past_deadline", 0), r.get("exempt", 0)] for r in rows],
        [50 * mm, 30 * mm, 18 * mm, 18 * mm, 30 * mm, w - 146 * mm],
    ))  # fmt: skip
    no_policy = [r["project"] for r in sla["rows"] if not r["policy"]]
    if no_policy:
        story.append(p(f"No SLA policy: {', '.join(no_policy)}.", small, 2000))

    story.append(Paragraph("Risk acceptances", h2))
    rows = ev["risk_acceptances"]["rows"]
    story.append(grid(
        ["Project", "Decision", "State", "Issues", "Requested", "Approved by", "Expires"],
        [[r["project"], r["decision"], r["state"], r["issues"],
          f"{r['requested_by']} {(r['requested_at'] or '')[:10]}",
          f"{r['decided_by'] or '-'} {(r['decided_at'] or '')[:10]}"
          + ("" if r["second_person"] or not r["decided_by"] else " (same person)"),
          (r["expires_at"] or "")[:10]] for r in rows],
        [30 * mm, 18 * mm, 18 * mm, 15 * mm, 36 * mm, 36 * mm, w - 153 * mm],
    ))  # fmt: skip
    story += more(rows)
    if not rows:
        story.append(p("None in the period.", small))

    story.append(Paragraph("Open Issues by priority", h2))
    oi = ev["open_issues"]
    story.append(p(f"As of {oi['as_of'][:19]}Z. " + ", ".join(
        f"{k}: {v}" for k, v in oi["by_priority"].items()) + ".", small))  # fmt: skip
    bands = sorted(oi["by_priority"])
    rows = [r for r in oi["rows"] if r["total"]]
    story.append(grid(
        ["Project", *bands, "Total"],
        [[r["project"], *[r.get(b, 0) for b in bands], r["total"]] for r in rows],
        [60 * mm] + [(w - 80 * mm) / max(len(bands), 1)] * len(bands) + [20 * mm],
    ))  # fmt: skip
    story += more(rows)

    story.append(Paragraph("Components, advisories and VEX", h2))
    adv, vx = ev["advisories"], ev["vex"]
    story.append(p(
        f"{ev['inventory']['libraries']} distinct libraries in {ev['inventory']['with_sbom']} "
        f"projects' current SBOMs. {adv['new_in_period']} vulnerabilities first affected a "
        f"project in the period ({adv['new_known_exploited']} known exploited; Issues created for "
        f"{adv['new_with_issues']}); {adv['affecting_now']} affect a project now. "
        f"VEX: {vx['confirmed']} statements confirmed in the period, {vx['rejected']} proposals "
        f"rejected, {vx['proposed_waiting']} waiting; "
        f"{vx['issues_dismissed_with_justification']} dependency Issues dismissed with a VEX "
        "justification.", body, 2000))  # fmt: skip
    story.append(grid(
        ["Advisory source", "Last success", "Records", "Last error"],
        [[f["source"], (f["last_success_at"] or "never")[:19], f["records"], f["last_error"] or ""]
         for f in adv["feeds"]],
        [30 * mm, 35 * mm, 20 * mm, w - 85 * mm],
    ))  # fmt: skip

    story.append(Paragraph("Assessments", h2))
    rows = ev["engagements"]["rows"]
    if rows:
        story.append(grid(
            ["Assessment", "Type", "Project", "Started", "Closed", "Report"],
            [[r["name"], r["type"], r["project"], (r["started_at"] or "")[:10],
              (r["closed_at"] or "open")[:10], "yes" if r["report"] else "no"] for r in rows],
            [50 * mm, 18 * mm, 40 * mm, 20 * mm, 20 * mm, w - 148 * mm],
        ))  # fmt: skip
    else:
        story.append(p("None in the period.", small))

    for fw in ev["frameworks"]:
        story.append(PageBreak())
        story.append(Paragraph(_t(fw["name"], 200), h2))
        src = fw["source"]
        story.append(p(f"{src['title']}. {src['publisher']}, {src['url']}. {src['terms']} "
                       f"Bulwark mapping version {fw['mapping_version']} "
                       f"({fw['mapping_date']}).", small, 2000))  # fmt: skip
        story.append(p(ev["disclaimer"], small))
        if fw.get("projects"):
            story.append(Paragraph("ASVS level 2, per project", h3))
            keys = ["met", "not_met", "issues_open", "tested", "not_applicable", "not_assessed"]
            story.append(grid(
                ["Project", *[k.replace("_", " ") for k in keys]],
                [[r["project"], *[r.get(k, 0) for k in keys]] for r in fw["projects"]],
                [50 * mm] + [(w - 50 * mm) / len(keys)] * len(keys),
            ))  # fmt: skip
            story.append(p("Met is set by a person only. Each project's requirement-by-requirement "
                           "checklist is in Bulwark and evidence.json.", small))  # fmt: skip
            continue
        story.append(grid(
            ["Control", "Title", "Evidence in this pack"],
            [[c["id"], c["title"],
              Paragraph("<br/>".join(_t(f"{e['label']}: {e['here']}", 300)
                                     for e in c["evidence"]) or _t(c["note"] or "None", 300), cell)]
             for c in fw["controls"]],
            [18 * mm, 62 * mm, w - 80 * mm],
        ))  # fmt: skip

    story.append(PageBreak())
    story.append(Paragraph("Audit log", h2))
    ex = ev["audit"]
    story.append(p(
        f"Entries {a['first_seq']} to {a['last_seq']} of the deployment's tamper-evident audit "
        f"log: {a['disclosed']} of this organization's entries in the period shown in full (a "
        f"digest of each payload, never the payload), every other entry as its hashes. "
        f"{a['recomputed']} hashes recomputed, {a['linked_only']} checked by link only (entries "
        "from before per-organization hashing). "
        + ("The chain is intact." if a["ok"] else "THE CHAIN DOES NOT CHECK: " + "; ".join(a["problems"][:5]))  # noqa: E501
        + (f" Rekor checkpoints at entries {', '.join(map(str, a['anchored_at']))}"
           + ("." if a["all_disclosed_anchored"] else "; the latest entries are not yet anchored.")
           if a["anchored_at"] else " No Rekor checkpoint covers these entries."),
        body, 3000))  # fmt: skip
    if ex.get("truncated"):
        story.append(p("The extract was cut at its maximum size.", small))
    shown = [e for e in ex["entries"] if not e.get("withheld")]
    story.append(grid(
        ["#", "When", "Actor", "Action", "Target"],
        [[e["seq"], e["timestamp"][:19], e["actor"], e["action"], e["target"]] for e in shown],
        [14 * mm, 32 * mm, 36 * mm, 44 * mm, w - 126 * mm],
    ))  # fmt: skip
    story += more(shown)
    if ex["checkpoints"]:
        story.append(Paragraph("Rekor checkpoints", h3))
        story.append(grid(
            ["Entry", "Chain hash", "Rekor log index", "Signed"],
            [[c["seq_end"], Paragraph(_t(c["chain_hash"]), mono), c["rekor_log_index"],
              (c["created_at"] or "")[:19]] for c in ex["checkpoints"]],
            [16 * mm, 95 * mm, 30 * mm, w - 141 * mm],
        ))  # fmt: skip

    story.append(Paragraph("Checking this pack", h2))
    for line in (
        "1. Unzip the pack and run: python3 verify.py. It checks every file against "
        "manifest.json and recomputes the audit chain, using only Python's standard library.",
        "2. Check the signature on manifest.json with the deployment's public key: cosign "
        "verify-blob --key cosign.pub --bundle manifest.json.sig --insecure-ignore-tlog "
        "manifest.json" + ("" if signed else " (this pack is unsigned)."),
        "3. For each checkpoint, verify.py prints the cosign command that checks its signature "
        "and its entry in the Rekor transparency log.",
    ):
        story.append(p(line, body, 1000))
    doc.build(story)
    return buf.getvalue()
