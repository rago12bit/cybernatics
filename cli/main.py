"""Bulwark CLI: `bulwark scan <path> --tools bandit --format json`."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import typer

from core.cache import ResultCache
from core.ignore import IgnoreRules
from core.ingest import IngestError
from core.scan import ADAPTERS, DEFAULT_TOOLS, scan
from core.source import materialize

app = typer.Typer(help="Bulwark: unified security scanning.", no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Bulwark: unified security scanning."""


@app.command("scan")
def scan_cmd(
    source: str = typer.Argument(..., help="Directory, .zip/.tar.gz archive, or public Git URL."),
    tools: str = typer.Option(
        ",".join(DEFAULT_TOOLS),
        help=f"Comma-separated tools. Also available: {', '.join(t for t in ADAPTERS if t not in DEFAULT_TOOLS)}.",
    ),
    fmt: str = typer.Option("json", "--format", help="json (default), sarif, html or pdf."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write here instead of stdout."
    ),
    distributed: bool = typer.Option(False, "--distributed", help="Run tools on Celery workers."),
    ignore_file: Path | None = typer.Option(
        None,
        "--ignore-file",
        help="Ignore file to use instead of the source's own (CI: the base branch's).",
    ),
    cache_dir: Path | None = typer.Option(
        None,
        "--cache-dir",
        help="Content-addressed result cache (plan §20.1): reuse a prior run's results for "
        "unchanged files instead of rescanning them. Safe to reuse across scans of different "
        "repositories, and to persist across CI runs (e.g. actions/cache) -- that's what makes a "
        "pull request's unchanged files free on every run after the first.",
    ),
) -> None:
    if fmt not in ("json", "sarif", "html", "pdf"):
        raise typer.BadParameter("use json, sarif, html or pdf", param_hint="--format")
    if fmt == "pdf" and output is None:
        raise typer.BadParameter("pdf is binary: pass --output report.pdf", param_hint="--output")
    names = [t.strip() for t in tools.split(",") if t.strip()]
    try:
        rules = IgnoreRules.load(ignore_file) if ignore_file is not None else None
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--ignore-file") from exc
    if distributed and cache_dir is not None:
        raise typer.BadParameter(
            "not yet supported together with --distributed", param_hint="--cache-dir"
        )
    cache = ResultCache(cache_dir) if cache_dir is not None else None
    try:
        with materialize(source) as workspace:
            if distributed:
                from core.tasks import celery_executor

                result = scan(workspace, names, celery_executor, rules)
            else:
                result = scan(workspace, names, ignore=rules, cache=cache)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--tools") from exc
    except IngestError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    for tool, st in result.tool_status.items():
        for w in st.get("warnings", []):
            typer.echo(f"warning: {tool}: {w}", err=True)
    if fmt == "json":
        text = json.dumps(
            {
                "tool_status": result.tool_status,
                "stats": {
                    "raw_findings": result.stats.raw,
                    "unique_findings": result.stats.unique,
                    "dedup_rate": round(result.stats.dedup_rate, 3),
                    "ignored_findings": result.ignored,
                },
                "findings": [f.to_dict() for f in result.findings],
            },
            indent=2,
        )
        data = text.encode()
    else:
        from core.export import ReportData, render

        counts = Counter(f.scoring.normalized_severity.value for f in result.findings)
        failed = any(t.get("status") not in ("ok", "skipped") for t in result.tool_status.values())
        report = ReportData(
            scan_id="local",
            source_label=source if "://" in source else Path(source).name or source,
            status="partial" if failed else "completed",
            finished_at=None,
            tool_status={
                k: {**v, "findings": v.get("findings", 0)} for k, v in result.tool_status.items()
            },
            raw_findings=result.stats.raw,
            unique_findings=result.stats.unique,
            dedup_rate=result.stats.dedup_rate,
            severity_counts=dict(counts),
            findings=[f.to_dict() for f in result.findings],
        )
        data = render(fmt, report)
    if output:
        output.write_bytes(data)
        typer.echo(f"wrote {output} ({len(data)} bytes)", err=True)
    else:
        typer.echo(data.decode())


kb_app = typer.Typer(help="Remediation knowledge base: CWE + OWASP cheat-sheet corpus in pgvector.")
app.add_typer(kb_app, name="kb")


@kb_app.command("load")
def kb_load(
    if_empty: bool = typer.Option(
        False, "--if-empty", help="Do nothing when the index already exists."
    ),
) -> None:
    """(Re)build the search index from the committed corpus. Idempotent; takes a few seconds."""
    from sqlalchemy import select

    from core.persistence.db import get_session_factory
    from core.rag.corpus_io import read_corpus
    from core.rag.store import KbMeta, load_corpus

    with get_session_factory()() as s:
        if if_empty and s.scalar(select(KbMeta.key).where(KbMeta.key == "embedder")):
            typer.echo(json.dumps({"skipped": "knowledge base already loaded"}))
            return
        info = load_corpus(s, read_corpus())
    typer.echo(json.dumps(info))


@kb_app.command("stats")
def kb_stats() -> None:
    from core.persistence.db import get_session_factory
    from core.rag.store import KnowledgeBase

    with get_session_factory()() as s:
        typer.echo(json.dumps(KnowledgeBase(s).stats(), indent=2))


@kb_app.command("search")
def kb_search(
    query: str = typer.Argument(..., help="What to look for, in plain words."),
    k: int = typer.Option(5, "-k", help="How many results."),
    kind: str | None = typer.Option(None, help="cwe or cheatsheet."),
) -> None:
    """Semantic search over the corpus (for checking what a finding would be given)."""
    from core.persistence.db import get_session_factory
    from core.rag.store import KnowledgeBase

    with get_session_factory()() as s:
        for h in KnowledgeBase(s).search(query, k, kind=kind):
            typer.echo(
                f"{h.score:.3f}  {h.chunk.title} | {h.chunk.section[:70]}\n        {h.chunk.url}"
            )


llm_app = typer.Typer(
    help="LLM remediation suggestions (off by default; see docs/llm-remediation.md)."
)
app.add_typer(llm_app, name="llm")


def _load_finding(path: Path, index: int) -> Any:
    from core.models import finding_from_dict

    doc = json.loads(path.read_text())
    item = doc["findings"][index] if isinstance(doc, dict) and "findings" in doc else doc
    return finding_from_dict(item)


def _code_for(finding: Any, source: Path | None) -> Any:
    from core.llm.prompt import extract_context

    if source is None:
        return None
    loc = finding.location
    return extract_context(source.read_text(errors="replace"), loc.start_line, loc.end_line)


@llm_app.command("status")
def llm_status() -> None:
    """Which backend each task routes to (hosted or local), privacy mode, and whether a key/model
    is set for each -- never the key itself."""
    from core.llm.gateway import gateway_status

    typer.echo(json.dumps(gateway_status(), indent=2))


@llm_app.command("prompt")
def llm_prompt(
    finding_json: Path = typer.Argument(
        ..., help="A finding, or the output of `bulwark scan` (use --index)."
    ),
    source: Path | None = typer.Option(
        None, help="The source file the finding is in (adds +/-20 lines of code)."
    ),
    index: int = typer.Option(0, help="Which finding, when the file is a full scan result."),
) -> None:
    """Print exactly what would be sent to a model. Nothing is sent; no key needed."""
    from core.llm.prompt import build_prompt
    from core.persistence.db import get_session_factory
    from core.rag.retrieve import RemediationContext, context_for
    from core.rag.store import KnowledgeBase

    finding = _load_finding(finding_json, index)
    try:
        with get_session_factory()() as s:
            ctx = context_for(finding, KnowledgeBase(s))
    except (
        Exception
    ):  # noqa: BLE001 - no knowledge base yet: show the prompt without reference text
        ctx = RemediationContext(basis="none")
        typer.echo(
            "(knowledge base not loaded: reference text omitted; run `bulwark kb load`)", err=True
        )
    p = build_prompt(finding, ctx, _code_for(finding, source))
    typer.echo(f"### SYSTEM\n{p.system}\n\n### USER\n{p.user}")
    typer.echo(
        f"\n[code sent: {p.code_included}; secrets removed: {p.secrets_scrubbed}; "
        f"injection-like text: {p.signals or 'none'}]",
        err=True,
    )


@llm_app.command("suggest")
def llm_suggest(
    finding_json: Path = typer.Argument(...),
    source: Path | None = typer.Option(None, help="The source file the finding is in."),
    index: int = typer.Option(0),
    privacy: bool = typer.Option(
        False,
        "--privacy",
        help="Force a local model (Ollama) and refuse to use a hosted one, even if configured: "
        "the code never leaves this machine. Same as BULWARK_LLM_PRIVACY_MODE=1 for this command.",
    ),
) -> None:
    """Ask the routed model for a suggestion (sends data off this machine, unless --privacy); else
    static text."""
    from dataclasses import asdict

    from core.llm.gateway import GatewayConfig, PrivacyModeViolation, Task, make_gateway_client
    from core.llm.service import suggest
    from core.persistence.db import get_session_factory
    from core.rag.store import KnowledgeBase

    gw_cfg = GatewayConfig.from_env()
    if privacy:
        gw_cfg = GatewayConfig(default_backend=gw_cfg.default_backend, privacy_mode=True)
    try:
        client = make_gateway_client(Task.FIX, gateway_cfg=gw_cfg)
    except PrivacyModeViolation as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from None
    if client is None:
        typer.echo(
            "No model routed for this task: set BULWARK_LLM_ENABLED=1 (+key) for hosted, or "
            "BULWARK_LLM_LOCAL_ENABLED=1 for local. Falling back to static text.",
            err=True,
        )
    finding = _load_finding(finding_json, index)
    with get_session_factory()() as s:
        result = suggest(finding, KnowledgeBase(s), client, _code_for(finding, source))
    typer.echo(json.dumps(asdict(result), indent=2))


@app.command("update-feeds")
def update_feeds_cmd() -> None:
    """Download the EPSS and CISA KEV feeds behind risk scores (the worker also does this daily)."""
    from core.risk import update_feeds

    meta = update_feeds()
    for name, detail in (("epss", meta.get("epss")), ("kev", meta.get("kev"))):
        err = meta["errors"].get(name)
        typer.echo(f"{name}: {'FAILED ' + err if err else detail}")
    if meta["errors"]:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()


ci_app = typer.Typer(
    help="Continuous-integration helpers: compare scans, gate, comment on pull requests."
)
app.add_typer(ci_app, name="ci")


def _gh_output(path: Path | None, values: dict[str, str]) -> None:
    if path:
        with path.open("a", encoding="utf-8") as fh:
            for k, v in values.items():
                fh.write(f"{k}={v}\n")


@ci_app.command("compare")
def ci_compare(
    head: Path = typer.Option(..., help="`bulwark scan --format json` output for the change."),
    base: Path | None = typer.Option(
        None, help="The same for the base branch (for new-findings-only)."
    ),
    fail_on: str = typer.Option("none", help="none, low, medium, high or critical."),
    label: str = typer.Option("repository", help="Name shown in reports."),
    sarif_out: Path | None = typer.Option(None, help="Write the head scan as SARIF 2.1.0."),
    comment_out: Path | None = typer.Option(
        None, help="Write the pull-request comment (markdown)."
    ),
    summary_out: Path | None = typer.Option(
        None, help="Append a job summary (e.g. $GITHUB_STEP_SUMMARY)."
    ),
    run_url: str = typer.Option("", help="Link to the workflow run, shown in the comment."),
    github_output: Path | None = typer.Option(None, help="Append outputs (e.g. $GITHUB_OUTPUT)."),
    policy: Path | None = typer.Option(
        None,
        help="A Rego policy file (plan §20.4); its data.gate.pull_request.deny drives the check too.",
    ),
    sbom: Path | None = typer.Option(
        None,
        help=(
            "A CycloneDX SBOM (`bulwark sbom` output, plan §20.5). Joins each finding's package "
            "license onto it before policy evaluation, so a policy testing issue.license has "
            "something real to match against. No effect without --policy."
        ),
    ),
) -> None:
    """Exit 0 if the change passes the threshold and policy, 1 if it does not, 2 on unusable input."""
    from core.ci import breaches, compare, load_scan, markdown_comment, report_data
    from core.export import render
    from core.policy import evaluate_gate
    from core.sbom import SbomError, summarize

    try:
        head_scan = load_scan(head)
        base_scan = load_scan(base) if base and base.exists() else None
        cmp = compare(head_scan, base_scan)
        bad = breaches(cmp.gate_set(), fail_on)
    except (ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    policy_denials: tuple[str, ...] = ()
    if policy is not None:
        gate_set = cmp.gate_set()
        if sbom is not None:
            from core.sbom.enrich import apply_licenses

            try:
                gate_set = apply_licenses(gate_set, summarize(sbom.read_bytes()))
            except (SbomError, OSError) as exc:
                typer.echo(f"error: --sbom: {exc}", err=True)
                raise typer.Exit(2) from exc
        result = evaluate_gate(gate_set, policy.read_text(encoding="utf-8"))
        if result.error is not None:
            typer.echo(f"error: policy evaluation failed: {result.error}", err=True)
            raise typer.Exit(2)
        policy_denials = result.deny
    failed = bool(bad) or bool(policy_denials)
    comment = markdown_comment(cmp, fail_on, failed, run_url, policy_denials)
    if sarif_out:
        sarif_out.write_bytes(render("sarif", report_data(label, cmp)))
    if comment_out:
        comment_out.write_text(comment, encoding="utf-8")
    if summary_out:
        with summary_out.open("a", encoding="utf-8") as fh:
            fh.write(comment + "\n")
    shown = len(cmp.gate_set())
    gh_outputs = {
        "new-findings": str(shown),
        "total-findings": str(len(cmp.head.findings)),
        "failed": str(failed).lower(),
        "baseline": str(cmp.baseline_available).lower(),
    }
    if policy is not None:
        gh_outputs["policy-violations"] = str(len(policy_denials))
    _gh_output(github_output, gh_outputs)
    scope = "new" if cmp.baseline_available else "total"
    policy_note = f"; {len(policy_denials)} policy violation(s)" if policy is not None else ""
    typer.echo(
        f"{shown} {scope} finding(s); {len(bad)} at or above '{fail_on}'{policy_note}"
        + ("; failing the check" if failed else "")
    )
    raise typer.Exit(1 if failed else 0)


@ci_app.command("comment")
def ci_comment(
    body: Path = typer.Option(..., help="Markdown file from `bulwark ci compare --comment-out`."),
    repo: str = typer.Option(..., help="owner/name"),
    pr: int = typer.Option(..., help="Pull request number."),
    api_url: str = typer.Option("https://api.github.com", help="GitHub API base URL (Enterprise)."),
    strict: bool = typer.Option(False, help="Fail if the comment cannot be posted."),
) -> None:
    """Create or update the one Bulwark comment (token: GITHUB_TOKEN; forks cannot comment)."""
    import os

    from core.ci.github import CommentError, upsert_comment

    try:
        action = upsert_comment(
            repo, pr, body.read_text("utf-8"), os.environ.get("GITHUB_TOKEN", ""), api_url
        )
        typer.echo(f"comment {action}")
    except (CommentError, OSError) as exc:
        typer.echo(f"warning: comment not posted: {exc}", err=True)
        if strict:
            raise typer.Exit(1) from exc


@app.command("scan-image")
def scan_image_cmd(
    image: str = typer.Argument(
        ..., help="A LOCAL image, e.g. myapp:latest (never pulled for you)."
    ),
    fmt: str = typer.Option("json", "--format", help="json (default) or sarif."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write here instead of stdout."
    ),
) -> None:
    """Lint a built container image with Dockle (CIS Docker benchmark)."""
    import re
    import subprocess
    import tempfile

    from core.adapters.dockle import IMAGE_ARCHIVE
    from core.config import scratch_dir

    if fmt not in ("json", "sarif"):
        raise typer.BadParameter("use json or sarif", param_hint="--format")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,200}", image):
        raise typer.BadParameter("not a valid image reference", param_hint="IMAGE")
    with tempfile.TemporaryDirectory(prefix="bulwark-image-", dir=scratch_dir()) as tmp:
        saved = subprocess.run(
            ["docker", "save", "--output", str(Path(tmp) / IMAGE_ARCHIVE), "--", image],
            capture_output=True,
            check=False,
        )
        if saved.returncode != 0:
            msg = saved.stderr.decode(errors="replace").strip()[-300:] or "docker save failed"
            typer.echo(f"error: {msg} (pull or build the image first)", err=True)
            raise typer.Exit(2)
        result = scan(Path(tmp), ["dockle"], ignore=IgnoreRules())
    if fmt == "sarif":
        from core.ci.compare import Comparison, Scan
        from core.ci.report import report_data
        from core.export import render

        scan_ = Scan([f.to_dict() for f in result.findings], result.tool_status)
        data = render("sarif", report_data(image, Comparison(head=scan_)))
    else:
        data = json.dumps(
            {"tool_status": result.tool_status, "findings": [f.to_dict() for f in result.findings]},
            indent=2,
        ).encode()
    if output:
        output.write_bytes(data)
        typer.echo(f"wrote {output}", err=True)
    else:
        typer.echo(data.decode())


@app.command("sbom")
def sbom_cmd(
    source: str = typer.Argument(..., help="Directory, archive or public Git URL."),
    output: Path = typer.Option(
        ..., "--output", "-o", help="Where to write the CycloneDX 1.6 JSON."
    ),
) -> None:
    """Write a software bill of materials (CycloneDX 1.6, from Syft in the sandbox)."""
    from core.sbom import SbomError, generate_sbom

    try:
        with materialize(source) as workspace:
            sbom = generate_sbom(workspace, source if "://" in source else Path(source).name)
    except (IngestError, SbomError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    output.write_bytes(sbom.raw)
    kinds = ", ".join(f"{k} {v}" for k, v in sorted(sbom.ecosystems.items())) or "none"
    typer.echo(
        f"wrote {output}: {sbom.components} components (CycloneDX {sbom.spec_version}; {kinds})",
        err=True,
    )


supply_chain_app = typer.Typer(
    help="Supply-chain risk (plan §20.5): typosquats and OpenSSF Scorecard for direct dependencies."
)
app.add_typer(supply_chain_app, name="supply-chain")


@supply_chain_app.command("analyze")
def supply_chain_analyze(
    sbom: Path = typer.Option(..., help="A CycloneDX SBOM (`bulwark sbom` output)."),
    output: Path = typer.Option(..., "--output", "-o", help="Where to write the JSON report."),
    scorecard: bool = typer.Option(
        True,
        help=(
            "Also fetch OpenSSF Scorecard results for direct dependencies (network: "
            "api.deps.dev to resolve a source repo, api.securityscorecards.dev for its score). "
            "Malicious-package flags are not here -- they already show up as CRITICAL findings "
            "from `bulwark scan`'s own osv-scanner (plan §20.5); this SBOM alone carries no "
            "vulnerability data to check them against."
        ),
    ),
) -> None:
    """Typosquat detection over the SBOM's own packages, plus (optionally) OpenSSF Scorecard for
    its direct dependencies (plan §20.5)."""
    from core.sbom import SbomError, summarize
    from core.supplychain import enrich_direct_dependencies, find_typosquats

    try:
        parsed = summarize(sbom.read_bytes())
    except (SbomError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    typosquats = find_typosquats(parsed.packages)
    scores: dict[str, dict[str, Any]] = {}
    if scorecard:
        scores = {
            purl: {"score": r.score, "checks": r.checks, "date": r.date}
            for purl, r in enrich_direct_dependencies(parsed.direct_purls).items()
        }
    report = {
        "typosquats": [f.to_dict() for f in typosquats],
        "scorecard": scores,
        "direct_dependencies": sorted(parsed.direct_purls),
        "transitive_dependencies": sorted(parsed.transitive_purls),
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True))
    typer.echo(
        f"wrote {output}: {len(typosquats)} possible typosquat(s), "
        f"{len(scores)} Scorecard result(s) for {len(parsed.direct_purls)} direct dependencies",
        err=True,
    )


attest_app = typer.Typer(help="Sign scan artifacts and attest their provenance (cosign key pair).")
app.add_typer(attest_app, name="attest")


def _attest_guard(fn: Any) -> Any:
    from core.attest import AttestError

    def wrapped(*a: Any, **k: Any) -> Any:
        try:
            return fn(*a, **k)
        except AttestError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1) from exc

    return wrapped


@attest_app.command("sign")
def attest_sign(
    file: Path = typer.Argument(
        ..., exists=True, dir_okay=False, help="Report, SARIF or SBOM to sign."
    ),
    key: Path = typer.Option(..., help="cosign private key (password in COSIGN_PASSWORD)."),
    bundle: Path | None = typer.Option(None, help="Output (default: FILE.sig.bundle)."),
) -> None:
    """Sign FILE. The bundle is the signature; no transparency-log entry is made."""
    from core.attest import sign_blob

    out = bundle or file.with_name(file.name + ".sig.bundle")
    _attest_guard(sign_blob)(file, key, out)
    typer.echo(f"signed {file.name} -> {out}")


@attest_app.command("provenance")
def attest_provenance(
    file: Path = typer.Argument(
        ..., exists=True, dir_okay=False, help="The artifact the attestation is about."
    ),
    scan_json: Path = typer.Option(
        ..., "--scan", exists=True, help="`bulwark scan --format json` output."
    ),
    key: Path = typer.Option(..., help="cosign private key (password in COSIGN_PASSWORD)."),
    artifact: list[str] = typer.Option(
        [], help="Extra artifacts to list, NAME=PATH (e.g. sbom=sbom.cdx.json)."
    ),
    source_label: str = typer.Option("", help="What was scanned, e.g. owner/repo."),
    commit: str = typer.Option("", help="Commit that was scanned."),
    bundle: Path | None = typer.Option(None, help="Output (default: FILE.provenance.bundle)."),
) -> None:
    """Sign an in-toto attestation: which Bulwark and scanner images produced FILE, and the result counts."""
    import json

    from core.attest import PREDICATE_TYPE, attest_blob, build_predicate
    from core.scan import ADAPTERS

    try:
        scan_doc = json.loads(scan_json.read_text("utf-8"))
        extra = dict(a.split("=", 1) for a in artifact)
    except (ValueError, OSError) as exc:
        typer.echo(f"error: cannot read the scan output or --artifact: {exc}", err=True)
        raise typer.Exit(2) from exc
    arts = {file.name: file, scan_json.name: scan_json, **{n: Path(p) for n, p in extra.items()}}
    images = {n: a.spec.image for n, a in ADAPTERS.items()}
    predicate = build_predicate(scan_doc, arts, images, {"label": source_label, "commit": commit})
    out = bundle or file.with_name(file.name + ".provenance.bundle")
    _attest_guard(attest_blob)(file, predicate, PREDICATE_TYPE, key, out)
    typer.echo(f"attested {file.name} -> {out}")


@attest_app.command("verify")
def attest_verify(
    file: Path = typer.Argument(..., exists=True, dir_okay=False),
    pub: Path = typer.Option(..., help="cosign public key."),
    sig_bundle: Path | None = typer.Option(
        None, help="Signature bundle (default: FILE.sig.bundle if present)."
    ),
    provenance_bundle: Path | None = typer.Option(
        None, help="Attestation bundle (default: FILE.provenance.bundle if present)."
    ),
) -> None:
    """Verify FILE against its signature and/or provenance attestation. Exit 1 if any check fails."""
    import json

    from core.attest import PREDICATE_TYPE, sha256_file, verify_attestation, verify_blob

    sig = sig_bundle or file.with_name(file.name + ".sig.bundle")
    prov = provenance_bundle or file.with_name(file.name + ".provenance.bundle")
    checked = 0
    if sig.exists():
        _attest_guard(verify_blob)(file, pub, sig)
        typer.echo(f"signature OK ({sig.name})")
        checked += 1
    if prov.exists():
        stmt = _attest_guard(verify_attestation)(file, PREDICATE_TYPE, pub, prov)
        pred = stmt.get("predicate", {})
        typer.echo(f"attestation OK ({prov.name})")
        typer.echo(json.dumps({"scanner": pred.get("scanner"), "source": pred.get("source"),
                               "result": pred.get("result"), "generatedAt": pred.get("generatedAt")}, indent=2))  # fmt: skip
        listed = {a.get("name"): a.get("sha256") for a in pred.get("artifacts", [])}
        if listed.get(file.name) not in (None, sha256_file(file)):
            typer.echo("error: attested digest differs from this file", err=True)
            raise typer.Exit(1)
        checked += 1
    if not checked:
        typer.echo("error: no signature or attestation bundle found next to the file", err=True)
        raise typer.Exit(2)


token_app = typer.Typer(
    help="Scoped API tokens (Week 29 backfill, ADR-0018): create, list and revoke, per organization."
)
app.add_typer(token_app, name="token")


@token_app.command("create")
def token_create(
    org_id: str = typer.Option(..., help="The organization this token authenticates as."),
    name: str = typer.Option(..., help="A human label, e.g. 'CI pipeline' or 'laptop'."),
    scope: list[str] = typer.Option(
        ..., "--scope", help="Repeatable. Valid: scans:read, scans:write."
    ),
    expires_days: int | None = typer.Option(
        None, help="Expire this many days from now. Omit for a token that never expires."
    ),
) -> None:
    """Mint a token and print it once. It is never shown or stored again -- only its hash is."""
    from datetime import datetime, timedelta, timezone

    from core.persistence import repo
    from core.persistence.db import get_session_factory
    from core.tenancy import set_session_org
    from core.tokens import TokenError, parse_scopes

    try:
        scopes = parse_scopes(scope)
    except TokenError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days) if expires_days else None
    with get_session_factory()() as s:
        set_session_org(
            s, org_id
        )  # this write needs org context set explicitly (no request path here)
        row, raw = repo.create_api_token(
            s, org_id=org_id, name=name, scopes=sorted(scopes), expires_at=expires_at
        )
        token_id, display_prefix = row.id, row.display_prefix  # read before the session closes
        repo.append_audit_entry(
            s, actor="cli:token-create", action="token.created", target=token_id,
            payload={"org_id": org_id, "name": name, "scopes": sorted(scopes)},
        )  # fmt: skip
    typer.echo(f"token: {raw}")
    typer.echo("(shown once -- store it now; Bulwark never displays it again)")
    typer.echo(json.dumps({"id": token_id, "display_prefix": display_prefix, "scopes": sorted(scopes)}))  # fmt: skip


@token_app.command("list")
def token_list(
    org_id: str = typer.Option(..., help="The organization to list tokens for.")
) -> None:
    from core.persistence import repo
    from core.persistence.db import get_session_factory

    with get_session_factory()() as s:
        rows = repo.list_api_tokens(s, org_id)
    typer.echo(
        json.dumps(
            [
                {
                    "id": r.id, "name": r.name, "display_prefix": r.display_prefix,
                    "scopes": r.scopes, "created_at": r.created_at.isoformat(),
                    "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                    "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                    "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                }  # fmt: skip
                for r in rows
            ],
            indent=2,
        )
    )


@token_app.command("revoke")
def token_revoke(
    token_id: str = typer.Argument(..., help="The token's id, from `token list`.")
) -> None:
    from core.persistence import repo
    from core.persistence.db import get_session_factory

    with get_session_factory()() as s:
        ok = repo.revoke_api_token(s, token_id)
        if ok:
            repo.append_audit_entry(
                s, actor="cli:token-revoke", action="token.revoked", target=token_id, payload={}
            )
    if not ok:
        typer.echo("error: no such token, or it was already revoked", err=True)
        raise typer.Exit(1)
    typer.echo(f"revoked {token_id}")


secrets_app = typer.Typer(
    help="Secrets in OpenBao (Week 47 task 4, plan §22.2, ADR-0033), instead of plain env files."
)
app.add_typer(secrets_app, name="secrets")

# core.secrets.resolve.resolve_secret's own kv_path for each -- kept in sync by hand since there are
# only four call sites (core/config.py x3, core/llm/client.py x1), not worth a shared registry yet.
_MIGRATABLE_SECRETS = {
    "bulwark/api-token": "BULWARK_API_TOKEN",
    "bulwark/github-webhook-secret": "BULWARK_GITHUB_WEBHOOK_SECRET",
    "bulwark/github-app-private-key": "BULWARK_GITHUB_APP_PRIVATE_KEY",
    "bulwark/llm-api-key": "BULWARK_LLM_API_KEY",
}


@secrets_app.command("migrate-env")
def secrets_migrate_env() -> None:
    """Copies every secret core.secrets.resolve.resolve_secret knows about from its current
    environment variable into OpenBao, so it can be removed from .env / plain deployment config
    afterwards. Requires BULWARK_OPENBAO_ADDR/BULWARK_OPENBAO_TOKEN already set in this shell --
    this command only writes TO OpenBao, it never configures access to one."""
    import os

    from core.secrets.openbao import OpenBaoClient, OpenBaoError

    addr, token = os.environ.get("BULWARK_OPENBAO_ADDR", ""), os.environ.get(
        "BULWARK_OPENBAO_TOKEN", ""
    )
    if not addr or not token:
        typer.echo(
            "error: BULWARK_OPENBAO_ADDR and BULWARK_OPENBAO_TOKEN must both be set", err=True
        )
        raise typer.Exit(1)
    client = OpenBaoClient(addr=addr, token=token)
    client.ensure_kv_engine_enabled()
    migrated: list[str] = []
    skipped: list[str] = []
    for kv_path, env_var in _MIGRATABLE_SECRETS.items():
        value = os.environ.get(env_var, "")
        if not value:
            skipped.append(env_var)
            continue
        try:
            client.put_secret(kv_path, value)
        except OpenBaoError as exc:
            typer.echo(f"error writing {kv_path}: {exc}", err=True)
            raise typer.Exit(1) from exc
        migrated.append(env_var)
    typer.echo(f"Migrated {len(migrated)} secret(s) to OpenBao: {', '.join(migrated) or '(none)'}")
    if skipped:
        typer.echo(f"Skipped (not set in this environment): {', '.join(skipped)}")
    typer.echo("You can now remove these from .env / your deployment's plain environment config.")


audit_app = typer.Typer(help="Tamper-evident audit log (Week 30 backfill, ADR-0019).")
app.add_typer(audit_app, name="audit")


@audit_app.command("verify")
def audit_verify() -> None:
    """Walk the whole chain and recompute every hash. Exit 1 if anything doesn't match."""
    import core.audit as audit
    from core.persistence import repo
    from core.persistence.db import get_session_factory

    with get_session_factory()() as s:
        entries = repo.list_audit_entries(s)
        checkpoints = repo.list_checkpoints(s)
    result = audit.verify_chain(entries)
    out = {
        "entries_checked": result.checked,
        "chain_ok": result.ok,
        "checkpoints": len(checkpoints),
    }
    if not result.ok:
        out["broken_at_seq"] = result.broken_at_seq
        out["reason"] = result.reason
    typer.echo(json.dumps(out, indent=2))
    if not result.ok:
        raise typer.Exit(1)
    for cp in checkpoints:
        if cp.seq_end > result.checked:
            typer.echo(
                f"warning: checkpoint at seq {cp.seq_end} covers entries beyond the current chain "
                "(entries were removed since it was published, or the chain was truncated)",
                err=True,
            )
            raise typer.Exit(1)


@audit_app.command("checkpoint")
def audit_checkpoint(
    key: Path = typer.Option(..., help="cosign private key (password in COSIGN_PASSWORD)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would be checkpointed; sign and publish nothing."
    ),
) -> None:
    """Sign the current chain head and publish it to Sigstore's Rekor -- a REAL, public, permanent
    transparency-log entry. Not run automatically on a schedule yet (a documented Week 30 scope
    cut); run this by hand or from your own cron/CI until it is."""
    from core.attest.cosign import AttestError
    from core.audit_rekor import sign_checkpoint
    from core.persistence import repo
    from core.persistence.db import get_session_factory

    with get_session_factory()() as s:
        entries = repo.list_audit_entries(s)
        if not entries:
            typer.echo("nothing to checkpoint: the audit log is empty")
            return
        last = entries[-1]
        latest_cp = repo.latest_checkpoint(s)
        if latest_cp is not None and latest_cp.seq_end == last.seq:
            typer.echo(f"already checkpointed at seq {last.seq}")
            return
        if dry_run:
            typer.echo(
                json.dumps({"would_checkpoint_seq": last.seq, "chain_hash": last.entry_hash})
            )
            return
        try:
            bundle, log_index = sign_checkpoint(last.seq, last.entry_hash, key)
        except AttestError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1) from exc
        cp = repo.record_checkpoint(
            s, seq_end=last.seq, chain_hash=last.entry_hash, signature_bundle=bundle,
            rekor_log_index=log_index,
        )  # fmt: skip
        seq_end = last.seq  # read before append_audit_entry's commit expires this instance
        repo.append_audit_entry(
            s, actor="cli:audit-checkpoint", action="audit.checkpointed", target=cp.id,
            payload={"seq_end": seq_end, "rekor_log_index": log_index},
        )  # fmt: skip
    typer.echo(json.dumps({"seq_end": seq_end, "rekor_log_index": log_index}))
