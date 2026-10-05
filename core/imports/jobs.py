"""The worker side of an import (plan §42.1): take a queued ImportRecord through parse, then either
preview or apply it.

`POST /v2/ingest` answers 202 and returns before any of this happens, so this has to be safe to run
exactly as the API leaves things and safe to run twice (Celery redelivers): a record that is no
longer `queued` is left alone. Whatever goes wrong becomes `status="failed"` with a message a person
can act on -- never an exception that leaves a record stuck in `processing`, and never a partly
applied import: `apply_import` is one transaction.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from core.config import Settings
from core.imports import mapper, service
from core.imports.parsers import ParseResult, run_parser
from core.imports.parsers.base import ParseLimits
from core.imports.parsers.sandbox import parse_in_sandbox
from core.imports.prepare import prepare
from core.persistence import repo
from core.persistence.models import ImportRecord

log = logging.getLogger(__name__)

NOT_CLOSED_WARNING = (
    "close_missing was ignored: this kind of file does not say what is no longer present, so it "
    "cannot close anything"
)


def _parse(
    s: Session, org_id: str, path: Path, parser_name: str, settings: Settings
) -> ParseResult:
    """A saved mapping (`universal:<id>`) is looked up here, outside the sandbox, and its spec is
    shipped in beside the file; inside, it is a parser like any other (ADR-0043)."""
    parser, spec = mapper.resolve(s, org_id, parser_name)
    return parse_file(path, parser_name, settings, parser=parser, mapping=spec)


def parse_file(
    path: Path,
    parser_name: str,
    settings: Settings,
    *,
    parser: Any = None,
    mapping: dict[str, Any] | None = None,
    max_bytes: int | None = None,
) -> ParseResult:
    limits = ParseLimits(max_bytes=max_bytes or settings.max_upload_bytes)
    if settings.ingest_sandbox:
        return parse_in_sandbox(path, parser_name, limits, mapping=mapping)
    with path.open("rb") as fh:  # in-process: tests and Docker-less local development only
        return run_parser(parser, fh, limits)


def _fail(s: Session, record: ImportRecord, message: str) -> ImportRecord:
    s.rollback()
    record.status, record.error = "failed", message[:2000]
    _discard_upload(record)
    s.commit()
    return record


def _discard_upload(record: ImportRecord) -> None:
    if record.upload_path:
        Path(record.upload_path).unlink(missing_ok=True)
        record.upload_path = None


def process_import(
    s: Session, import_id: str, org_id: str, settings: Settings
) -> ImportRecord | None:
    """Run one queued import to its next resting state: `applied`, `previewed`, `duplicate` or
    `failed`. Returns None for an id this org does not own (or that no longer exists)."""
    record = repo.get_import_record(s, import_id, org_id)
    if record is None:
        log.warning("import %s not found for org %s", import_id, org_id)
        return None
    if record.status != "queued":
        return record  # a redelivered task for an import that already ran
    record.status = "processing"
    s.commit()
    try:
        if not record.upload_path or not Path(record.upload_path).is_file():
            return _fail(s, record, "the uploaded file is no longer available; upload it again")
        try:
            result = _parse(s, org_id, Path(record.upload_path), record.parser, settings)
        except ValueError as exc:  # a mapping that was deleted, or an unknown parser
            return _fail(s, record, str(exc))
        if not result.complete:
            # An incomplete parse is refused outright: reimport closes what a file no longer
            # lists, so a half-read file must never be applied (ADR-0040, parsers/base.py).
            return _fail(s, record, f"The file could not be read: {result.error or 'unreadable'}")

        findings = prepare(result.findings)
        warnings = list(result.warnings)
        close_missing = record.close_missing
        if close_missing and not result.can_close_missing:
            close_missing = False
            warnings.append(NOT_CLOSED_WARNING)

        if record.mode == "preview":
            preview = service.preview_import(
                s,
                org_id=org_id,
                test_id=record.test_id,
                findings=findings,
                close_missing=close_missing,
                scope=record.scope,
            )
            record.preview = preview.to_dict()
            record.warnings = warnings
            record.close_missing = close_missing
            record.status = "previewed"  # the upload is kept: confirming applies it
            s.commit()
            return record

        upload = Path(record.upload_path)  # apply_import clears the column; keep the path to delete
        applied = service.apply_import(
            s,
            org_id=org_id,
            test_id=record.test_id,
            findings=findings,
            parser=record.parser,
            file_digest=record.file_digest,
            file_name=record.file_name,
            size_bytes=record.size_bytes,
            close_missing=close_missing,
            scope=record.scope,
            created_by=record.created_by,
            warnings=warnings,
            record=record,
        )
        upload.unlink(missing_ok=True)  # applied or noticed as a duplicate: the file is done with
        return applied.record
    except service.ImportRequestError as exc:
        return _fail(s, record, str(exc))
    except Exception:  # noqa: BLE001 - a worker must record the failure, not die with it
        log.exception("import %s failed", import_id)
        return _fail(s, record, "the import failed unexpectedly; it was not applied")
