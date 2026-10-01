"""core.precommit.runner.scan_files: composes the secrets + SAST checks over a batch of files,
applies .bulwarkignore, and reports the severity-ranked blocking set (Week 51 task 4, plan §23).
Source-agnostic on purpose -- the CLI feeds it both git-staged content and `pre-commit`
framework-supplied file paths through the same (path, content) shape."""

from __future__ import annotations

from core.ignore import IgnoreRules
from core.precommit.runner import MAX_FILE_BYTES, scan_files

SECRET_LINE = "aws_key = 'AKIAABCDEFGHIJKLMNOP'"


def test_scans_both_secrets_and_python_sast_in_one_pass() -> None:
    result = scan_files([("a.py", SECRET_LINE + "\neval(x)\n")])
    rule_ids = {
        rid for f in result.findings for rids in f.evidence.rule_ids.values() for rid in rids
    }
    assert rule_ids == {"PCS001", "PCA001"}
    assert result.files_scanned == 1


def test_sast_only_runs_on_dot_py_files() -> None:
    result = scan_files([("a.txt", "eval(x)\n")])
    assert result.findings == []  # secrets would still fire on .txt; SAST does not
    result = scan_files([("a.py", "eval(x)\n")])
    assert len(result.findings) == 1


def test_secrets_rule_fires_regardless_of_file_extension() -> None:
    result = scan_files([("notes.txt", SECRET_LINE)])
    assert len(result.findings) == 1


def test_binary_content_none_is_skipped_not_scanned() -> None:
    result = scan_files([("image.png", None)])
    assert result.findings == []
    assert result.files_scanned == 0
    assert result.files_skipped_binary == ["image.png"]


def test_bytes_content_that_fails_utf8_decoding_is_treated_as_binary() -> None:
    result = scan_files([("blob.bin", b"\xff\xfe\x00\x01")])
    assert result.files_scanned == 0
    assert result.files_skipped_binary == ["blob.bin"]


def test_bytes_content_that_decodes_cleanly_is_scanned() -> None:
    result = scan_files([("a.py", SECRET_LINE.encode())])
    assert result.files_scanned == 1
    assert len(result.findings) == 1


def test_oversized_file_is_skipped_not_scanned() -> None:
    huge = "x = 1\n" * (MAX_FILE_BYTES // 5)
    result = scan_files([("huge.py", huge)])
    assert result.files_scanned == 0
    assert result.files_skipped_large == ["huge.py"]


def test_ignore_rules_drop_findings_in_matched_paths_and_count_them() -> None:
    rules = IgnoreRules(["tests/fixtures/"])
    result = scan_files(
        [("tests/fixtures/a.py", SECRET_LINE), ("src/a.py", SECRET_LINE)], ignore_rules=rules
    )
    assert len(result.findings) == 1
    assert result.findings[0].location.path == "src/a.py"
    assert result.ignored_count == 1


def test_elapsed_seconds_is_populated_and_small() -> None:
    result = scan_files([("a.py", SECRET_LINE)])
    assert 0 <= result.elapsed_seconds < 2.0


def test_blocking_defaults_to_high_and_above() -> None:
    result = scan_files([("a.py", "hashlib.md5(x)\n")])  # LOW
    assert result.findings
    assert result.blocking() == []  # LOW doesn't block under the default HIGH floor


def test_blocking_at_low_floor_includes_everything() -> None:
    result = scan_files([("a.py", "hashlib.md5(x)\n")])
    assert result.blocking("LOW") == result.findings


def test_blocking_includes_high_and_critical_but_not_medium() -> None:
    result = scan_files([("a.py", "eval(x)\npickle.loads(y)\n")])  # HIGH + MEDIUM
    blocking_titles = {f.title for f in result.blocking("HIGH")}
    assert any("eval" in t for t in blocking_titles)
    assert not any("pickle" in t for t in blocking_titles)
