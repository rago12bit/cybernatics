"""core.precommit.sast_scan: the native, AST-based SAST checks the pre-commit hook runs on staged
Python files (Week 51 task 4, plan §23) -- no subprocess, no container, a deliberately narrow
complement to the dockerized Bandit adapter (core/adapters/bandit.py)."""

from __future__ import annotations

from core.models import Category
from core.precommit.sast_scan import scan_python_sast


def _rule_ids(path: str, text: str) -> set[str]:
    findings = scan_python_sast(path, text)
    return {rid for f in findings for rids in f.evidence.rule_ids.values() for rid in rids}


def test_eval_and_exec_fire_pca001() -> None:
    assert _rule_ids("x.py", "eval(user_input)") == {"PCA001"}
    assert _rule_ids("x.py", "exec(user_input)") == {"PCA001"}


def test_os_system_and_shell_true_fire_pca002() -> None:
    assert _rule_ids("x.py", "import os\nos.system(cmd)") == {"PCA002"}
    assert _rule_ids("x.py", "subprocess.run(cmd, shell=True)") == {"PCA002"}


def test_subprocess_without_shell_true_does_not_fire() -> None:
    assert _rule_ids("x.py", "subprocess.run([cmd, arg])") == set()
    assert _rule_ids("x.py", "subprocess.run(cmd, shell=False)") == set()


def test_verify_false_fires_pca003_regardless_of_the_calling_library() -> None:
    assert _rule_ids("x.py", "requests.get(url, verify=False)") == {"PCA003"}
    assert _rule_ids("x.py", "httpx.post(url, verify=False)") == {"PCA003"}
    assert _rule_ids("x.py", "ssl._create_unverified_context()") == {"PCA003"}


def test_verify_true_does_not_fire() -> None:
    assert _rule_ids("x.py", "requests.get(url, verify=True)") == set()
    assert _rule_ids("x.py", "requests.get(url)") == set()


def test_pickle_load_and_loads_fire_pca004() -> None:
    assert _rule_ids("x.py", "pickle.load(f)") == {"PCA004"}
    assert _rule_ids("x.py", "pickle.loads(data)") == {"PCA004"}


def test_yaml_load_without_safe_loader_fires_pca005() -> None:
    assert _rule_ids("x.py", "yaml.load(stream)") == {"PCA005"}
    assert _rule_ids("x.py", "yaml.load(stream, Loader=yaml.Loader)") == {"PCA005"}


def test_yaml_load_with_safe_loader_does_not_fire() -> None:
    assert _rule_ids("x.py", "yaml.load(stream, Loader=yaml.SafeLoader)") == set()
    assert _rule_ids("x.py", "yaml.safe_load(stream)") == set()


def test_tempfile_mktemp_fires_pca006() -> None:
    assert _rule_ids("x.py", "path = tempfile.mktemp()") == {"PCA006"}


def test_weak_hash_fires_pca007_as_the_only_rule() -> None:
    assert _rule_ids("x.py", "hashlib.md5(data)") == {"PCA007"}
    assert _rule_ids("x.py", "hashlib.sha1(data)") == {"PCA007"}


def test_sha256_does_not_fire() -> None:
    assert _rule_ids("x.py", "hashlib.sha256(data)") == set()


def test_clean_file_produces_no_findings() -> None:
    text = "\n".join(["import json", "", "def load(path):", "    return json.load(open(path))"])
    assert scan_python_sast("x.py", text) == []


def test_syntactically_invalid_file_is_skipped_not_raised() -> None:
    assert scan_python_sast("x.py", "def broken(:\n    pass") == []


def test_one_finding_per_call_site_even_if_two_rules_could_match() -> None:
    # subprocess.run(..., shell=True) could in principle also look like a "verify=False"-shaped
    # call if rules were checked independently per keyword; the real risk here is PCA002 only.
    findings = scan_python_sast("x.py", "subprocess.run(cmd, shell=True)")
    assert len(findings) == 1


def test_findings_are_category_sast_with_appropriate_severities() -> None:
    [f] = scan_python_sast("x.py", "eval(x)")
    assert f.taxonomy.category is Category.SAST
    assert f.scoring.normalized_severity.value == "HIGH"
    [f] = scan_python_sast("x.py", "hashlib.md5(x)")
    assert f.scoring.normalized_severity.value == "LOW"
    [f] = scan_python_sast("x.py", "pickle.loads(x)")
    assert f.scoring.normalized_severity.value == "MEDIUM"


def test_line_number_points_at_the_call() -> None:
    text = "a = 1\nb = 2\neval(x)\n"
    [f] = scan_python_sast("x.py", text)
    assert f.location.start_line == 3
