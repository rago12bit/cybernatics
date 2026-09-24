from core.models import Category, Finding, Location, Taxonomy
from core.redact import WITHHELD, redact_near_secrets


def mk(cat: Category, path: str, line: int, snippet: str) -> Finding:
    return Finding(
        id=f"{cat.value}:{line}",
        title="t",
        description="d",
        location=Location(path, line, line, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(cat),
    )


def test_snippets_near_a_secret_are_withheld_others_untouched() -> None:
    secret = mk(Category.SECRETS, "a.py", 20, "[secret redacted]")
    near = mk(Category.SAST, "a.py", 18, 'KEY = "s3cr3t"')
    far = mk(Category.SAST, "a.py", 60, "x = 1")
    other_file = mk(Category.SAST, "b.py", 20, "y = 2")
    out = redact_near_secrets([secret, near, far, other_file])
    by_id = {(f.location.path, f.location.start_line): f for f in out}
    assert by_id[("a.py", 18)].location.snippet == WITHHELD
    assert by_id[("a.py", 18)].location.snippet_hash == Location.hash_snippet(WITHHELD)
    assert by_id[("a.py", 60)].location.snippet == "x = 1"
    assert by_id[("b.py", 20)].location.snippet == "y = 2"


def test_no_secrets_is_a_noop() -> None:
    f = mk(Category.SAST, "a.py", 1, "x")
    assert redact_near_secrets([f])[0].location.snippet == "x"


def test_quoted_literals_in_text_are_scrubbed_near_secrets() -> None:
    secret = mk(Category.SECRETS, "a.py", 5, "[secret redacted]")
    near = mk(Category.SAST, "a.py", 5, "x")
    near.title = "Possible hardcoded password: 'abcdef123456'"
    near.description = 'value "abcdef123456" used'
    out = redact_near_secrets([secret, near])[1]
    assert "abcdef123456" not in out.title + out.description
