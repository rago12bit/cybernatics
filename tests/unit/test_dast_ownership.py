from __future__ import annotations

import pytest

from core.dast import ownership


class _FakeResolver:
    def __init__(self, records: dict[str, list[str]]) -> None:
        self._records = records

    def resolve_txt(self, name: str) -> list[str]:
        if name not in self._records:
            raise LookupError(f"NXDOMAIN: {name}")
        return self._records[name]


class _FakeFetcher:
    def __init__(self, pages: dict[str, str]) -> None:
        self._pages = pages

    def get_text(self, url: str) -> str:
        if url not in self._pages:
            raise LookupError(f"404: {url}")
        return self._pages[url]


def test_generate_token_is_random_and_hex() -> None:
    a, b = ownership.generate_token(), ownership.generate_token()
    assert a != b
    assert len(a) == 32
    int(a, 16)  # does not raise


def test_dns_record_name_and_expected_value() -> None:
    assert ownership.dns_record_name("example.com") == "_bulwark-challenge.example.com"
    assert ownership.dns_expected_value("abc123") == "bulwark-site-verification=abc123"


def test_well_known_url() -> None:
    assert (
        ownership.well_known_url("example.com")
        == "https://example.com/.well-known/bulwark-verification.txt"
    )


def test_check_dns_txt_passes_when_the_exact_expected_record_is_present() -> None:
    token = "abc123"
    resolver = _FakeResolver(
        {"_bulwark-challenge.example.com": ["bulwark-site-verification=abc123"]}
    )
    outcome = ownership.check_dns_txt("example.com", token, resolver=resolver)
    assert outcome.ok is True
    assert outcome.error is None


def test_check_dns_txt_fails_when_no_record_exists() -> None:
    resolver = _FakeResolver({})
    outcome = ownership.check_dns_txt("example.com", "abc123", resolver=resolver)
    assert outcome.ok is False
    assert "DNS lookup" in outcome.error


def test_check_dns_txt_fails_when_record_has_the_wrong_value() -> None:
    resolver = _FakeResolver(
        {"_bulwark-challenge.example.com": ["bulwark-site-verification=WRONG"]}
    )
    outcome = ownership.check_dns_txt("example.com", "abc123", resolver=resolver)
    assert outcome.ok is False
    assert "no TXT record" in outcome.error


def test_check_dns_txt_passes_when_the_expected_record_is_one_of_several() -> None:
    resolver = _FakeResolver(
        {
            "_bulwark-challenge.example.com": [
                "v=spf1 include:_spf.example.com ~all",
                "bulwark-site-verification=abc123",
            ]
        }
    )
    outcome = ownership.check_dns_txt("example.com", "abc123", resolver=resolver)
    assert outcome.ok is True


def test_check_well_known_passes_when_the_file_contains_exactly_the_token() -> None:
    fetcher = _FakeFetcher({"https://example.com/.well-known/bulwark-verification.txt": "abc123\n"})
    outcome = ownership.check_well_known("example.com", "abc123", fetcher=fetcher)
    assert outcome.ok is True


def test_check_well_known_fails_on_wrong_content() -> None:
    fetcher = _FakeFetcher({"https://example.com/.well-known/bulwark-verification.txt": "nope"})
    outcome = ownership.check_well_known("example.com", "abc123", fetcher=fetcher)
    assert outcome.ok is False


def test_check_well_known_fails_when_unreachable() -> None:
    fetcher = _FakeFetcher({})
    outcome = ownership.check_well_known("example.com", "abc123", fetcher=fetcher)
    assert outcome.ok is False
    assert "fetching" in outcome.error


def test_verify_dispatches_by_method() -> None:
    resolver = _FakeResolver({"_bulwark-challenge.example.com": ["bulwark-site-verification=tok"]})
    fetcher = _FakeFetcher({})
    assert (
        ownership.verify("dns_txt", "example.com", "tok", resolver=resolver, fetcher=fetcher).ok
        is True
    )

    fetcher2 = _FakeFetcher({"https://example.com/.well-known/bulwark-verification.txt": "tok"})
    resolver2 = _FakeResolver({})
    assert (
        ownership.verify(
            "well_known", "example.com", "tok", resolver=resolver2, fetcher=fetcher2
        ).ok
        is True
    )


def test_verify_rejects_unknown_method() -> None:
    with pytest.raises(ValueError, match="unknown verification method"):
        ownership.verify(
            "carrier_pigeon",
            "example.com",
            "tok",
            resolver=_FakeResolver({}),
            fetcher=_FakeFetcher({}),
        )


def test_real_dns_resolver_against_a_real_domain_with_no_bulwark_record() -> None:
    """A genuine network DNS lookup (not a fake) against a real, stable domain that definitely has
    no `_bulwark-challenge` TXT record -- proves `DnsPythonResolver` actually talks to real DNS and
    `check_dns_txt` fails closed on a real NXDOMAIN, not just on a fake one."""
    resolver = ownership.DnsPythonResolver(timeout=5.0)
    outcome = ownership.check_dns_txt("example.com", "definitely-not-set", resolver=resolver)
    assert outcome.ok is False


def test_real_http_fetcher_against_a_real_domain_with_no_bulwark_file() -> None:
    """A genuine network HTTPS fetch against a real domain with no such well-known file -- proves
    `HttpxFetcher` really makes a request and a 404 is treated as "not verified," not a crash."""
    fetcher = ownership.HttpxFetcher(timeout=5.0)
    outcome = ownership.check_well_known("example.com", "definitely-not-set", fetcher=fetcher)
    assert outcome.ok is False
