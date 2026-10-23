"""Integration secrets are encrypted at rest (core/secrets/fields.py): what the database holds is
ciphertext, what the code reads is the value, and a value that cannot be vouched for reads as unset.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import IntegrationSettingsRow
from core.secrets import fields
from core.tenancy import DEFAULT_ORG_ID as ORG

KEY = "11" * 32
OTHER_KEY = "22" * 32
TOKEN = "ghp_not-a-real-token-0123456789"
SLACK = "https://hooks.slack.com/services/T000/B000/not-a-real-hook"


@pytest.fixture(autouse=True)
def no_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for var in (fields.ENV_VAR, "BULWARK_OPENBAO_ADDR", "BULWARK_OPENBAO_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    fields.reset_key_cache()
    yield
    fields.reset_key_cache()


def use_key(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    monkeypatch.setenv(fields.ENV_VAR, key)
    fields.reset_key_cache()


def save(sessions: sessionmaker[Session], **values: str | None) -> None:
    with sessions() as s:
        repo.set_integration_settings(s, ORG, actor="test", **values)


def stored(sessions: sessionmaker[Session], column: str) -> str | None:
    with sessions() as s:
        value = s.execute(text(f"SELECT {column} FROM integration_settings")).scalar()  # noqa: S608
    return None if value is None else str(value)


def read(sessions: sessionmaker[Session]) -> IntegrationSettingsRow:
    with sessions() as s:
        row = repo.get_integration_settings(s, ORG)
        assert row is not None
        s.expunge(row)
        return row


def test_with_a_key_the_database_holds_only_ciphertext(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    use_key(monkeypatch, KEY)
    save(sessions, github_token=TOKEN, github_issues_repo="acme/widgets", slack_webhook_url=SLACK)
    for column, value in (("github_token", TOKEN), ("slack_webhook_url", SLACK)):
        raw = stored(sessions, column)
        assert raw is not None and raw.startswith(fields.PREFIX) and value not in raw
    assert stored(sessions, "github_issues_repo") == "acme/widgets"  # not a secret
    row = read(sessions)
    assert row.github_token == TOKEN and row.slack_webhook_url == SLACK


def test_the_same_value_encrypts_differently_each_time(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    use_key(monkeypatch, KEY)
    assert fields.encrypt_value(TOKEN, "x") != fields.encrypt_value(TOKEN, "x")  # a fresh nonce


def test_without_a_key_values_are_stored_as_before(
    sessions: sessionmaker[Session], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="core.secrets.fields"):
        save(sessions, github_token=TOKEN)
    assert stored(sessions, "github_token") == TOKEN
    assert read(sessions).github_token == TOKEN
    assert "BULWARK_SECRETS_KEY is not set" in caplog.text


def test_values_saved_before_the_key_still_read_and_are_encrypted_on_request(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    save(sessions, github_token=TOKEN, jira_webhook_secret="jira-secret")
    use_key(monkeypatch, KEY)
    assert read(sessions).github_token == TOKEN  # plain text, from before
    with sessions() as s:
        assert repo.reencrypt_integration_secrets(s, ORG) == 2
    assert str(stored(sessions, "github_token")).startswith(fields.PREFIX)
    assert str(stored(sessions, "jira_webhook_secret")).startswith(fields.PREFIX)
    row = read(sessions)
    assert row.github_token == TOKEN and row.jira_webhook_secret == "jira-secret"
    with sessions() as s:
        assert repo.reencrypt_integration_secrets(s, "no-such-org") == 0


@pytest.mark.parametrize("later_key", [OTHER_KEY, None])
def test_a_value_that_does_not_decrypt_reads_as_unset(
    sessions: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    later_key: str | None,
) -> None:
    use_key(monkeypatch, KEY)
    save(sessions, github_token=TOKEN)
    if later_key:
        use_key(monkeypatch, later_key)
    else:
        monkeypatch.delenv(fields.ENV_VAR)
        fields.reset_key_cache()
    with caplog.at_level(logging.ERROR, logger="core.secrets.fields"):
        assert read(sessions).github_token is None
    assert "integration_settings.github_token" in caplog.text and TOKEN not in caplog.text


def test_ciphertext_moved_to_another_column_or_altered_does_not_decrypt(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    use_key(monkeypatch, KEY)
    save(sessions, slack_webhook_url=SLACK)
    slack = stored(sessions, "slack_webhook_url")
    with sessions() as s:  # someone with database access points Discord at the Slack hook
        s.execute(text("UPDATE integration_settings SET discord_webhook_url = :v"), {"v": slack})
        s.commit()
    assert read(sessions).discord_webhook_url is None
    assert read(sessions).slack_webhook_url == SLACK
    flipped = str(slack)[:-6] + ("A" if str(slack)[-6] != "A" else "B") + str(slack)[-5:]
    with sessions() as s:
        s.execute(text("UPDATE integration_settings SET slack_webhook_url = :v"), {"v": flipped})
        s.commit()
    assert read(sessions).slack_webhook_url is None


@pytest.mark.parametrize("bad", ["short", "zz" * 32, "11" * 31])
def test_a_malformed_key_is_an_error_not_a_silent_fallback(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    use_key(monkeypatch, bad)
    with pytest.raises(fields.SecretsKeyError):
        fields.encrypt_value(TOKEN, "x")
