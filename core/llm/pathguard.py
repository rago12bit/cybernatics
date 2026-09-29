"""Path denylist: files whose content is never sent to a model, whatever the finding's category
(plan §21.1, "a path denylist (.env, *.pem, *.key) that is never sent").

Complements, rather than replaces, `scrub.scrub_secrets`/`pii.redact_pii`: those clean text already
selected for sending; this decides whether to select it at all. A `.env` file or a private key may
carry nothing either recognizes syntactically (an unlabelled value on its own line, a raw PEM body
scrub_secrets already catches by header -- but a denylist doesn't need to rely on that), so refusing
the whole file for these specific, unusually sensitive path shapes is the only guarantee that holds
regardless of content. `build_prompt` (core/llm/prompt.py) checks this the same way it already
withholds code for a `secrets`-category finding.
"""

from __future__ import annotations

import fnmatch
import os

DEFAULT_DENYLIST: tuple[str, ...] = (
    ".env", ".env.*", "*.pem", "*.key", "*.pfx", "*.p12", "*.jks", "*.keystore",
    "id_rsa", "id_rsa.*", "id_dsa", "id_dsa.*", "id_ed25519", "id_ed25519.*", "id_ecdsa", "id_ecdsa.*",
    "*.kdbx", "known_hosts", "*.ovpn", "credentials.json", "*.pkcs12",
)  # fmt: skip


def denylist_from_env(extra_env: str = "BULWARK_LLM_PATH_DENYLIST") -> tuple[str, ...]:
    """The built-in list plus any comma-separated extra patterns -- additive only, so a misconfigured
    or empty env var can never *weaken* the defaults."""
    extra = [p.strip() for p in os.environ.get(extra_env, "").split(",") if p.strip()]
    return (*DEFAULT_DENYLIST, *extra)


def is_denylisted(path: str, patterns: tuple[str, ...] | None = None) -> bool:
    patterns = patterns if patterns is not None else denylist_from_env()
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(path, pat) for pat in patterns)
