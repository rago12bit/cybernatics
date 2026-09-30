"""OpenBao Transit client: mints and unwraps per-organization key-encryption keys (Week 47 task 1,
plan §22.2, ADR-0032).

Every call, method, and error shape here was exercised live against a real `openbao/openbao:2.1`
dev-mode container before being written -- see docs/v2-week47-verification.md. Envelope encryption
proper (encrypting actual bytes with the data key this module returns) is core.secrets.envelope's
job; this module never sees a scan's plaintext data.

Uses `urllib.request` rather than a new HTTP dependency, matching `core/ci/github.py` and
`core/llm/ollama_client.py`'s existing convention for talking to an external HTTP API.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from base64 import b64decode
from dataclasses import dataclass
from typing import Any


class OpenBaoError(Exception):
    pass


@dataclass(frozen=True)
class DataKey:
    plaintext: bytes  # 32 bytes (AES-256) -- use immediately with core.secrets.envelope, then drop
    wrapped: str  # OpenBao's own "vault:v1:..." ciphertext string; store this, never the plaintext


@dataclass(frozen=True)
class OpenBaoClient:
    addr: str  # e.g. "http://127.0.0.1:8200"
    token: str

    def _request(
        self, method: str, path: str, body: dict[str, object] | None = None
    ) -> dict[str, Any]:
        url = f"{self.addr.rstrip('/')}/v1/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method, headers={"X-Vault-Token": self.token}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise OpenBaoError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise OpenBaoError(f"could not reach OpenBao at {self.addr}: {exc}") from exc
        return json.loads(raw) if raw else {}

    def ensure_transit_engine_enabled(self) -> None:
        """Mounts the Transit secrets engine if it isn't already. NOT idempotent to just POST
        blindly, unlike ensure_org_key: re-mounting an already-enabled engine is a real error
        (verified live: HTTP 400 "path is already in use"), so this checks first via GET
        /sys/mounts. Call once per OpenBao instance (e.g. at worker/API startup), not per request.
        """
        mounts = self._request("GET", "sys/mounts")
        if "transit/" in mounts.get("data", mounts):
            return
        self._request("POST", "sys/mounts/transit", {"type": "transit"})

    def ensure_org_key(self, org_id: str) -> None:
        """Creates the org's named Transit key if it doesn't exist. Idempotent -- POSTing to an
        existing key's creation endpoint is a documented no-op (verified live), not an error, so
        callers never need a GET-first check."""
        self._request("POST", f"transit/keys/{_key_name(org_id)}")

    def generate_data_key(self, org_id: str) -> DataKey:
        """Mints a fresh 32-byte data key, wrapped by the org's KEK. Transit's own
        `/datakey/plaintext` endpoint returns both forms in one call -- built for exactly this
        envelope-encryption pattern, not something assembled from separate primitives."""
        resp = self._request("POST", f"transit/datakey/plaintext/{_key_name(org_id)}")
        data = resp["data"]
        return DataKey(plaintext=b64decode(data["plaintext"]), wrapped=data["ciphertext"])

    def unwrap_data_key(self, org_id: str, wrapped: str) -> bytes:
        """Recovers the plaintext data key from its wrapped form. Raises OpenBaoError for a
        tampered/garbled wrapped value or the wrong org's key (verified live: OpenBao returns
        HTTP 400 for an undecodable ciphertext) -- never returns a wrong-but-plausible key."""
        resp = self._request(
            "POST", f"transit/decrypt/{_key_name(org_id)}", {"ciphertext": wrapped}
        )
        return b64decode(resp["data"]["plaintext"])


def _key_name(org_id: str) -> str:
    return f"org-{org_id}"


def encode_wrapped_key(wrapped: str) -> bytes:
    """DataKey.wrapped is OpenBao's own ASCII "vault:v1:..." string; stored as bytes in
    scan_data_keys.wrapped_dek for symmetry with the ciphertext columns it sits next to."""
    return wrapped.encode("ascii")


def decode_wrapped_key(stored: bytes) -> str:
    return stored.decode("ascii")


__all__ = [
    "DataKey",
    "OpenBaoClient",
    "OpenBaoError",
    "decode_wrapped_key",
    "encode_wrapped_key",
]
