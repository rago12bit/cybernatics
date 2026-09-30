"""Envelope encryption for data at rest (Week 47 task 1, plan §22.2, ADR-0032).

core.secrets.openbao talks to OpenBao's Transit engine to mint and unwrap per-scan data keys under
an organization's own key-encryption key; core.secrets.envelope does the actual AES-256-GCM
encryption of bytes with a data key OpenBao never sees in wrapped form. Neither module holds a
plaintext data key longer than one call needs it.
"""

from __future__ import annotations
