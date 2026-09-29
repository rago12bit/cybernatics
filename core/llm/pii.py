"""Personal-data removal with Microsoft Presidio, layered after secret scrubbing (plan §21.1).

`scrub.scrub_secrets` already removes API keys, tokens and passwords: structured, provider-specific
formats matched by regex. Presidio catches what that can't -- names, emails, phone numbers, IP
addresses, national ids -- free-text PII a finding's own title/description or a code snippet might
happen to carry (a hardcoded test email, a real name in a comment). Always run AFTER
`scrub_secrets`, never before: redacting secrets first means Presidio's NER models never see raw key
material at all.

Optional and lazy, the same shape as `AnthropicClient` in `client.py`: `pip install
'bulwark-scan[pii]'` pulls in `presidio-analyzer`/`presidio-anonymizer`, but the actual spaCy
language model (`en_core_web_sm`) is a separate download no pip extra can express (`python -m spacy
download en_core_web_sm`) -- so this degrades to a no-op, not a crash, whenever either piece is
missing. `scrub_secrets` alone still ran either way.

The analyzer's own default config downloads `en_core_web_lg` (~400MB) the first time it runs if not
told otherwise -- confirmed by actually running `AnalyzerEngine()` with no config during this
feature's own development. Explicitly wiring `en_core_web_sm` (~13MB) here is deliberate, not an
oversight: this runs inline on every model call, so pulling a large, unexpected model into a
sandboxed environment with no egress (or a slow cold start) is exactly the kind of surprise this
module exists to avoid causing itself.
"""

from __future__ import annotations

import os
import threading
from typing import Any

_engine_lock = threading.Lock()
_engine: Any | None = None  # presidio_analyzer.AnalyzerEngine, loosely typed: an optional import
_unavailable = False

SPACY_MODEL = "en_core_web_sm"
DEFAULT_THRESHOLD = 0.4


def _get_analyzer() -> Any | None:
    global _engine, _unavailable
    if _unavailable:
        return None
    with _engine_lock:
        if _engine is not None or _unavailable:
            return _engine
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError:
            _unavailable = True
            return None
        try:
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": SPACY_MODEL}],
                }
            )
            _engine = AnalyzerEngine(
                nlp_engine=provider.create_engine(), supported_languages=["en"]
            )
        except (
            Exception
        ):  # noqa: BLE001 - model not downloaded, or any other setup failure: degrade
            _unavailable = True
            return None
        return _engine


def redact_pii(text: str) -> tuple[str, int]:
    """`(text, 0)` unchanged when Presidio (or its language model) isn't installed, or on any
    analysis failure -- this is a best-effort second layer, never a hard requirement to send text.
    The whole body is one try/except, not just the analyze call: a caller of `suggest()` depends on
    prompt-building never raising, so a surprise failure inside Presidio itself (not just "not
    installed") must degrade the same way as everything else here, not propagate."""
    if not text or not text.strip():
        return text, 0
    try:
        analyzer = _get_analyzer()
        if analyzer is None:
            return text, 0
        from presidio_anonymizer import AnonymizerEngine

        threshold = float(os.environ.get("BULWARK_LLM_PII_THRESHOLD", str(DEFAULT_THRESHOLD)))
        results = analyzer.analyze(text=text, language="en", score_threshold=threshold)
        if not results:
            return text, 0
        out = AnonymizerEngine().anonymize(text=text, analyzer_results=results)
        return out.text, len(results)
    except Exception:  # noqa: BLE001 - never block sending code over a redaction-layer failure
        return text, 0
