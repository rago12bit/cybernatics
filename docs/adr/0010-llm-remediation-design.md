# ADR-010: LLM remediation as a validated annotation, never a decision

Status: Accepted (2026-09-25, Week 12)

## Context
The plan wants plain-English explanations and suggested patches from a model. The scanned repository is
attacker-controlled input to that model (threat T8), and sending code to a third party is a privacy decision.

## Decision
1. **Annotation only.** The model receives one existing finding and returns a separate object. It has no field
   that can change severity, triage or taxonomy, and `Finding` is never modified.
2. **Structural defences over trust.** Instructions in the system message only; repository text in random-nonce
   fenced data blocks; the reminder after the data; strict output contract that rejects extra keys, dismissal
   language and patches outside the finding's file; any failure returns static reference text.
3. **Provider-agnostic.** Code depends on an `LLMClient` protocol. An Anthropic implementation ships behind an
   optional extra; the model id comes from configuration.
4. **Opt-in, minimal, scrubbed.** Off by default; secrets findings send no code; other code is scrubbed first;
   `bulwark llm prompt` shows exactly what would be sent.
5. **Reject, do not repair.** A malformed reply is discarded whole. Partially trusting a reply an attacker may
   have influenced is riskier than showing the deterministic text.

## Consequences
- Some legitimate replies will be rejected (for example one that discusses "false positives" in a way the phrase
  filter matches); the user then sees static text, which is always safe.
- Structural safety is tested with simulated attackers. Real-model behaviour is unmeasured until a key is
  available (Week 14 evaluation).
- Patch correctness is not verifiable by Bulwark; patches are labelled and never applied.
