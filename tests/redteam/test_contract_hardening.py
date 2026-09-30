"""Red-team scenario (plan §21.9): can injected/adversarial text be accepted as a valid model reply
by any of this codebase's output contracts? Every one of the 20 corpus payloads is fed as a RAW
reply directly to every contract that parses raw text -- none of them are valid replies under any
contract's schema, so every single one must be rejected. This is a broad regression net across
core.llm.contract (fix), core.triage_assistant.contract (triage), and core.attackpath.contract
(narrative) -- core.copilot.contract.validate_citations takes structured citations, not raw text,
so it gets its own targeted test (test_copilot_tool_scope_and_unknown_tools.py) instead.
"""

from __future__ import annotations

import pytest

from core.attackpath.contract import validate_narrative
from core.llm.contract import ContractError as FixContractError
from core.llm.contract import parse_response as parse_fix_response
from core.triage_assistant.contract import ContractError as TriageContractError
from core.triage_assistant.contract import parse_response as parse_triage_response
from tests.redteam.payloads import load_payloads

PAYLOADS = load_payloads()


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_fix_contract_rejects_every_corpus_payload_as_a_raw_reply(name: str) -> None:
    with pytest.raises(FixContractError):
        parse_fix_response(PAYLOADS[name], path="app/users.py")


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_triage_contract_rejects_every_corpus_payload_as_a_raw_reply(name: str) -> None:
    with pytest.raises(TriageContractError):
        parse_triage_response(PAYLOADS[name], first_line=1, last_line=50)


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_narrative_contract_rejects_every_corpus_payload_as_a_raw_reply(name: str) -> None:
    with pytest.raises(ValueError):
        validate_narrative(PAYLOADS[name], node_labels=("GET /preview", "SSRF issue"))
