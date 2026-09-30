"""core.copilot.contract.validate_citations (plan §21.5): "citations are checked against the index
before the answer is shown.\" """

from __future__ import annotations

import pytest

from core.codeintel.models import CodeGraph, Symbol
from core.copilot.contract import ContractError, validate_citations


def _graph() -> CodeGraph:
    sym = Symbol("a.py:f:1", "a.py", "f", "f", "function", 1, 3, "python")
    return CodeGraph(symbols={sym.id: sym}, all_symbols=(sym,))


def test_a_known_issue_id_passes() -> None:
    validate_citations(
        [{"kind": "issue", "issue_id": "ISS-1"}], valid_issue_ids={"ISS-1"}, graph=_graph()
    )


def test_an_unknown_issue_id_is_rejected() -> None:
    with pytest.raises(ContractError, match="unknown issue id"):
        validate_citations(
            [{"kind": "issue", "issue_id": "ISS-999"}], valid_issue_ids={"ISS-1"}, graph=_graph()
        )


def test_a_known_path_and_valid_line_passes() -> None:
    validate_citations(
        [{"kind": "code", "path": "a.py", "line": 2}], valid_issue_ids=set(), graph=_graph()
    )


def test_a_path_never_seen_in_this_project_is_rejected() -> None:
    with pytest.raises(ContractError, match="not seen in this project"):
        validate_citations(
            [{"kind": "code", "path": "nope.py", "line": 1}], valid_issue_ids=set(), graph=_graph()
        )


def test_a_non_positive_line_is_rejected() -> None:
    with pytest.raises(ContractError, match="invalid line number"):
        validate_citations(
            [{"kind": "code", "path": "a.py", "line": 0}], valid_issue_ids=set(), graph=_graph()
        )


def test_an_unknown_kind_is_rejected() -> None:
    with pytest.raises(ContractError, match="unknown kind"):
        validate_citations([{"kind": "guess"}], valid_issue_ids=set(), graph=_graph())


def test_an_empty_citations_list_is_allowed() -> None:
    validate_citations([], valid_issue_ids=set(), graph=_graph())
