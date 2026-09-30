"""Citation validation for the security copilot (plan §21.5): "every answer cites issue IDs and
file:line. Citations are checked against the index before the answer is shown." A citation that
doesn't check out means the model is asked to try again (same retry-then-give-up shape
core.fixagent.agent.propose_patch already uses for a patch that fails
core.llm.contract.validate_patch) -- never shown to the user unverified.
"""

from __future__ import annotations

from typing import Any

from core.codeintel.models import CodeGraph


class ContractError(ValueError):
    """A citation doesn't check out -- told to the model as a tool-result error, never surfaced to
    the user as if it were valid."""


def validate_citations(
    citations: list[dict[str, Any]], *, valid_issue_ids: set[str], graph: CodeGraph
) -> None:
    """Raises on the first bad citation, naming it, so the model gets one actionable thing to fix
    at a time rather than a bulk rejection it has to guess its way through. An empty citations list
    is allowed -- a "the tools found nothing relevant" answer legitimately has nothing to cite."""
    known_paths = {s.path for s in graph.all_symbols}
    for c in citations:
        kind = c.get("kind")
        if kind == "issue":
            issue_id = c.get("issue_id")
            if not issue_id or issue_id not in valid_issue_ids:
                raise ContractError(f"citation refers to an unknown issue id: {issue_id!r}")
        elif kind == "code":
            path, line = c.get("path"), c.get("line")
            if not path or path not in known_paths:
                raise ContractError(f"citation refers to a file not seen in this project: {path!r}")
            if not isinstance(line, int) or line < 1:
                raise ContractError(f"citation has an invalid line number: {line!r}")
        else:
            raise ContractError(f"citation has an unknown kind: {kind!r}")
