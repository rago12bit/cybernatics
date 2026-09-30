"""core.attackpath.narrative.generate: the narrative call, against a fake model (same FakeModel
shape as test_triage_assistant_service.py)."""

from __future__ import annotations

from core.attackpath.model import (
    AttackPath,
    EdgeKind,
    Impact,
    Likelihood,
    NodeKind,
    PathEdge,
    PathNode,
)
from core.attackpath.narrative import generate
from core.llm.client import Completion


class FakeModel:
    model = "fake-model-1"

    def __init__(self, out: str | Exception | list[str | Exception], tokens: int = 10) -> None:
        self.out = out if isinstance(out, list) else [out]
        self.calls: list[tuple[str, str]] = []
        self.tokens = tokens

    def complete(self, system: str, user: str) -> Completion:
        self.calls.append((system, user))
        item = self.out[min(len(self.calls) - 1, len(self.out) - 1)]
        if isinstance(item, Exception):
            raise item
        return Completion(item, self.tokens)


def _path() -> AttackPath:
    ep = PathNode("ep_1", NodeKind.ENTRYPOINT, "GET /preview")
    issue = PathNode("iss_1", NodeKind.ISSUE, "SSRF issue", issue_id="iss1")
    resource = PathNode("res_1", NodeKind.CLOUD_RESOURCE, "cloud metadata service")
    edges = (
        PathEdge(EdgeKind.REACHABLE_FROM, "ep_1", "iss_1", "ssrf-metadata-v1"),
        PathEdge(EdgeKind.EXPOSES, "iss_1", "res_1", "ssrf-metadata-v1"),
    )
    nodes = (ep, issue, resource)
    return AttackPath(
        id=AttackPath.compute_id("asset1", nodes, edges), asset_id="asset1", nodes=nodes,
        edges=edges, likelihood=Likelihood.HIGH, impact=Impact.HIGH, rank_score=9.0,
        cheapest_link="iss_1",
    )  # fmt: skip


def test_no_client_means_no_narrative_not_a_guess() -> None:
    assert generate(_path(), None) is None


def test_a_valid_reply_produces_a_narrative() -> None:
    text = "GET /preview reaches the SSRF issue, which exposes the cloud metadata service."
    client = FakeModel(text)
    result = generate(_path(), client)
    assert result is not None
    assert result.text == text
    assert result.model == "fake-model-1"
    assert result.tokens_used == 10
    assert len(client.calls) == 1


def test_reply_missing_a_node_triggers_one_repair_then_succeeds() -> None:
    bad = "GET /preview reaches the SSRF issue."
    good = "GET /preview reaches the SSRF issue, which exposes the cloud metadata service."
    client = FakeModel([bad, good])
    result = generate(_path(), client)
    assert result is not None
    assert result.text == good
    assert result.tokens_used == 20
    assert len(client.calls) == 2
    assert "did not match the required format" in client.calls[1][1]


def test_reply_bad_twice_returns_none_not_a_guess() -> None:
    client = FakeModel(["GET /preview only.", "still missing nodes."])
    assert generate(_path(), client) is None


def test_model_call_failure_returns_none() -> None:
    client = FakeModel(RuntimeError("network down"))
    assert generate(_path(), client) is None
