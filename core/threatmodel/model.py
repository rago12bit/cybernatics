"""Threat-model-draft data model (plan §21.7): a Mermaid data-flow diagram plus a STRIDE table,
generated from code intelligence already computed for this asset -- entrypoints and the call graph
(`core.codeintel`) plus the taint engine's own sink catalogs (`core.taint.catalog`, plan §20.3).
No new detection is added here: a "database" node exists only because the same sink patterns the
taint engine already matches (e.g. `cursor.execute`) are reachable from an entrypoint; an "OS
process" node only because a command-injection-category sink is reachable the same way.

This is explicitly a STARTING POINT for a person, not an assessment (plan §21.7): the STRIDE rows
are fixed, generic prompts per element kind, not per-project findings, and both the diagram and the
table are stored editable -- a person's edits are never silently overwritten by a later regenerate
without their choosing to regenerate."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DfdElementKind(str, Enum):
    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"
    EXTERNAL_INTERACTOR = "external_interactor"


@dataclass(frozen=True)
class StrideRow:
    """One deterministic starter question for one diagram element. `category` is one of the six
    STRIDE names in full (never abbreviated to a single letter, so the table is self-explanatory
    without a legend)."""

    element: str
    element_kind: DfdElementKind
    category: str
    prompt: str


@dataclass(frozen=True)
class ThreatModelDraft:
    mermaid: str
    stride: tuple[StrideRow, ...]
