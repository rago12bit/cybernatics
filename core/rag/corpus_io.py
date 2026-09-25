"""Read the committed corpus (core/rag/corpus/*.jsonl) into uniform chunks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).with_name("corpus")


@dataclass(frozen=True)
class Chunk:
    id: str
    kind: str  # "cwe" | "cheatsheet"
    title: str
    section: str
    text: str
    owasp: tuple[str, ...]
    cwes: tuple[str, ...]
    url: str

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(f"{self.title}\n{self.section}\n{self.text}".encode()).hexdigest()


def _cwe_text(d: dict[str, Any]) -> str:
    parts = [d["description"]]
    if d["extended"]:
        parts.append(d["extended"])
    if d["consequences"]:
        parts.append("Consequences: " + "; ".join(d["consequences"]))
    if d["mitigations"]:
        parts.append("Mitigations: " + " ".join(d["mitigations"]))
    return "\n\n".join(parts)


def read_corpus(directory: Path = CORPUS_DIR) -> list[Chunk]:
    from core.taxonomy import owasp_for_cwe

    chunks: list[Chunk] = []
    for line in (directory / "cwe.jsonl").read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        chunks.append(
            Chunk(d["id"], "cwe", f"{d['id']}: {d['name']}", d["abstraction"], _cwe_text(d),
                  owasp_for_cwe(d["id"]), (d["id"],), d["url"])
        )  # fmt: skip
    for line in (directory / "cheatsheets.jsonl").read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        chunks.append(
            Chunk(d["id"], "cheatsheet", d["sheet"], d["section"], d["text"],
                  tuple(d["owasp"]), tuple(d["cwes"]), d["url"])
        )  # fmt: skip
    return chunks
