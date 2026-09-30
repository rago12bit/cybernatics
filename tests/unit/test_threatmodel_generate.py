"""core.threatmodel.generate.generate_threat_model: DFD + STRIDE table from a real analyzed
checkout -- no fixtures, no mocked CodeGraph (the same realism standard test_embeddings_service.py
and test_attackpath_service.py already hold this kind of pass to)."""

from __future__ import annotations

from pathlib import Path

from core.codeintel import analyze
from core.threatmodel.generate import generate_threat_model
from core.threatmodel.model import DfdElementKind

APP = (
    "from flask import Flask\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users', methods=['GET'])\n"
    "def list_users():\n"
    "    return db_query()\n\n"
    "def db_query():\n"
    "    cursor.execute('SELECT * FROM users')\n\n"
    "@app.route('/run', methods=['POST'])\n"
    "def run_cmd():\n"
    "    return shell()\n\n"
    "def shell():\n"
    "    import os\n"
    "    os.system('ls')\n\n"
    "@app.route('/health', methods=['GET'])\n"
    "def health():\n"
    "    return 'ok'\n"
)


def _draft(tmp_path: Path):
    (tmp_path / "app.py").write_text(APP)
    graph = analyze(tmp_path)
    assert len(graph.entrypoints) == 3, "fixture must produce 3 real Flask entrypoints"
    return generate_threat_model(graph)


def test_diagram_has_a_user_entity_and_one_process_per_route(tmp_path: Path) -> None:
    draft = _draft(tmp_path)
    assert "user([User])" in draft.mermaid
    assert '("GET /users")' in draft.mermaid
    assert '("POST /run")' in draft.mermaid
    assert '("GET /health")' in draft.mermaid
    assert draft.mermaid.count("user -->") == 3


def test_database_node_appears_only_for_the_route_reaching_a_sql_sink(tmp_path: Path) -> None:
    draft = _draft(tmp_path)
    assert "db[(Database)]" in draft.mermaid
    lines = draft.mermaid.splitlines()
    users_id = next(ln.split("(")[0].strip() for ln in lines if '("GET /users")' in ln)
    assert f"{users_id} --> db" in draft.mermaid
    assert draft.mermaid.count("--> db") == 1


def test_os_node_appears_only_for_the_route_reaching_a_command_sink(tmp_path: Path) -> None:
    draft = _draft(tmp_path)
    assert "os{{OS process}}" in draft.mermaid
    lines = draft.mermaid.splitlines()
    run_id = next(ln.split("(")[0].strip() for ln in lines if '("POST /run")' in ln)
    assert f"{run_id} --> os" in draft.mermaid
    assert draft.mermaid.count("--> os") == 1


def test_stride_table_has_one_user_row_six_rows_per_process_and_db_os_rows_once(
    tmp_path: Path,
) -> None:
    draft = _draft(tmp_path)
    user_rows = [r for r in draft.stride if r.element == "User"]
    assert len(user_rows) == 1 and user_rows[0].element_kind is DfdElementKind.EXTERNAL_ENTITY

    process_rows = [r for r in draft.stride if r.element_kind is DfdElementKind.PROCESS]
    assert len(process_rows) == 6 * 3
    by_route = {r.element for r in process_rows}
    assert by_route == {"GET /users", "POST /run", "GET /health"}

    db_rows = [r for r in draft.stride if r.element_kind is DfdElementKind.DATA_STORE]
    assert len(db_rows) == 3 and all(r.element == "Database" for r in db_rows)

    os_rows = [r for r in draft.stride if r.element_kind is DfdElementKind.EXTERNAL_INTERACTOR]
    assert len(os_rows) == 2 and all(r.element == "OS process" for r in os_rows)


def test_no_routes_means_only_the_user_entity(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    graph = analyze(tmp_path)
    draft = generate_threat_model(graph)
    assert draft.mermaid == "flowchart LR\n    user([User])"
    assert len(draft.stride) == 1
