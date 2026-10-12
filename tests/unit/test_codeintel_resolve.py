"""core/codeintel/resolve.py: intra-procedural-first, then inter-procedural name-based call
resolution (plan §20.2) -- and its documented unsoundness."""

from __future__ import annotations

from core.codeintel.models import Entrypoint, FileUnit, Mount, Symbol
from core.codeintel.resolve import resolve


def sym(path: str, name: str, line: int = 1) -> Symbol:
    return Symbol(f"{path}:{name}:{line}", path, name, name, "function", line, line, "python")


def test_a_call_resolves_when_exactly_one_symbol_anywhere_has_that_name() -> None:
    a = FileUnit(
        "a.py", "python", symbols=[sym("a.py", "caller")], calls=[("a.py:caller:1", "helper", 2)]
    )
    b = FileUnit("b.py", "python", symbols=[sym("b.py", "helper")])
    graph = resolve([a, b])
    assert graph.edges[0].callee_id == "b.py:helper:1"


def test_a_call_with_no_matching_symbol_anywhere_is_unresolved() -> None:
    a = FileUnit(
        "a.py",
        "python",
        symbols=[sym("a.py", "caller")],
        calls=[("a.py:caller:1", "unknown_lib_call", 2)],
    )
    graph = resolve([a])
    assert graph.edges[0].callee_id is None
    assert graph.edges[0].callee_name == "unknown_lib_call"  # kept, even though unresolved


def test_same_file_definition_wins_over_an_ambiguous_repo_wide_name() -> None:
    """Intra-procedural first (plan §20.2): a file that defines its own `process` must resolve a
    call to it locally, even though another, unrelated `process` exists elsewhere and would
    otherwise make the name ambiguous."""
    a = FileUnit(
        "a.py", "python",
        symbols=[sym("a.py", "caller"), sym("a.py", "process")],
        calls=[("a.py:caller:1", "process", 2)],
    )  # fmt: skip
    b = FileUnit("b.py", "python", symbols=[sym("b.py", "process")])
    graph = resolve([a, b])
    assert graph.edges[0].callee_id == "a.py:process:1"


def test_ambiguous_repo_wide_name_with_no_local_definition_is_unresolved() -> None:
    """The plan's own documented unsoundness: two functions named `process` in two unrelated
    files, called from a third file that defines neither -- there is no principled way to pick
    one, so neither is guessed."""
    a = FileUnit(
        "a.py", "python", symbols=[sym("a.py", "caller")], calls=[("a.py:caller:1", "process", 2)]
    )
    b = FileUnit("b.py", "python", symbols=[sym("b.py", "process")])
    c = FileUnit("c.py", "python", symbols=[sym("c.py", "process")])
    graph = resolve([a, b, c])
    assert graph.edges[0].callee_id is None


def test_a_symbol_id_collision_still_resolves_as_ambiguous_not_to_the_dict_survivor() -> None:
    """Regression test: `CodeGraph.symbols` is keyed by id, so two distinct symbols that happen to
    collide on the same id (a symbol_id generation bug elsewhere, not something resolve.py itself
    can prevent) would silently keep only the last one written. If the by-name index were built
    from that already-deduplicated dict, the caller's name-based lookup would then confidently
    resolve to whichever symbol survived -- rather than correctly recognizing two same-named
    definitions exist and staying unresolved."""
    colliding_id = "x.py:process:1"
    a = FileUnit(
        "a.py",
        "python",
        symbols=[Symbol(colliding_id, "x.py", "process", "process", "function", 1, 1, "python")],
        calls=[],
    )
    b = FileUnit(
        "b.py",
        "python",
        symbols=[Symbol(colliding_id, "x.py", "process", "process", "function", 1, 1, "python")],
        calls=[],
    )
    caller = FileUnit(
        "c.py", "python", symbols=[sym("c.py", "caller")], calls=[("c.py:caller:1", "process", 2)]
    )
    graph = resolve([a, b, caller])
    assert len(graph.symbols) == 2  # the id-keyed dict only kept one of the two colliding "process"
    assert len(graph.all_symbols) == 3  # but every emission is preserved for name resolution
    assert graph.edges[0].callee_id is None  # correctly ambiguous, not confidently "resolved"


def test_files_parsed_and_unparsed_are_counted() -> None:
    good = FileUnit("a.py", "python", parsed=True)
    bad = FileUnit("b.py", "python", parsed=False)
    graph = resolve([good, bad])
    assert graph.files_parsed == 1 and graph.files_unparsed == 1


def test_languages_seen_are_collected() -> None:
    graph = resolve([FileUnit("a.py", "python"), FileUnit("b.go", "go")])
    assert graph.languages == frozenset({"python", "go"})


def test_callers_of_and_calls_from_walk_the_resolved_graph() -> None:
    a = FileUnit(
        "a.py", "python", symbols=[sym("a.py", "caller")], calls=[("a.py:caller:1", "helper", 2)]
    )
    b = FileUnit("b.py", "python", symbols=[sym("b.py", "helper")])
    graph = resolve([a, b])
    assert graph.callers_of("b.py:helper:1") == ["a.py:caller:1"]
    assert [e.callee_id for e in graph.calls_from("a.py:caller:1")] == ["b.py:helper:1"]


def _route(path: str, route: str, router: str = "router") -> Entrypoint:
    return Entrypoint(f"{path}:h:1", "fastapi", "GET", route, (), router)


def test_a_router_mounted_twice_serves_its_routes_at_both_paths() -> None:
    main = FileUnit("main.py", "python", mounts=[
        Mount("main.py", "app", "/v1", "users", "router"),
        Mount("main.py", "app", "/v2", "users", "router"),
    ])  # fmt: skip
    users = FileUnit("users.py", "python", entrypoints=[_route("users.py", "/{id}")])
    assert sorted(e.path for e in resolve([main, users]).entrypoints) == ["/v1/{id}", "/v2/{id}"]


def test_mounts_that_form_a_cycle_end() -> None:
    a = FileUnit("a.py", "python", mounts=[Mount("a.py", "router", "/a", "b", "router")],
                 entrypoints=[_route("a.py", "/x")])  # fmt: skip
    b = FileUnit("b.py", "python", mounts=[Mount("b.py", "router", "/b", "a", "router")])
    paths = [e.path for e in resolve([a, b]).entrypoints]
    assert paths and all(p.endswith("/x") for p in paths)


def test_a_mount_that_names_nothing_here_or_two_things_alike_adds_nothing() -> None:
    main = FileUnit("main.py", "python", mounts=[
        Mount("main.py", "app", "/ext", "some_package.routes", "router"),
        Mount("main.py", "app", "/u", "users", "router"),
    ])  # fmt: skip
    one = FileUnit("x/users.py", "python", entrypoints=[_route("x/users.py", "/a")])
    two = FileUnit("y/users.py", "python", entrypoints=[_route("y/users.py", "/b")])
    assert sorted(e.path for e in resolve([main, one, two]).entrypoints) == ["/a", "/b"]


def test_the_nearer_of_two_modules_is_the_one_mounted() -> None:
    main = FileUnit("svc/main.py", "python",
                    mounts=[Mount("svc/main.py", "app", "/u", "users", "router")])  # fmt: skip
    near = FileUnit("svc/users.py", "python", entrypoints=[_route("svc/users.py", "/a")])
    far = FileUnit("other/users.py", "python", entrypoints=[_route("other/users.py", "/b")])
    assert sorted(e.path for e in resolve([main, near, far]).entrypoints) == ["/b", "/u/a"]
