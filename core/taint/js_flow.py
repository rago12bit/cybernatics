"""JavaScript/TypeScript intra-procedural taint flow (plan §20.3), via tree-sitter -- the same
grammars `core.codeintel.js_lang` already parses these languages with. See `python_flow.py`'s module
docstring for the shared algorithm (one analyzer answering both "function summary" and "real taint
path" questions depending only on the initial seed) and its documented precision trade-offs
(not path-sensitive, loops visited once); everything there applies here unchanged.

Deliberately smaller than `python_flow.py`'s expression coverage: destructuring assignment
(`const {a, b} = tainted`), optional chaining (`a?.b`), and tagged template literals are not
special-cased and fall through to "no taint tracked," an honest gap rather than a silent guess --
JavaScript's plain member/call/template-literal/binary-operator forms, which is what real Express
and Next.js handler code overwhelmingly uses, are what this covers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from core.taint.catalog import Catalog
from core.taint.models import (
    SOURCE,
    FunctionSummary,
    SinkHit,
    TaintHop,
    TaintSet,
    merge_taint_states,
    union_taint,
)


def _text(node) -> str:  # type: ignore[no-untyped-def]
    return node.text.decode("utf-8", "replace") if node.text else ""


def _callee_name(func) -> str | None:  # type: ignore[no-untyped-def]
    if func.type == "identifier":
        return _text(func)
    if func.type == "member_expression":
        prop = func.child_by_field_name("property")
        return _text(prop) if prop is not None else None
    return None


def _target_names(target) -> list[str]:  # type: ignore[no-untyped-def]
    if target.type == "identifier":
        return [_text(target)]
    return []  # destructuring patterns: no bare name to record taint against -- a documented gap


class _FunctionFlow:
    def __init__(
        self,
        path: str,
        resolve_callee: Callable[[str], str | None],
        summaries: dict[str, FunctionSummary],
        catalog: Catalog,
    ) -> None:
        self.tainted: dict[str, TaintSet] = {}
        self.sinks: list[SinkHit] = []
        self.returns: TaintSet = frozenset()
        self._path = path
        self._resolve_callee = resolve_callee
        self._summaries = summaries
        self._catalog = catalog

    def _union(self, sets: list[TaintSet]) -> TaintSet:
        return union_taint(sets)

    def _call_taint(self, call) -> TaintSet:  # type: ignore[no-untyped-def]
        args_node = call.child_by_field_name("arguments")
        args = list(args_node.named_children) if args_node is not None else []
        arg_taint = self._union([self.expr_taint(a) for a in args])
        fn = call.child_by_field_name("function")
        receiver_taint = (
            self.expr_taint(fn.child_by_field_name("object"))
            if fn is not None and fn.type == "member_expression"
            else frozenset()
        )
        name = _callee_name(fn) if fn is not None else None
        if name is None:
            return arg_taint | receiver_taint
        if self._catalog.is_sanitizer(name):
            return frozenset()
        line = call.start_point[0] + 1
        sink = self._catalog.sink_for(name)
        if sink is not None and arg_taint:
            self.sinks.append(SinkHit(arg_taint, self._path, line, name, sink.category))
        callee_id = self._resolve_callee(name)
        summary = self._summaries.get(callee_id) if callee_id else None
        if summary is not None and callee_id is not None:
            hop = TaintHop(callee_id, self._path, line, f"calls {name}()")
            for hit in summary.sinks:
                if SOURCE in hit.params:
                    self.sinks.append(
                        SinkHit(
                            frozenset({SOURCE}),
                            hit.path,
                            hit.line,
                            hit.sink_name,
                            hit.category,
                            (hop, *hit.hops),
                        )
                    )
                    continue
                mapped = self._union(
                    [
                        self.expr_taint(args[tag])
                        for tag in hit.params
                        if isinstance(tag, int) and tag < len(args)
                    ]
                )
                if mapped:
                    self.sinks.append(
                        SinkHit(
                            mapped,
                            hit.path,
                            hit.line,
                            hit.sink_name,
                            hit.category,
                            (hop, *hit.hops),
                        )
                    )
            result: TaintSet = frozenset()
            for tag in summary.returns:
                if isinstance(tag, int) and tag < len(args):
                    result = result | self.expr_taint(args[tag])
            # See python_flow.py's identical fix: never return less taint than the unresolved
            # fallback would -- a name-only resolution to an unrelated same-named function must
            # not silently erase a receiver's real taint (e.g. `req.query.get(...)` resolving to
            # some other class's own `get` method).
            return result | arg_taint | receiver_taint
        return arg_taint | receiver_taint

    def expr_taint(self, node) -> TaintSet:  # type: ignore[no-untyped-def]
        if node is None:
            return frozenset()
        t = node.type
        if t == "identifier":
            return self.tainted.get(_text(node), frozenset())
        if t == "call_expression":
            return self._call_taint(node)
        if t == "member_expression":
            return self.expr_taint(node.child_by_field_name("object"))
        if t == "subscript_expression":
            return self.expr_taint(node.child_by_field_name("object")) | self.expr_taint(
                node.child_by_field_name("index")
            )
        if t == "binary_expression":
            return self.expr_taint(node.child_by_field_name("left")) | self.expr_taint(
                node.child_by_field_name("right")
            )
        if t == "ternary_expression":
            return self.expr_taint(node.child_by_field_name("consequence")) | self.expr_taint(
                node.child_by_field_name("alternative")
            )
        if t in (
            "parenthesized_expression",
            "spread_element",
            "await_expression",
            "unary_expression",
            "as_expression",  # TypeScript `x as T` -- transparent to taint, only the value matters
            "non_null_expression",  # TypeScript `x!`
            "satisfies_expression",  # TypeScript `x satisfies T`
        ):
            children = node.named_children
            return self.expr_taint(children[0]) if children else frozenset()
        if t == "assignment_expression":
            return self.expr_taint(node.child_by_field_name("right"))
        if t == "augmented_assignment_expression":
            # `x += y` (this node type, distinct from plain `assignment_expression`) depends on
            # both the old value of `x` and `y`, not just `y` -- as a used expression's own value,
            # not only as a statement (see `visit()`'s handling of the same node type below).
            left = node.child_by_field_name("left")
            old = (
                self.expr_taint(left)
                if left is not None and left.type == "identifier"
                else frozenset()
            )
            return old | self.expr_taint(node.child_by_field_name("right"))
        if t == "template_string":
            return self._union(
                [
                    self.expr_taint(c.named_children[0]) if c.named_children else frozenset()
                    for c in node.children
                    if c.type == "template_substitution"
                ]
            )
        if t in ("array", "object"):
            return self._union([self.expr_taint(c) for c in node.named_children])
        if t == "pair":
            return self.expr_taint(node.child_by_field_name("value"))
        return frozenset()  # a function/arrow literal, destructuring pattern, or constant

    def _assign(self, target, t: TaintSet) -> None:  # type: ignore[no-untyped-def]
        if target.type == "identifier":
            name = _text(target)
            if t:
                self.tainted[name] = t
            else:
                self.tainted.pop(name, None)
        # object/array destructuring targets: no bare name to record taint against (documented gap)

    def _visit_branches(self, branches: list[Any], include_before: bool = False) -> None:
        """See `python_flow._visit_branches`: each branch starts from the same state and the
        results are merged by unioning tags, not visited sequentially into one shared map."""
        before = dict(self.tainted)
        results = [dict(before)] if include_before else []
        for branch in branches:
            self.tainted = dict(before)
            if branch is not None:
                self.visit(branch)
            results.append(self.tainted)
        self.tainted = merge_taint_states(results)

    def visit(self, node) -> None:  # type: ignore[no-untyped-def]
        t = node.type
        if t in ("program", "statement_block"):
            for c in node.named_children:
                self.visit(c)
        elif t == "expression_statement":
            if node.named_children:
                self.visit(node.named_children[0])
        elif t in ("variable_declaration", "lexical_declaration"):
            for decl in node.named_children:
                if decl.type != "variable_declarator":
                    continue
                value = decl.child_by_field_name("value")
                name_node = decl.child_by_field_name("name")
                if value is not None and name_node is not None:
                    self._assign(name_node, self.expr_taint(value))
        elif t == "call_expression":
            self.expr_taint(node)  # a bare call statement: walked for its sink/summary effects
        elif t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None:
                self._assign(left, self.expr_taint(right))
        elif t == "augmented_assignment_expression":
            # A distinct tree-sitter node type from `assignment_expression` (not a variant of it),
            # so it was previously matched by no branch at all here -- `x += y` was a silent no-op,
            # never updating `x`'s taint even when `y` (or `x` itself) was tainted. The new value
            # depends on both the old `x` and `y`.
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None:
                old = self.expr_taint(left) if left.type == "identifier" else frozenset()
                self._assign(left, old | self.expr_taint(right))
        elif t == "return_statement":
            value = node.named_children[0] if node.named_children else None
            self.returns = self.returns | self.expr_taint(value)
        elif t == "if_statement":
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            # `else_clause` wraps the real alternative as its own last child; a bare `else { ... }`
            # has no separate field to reach the block through directly.
            alt_block = alternative.children[-1] if alternative is not None else None
            self._visit_branches([consequence, alt_block])
        elif t in ("for_statement", "for_in_statement", "while_statement", "do_statement"):
            if t == "for_in_statement":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                iter_taint = self.expr_taint(right)
                if iter_taint and left is not None:
                    for name in _target_names(left):
                        self.tainted[name] = self.tainted.get(name, frozenset()) | iter_taint
            branches = []
            if t == "for_statement":
                # A C-style for's `initializer` (`let i = evil()`) always runs exactly once,
                # before the loop starts -- unlike `body`/`increment`, which may run zero or more
                # times -- so it is visited directly into the surrounding state, not as one of the
                # branches `_visit_branches` treats as "may or may not have happened." Without this,
                # `i`'s own taint (from a tainted initializer) was silently never set.
                initializer = node.child_by_field_name("initializer")
                if initializer is not None:
                    self.visit(initializer)
                increment = node.child_by_field_name("increment")
                if increment is not None:
                    branches.append(increment)
            body = node.child_by_field_name("body")
            self._visit_branches([body, *branches], include_before=True)
        elif t == "try_statement":
            body = node.child_by_field_name("body")
            handler = node.child_by_field_name("handler")
            finalizer = node.child_by_field_name("finalizer")
            handler_body = handler.child_by_field_name("body") if handler is not None else None
            self._visit_branches([body, handler_body])
            if finalizer is not None:
                fin_block = finalizer.children[-1] if finalizer.children else None
                if fin_block is not None:
                    self.visit(fin_block)
        # function/class/method declarations encountered while walking a body are not recursed
        # into: they get their own Symbol and their own top-level call to `analyze_function`.


def analyze_function(
    node: Any,
    path: str,
    initial_taint: dict[str, TaintSet],
    resolve_callee: Callable[[str], str | None],
    summaries: dict[str, FunctionSummary],
    catalog: Catalog,
) -> tuple[TaintSet, list[SinkHit]]:
    body = node.child_by_field_name("body")
    flow = _FunctionFlow(path, resolve_callee, summaries, catalog)
    flow.tainted = dict(initial_taint)
    if body is not None:
        flow.visit(body)
    return flow.returns, flow.sinks


def _param_name(p) -> str | None:  # type: ignore[no-untyped-def]
    if p.type == "identifier":
        return _text(p)
    if p.type in ("required_parameter", "optional_parameter"):
        # TypeScript wraps every parameter this way, even with no type annotation at all -- plain
        # JavaScript's grammar never does, which is why this needs its own case: `pattern` holds the
        # actual name, `type` (unused here) the annotation.
        pattern = p.child_by_field_name("pattern")
        return _text(pattern) if pattern is not None and pattern.type == "identifier" else None
    return None  # destructuring/default-value params: no bare name (documented gap, same as _target_names)


def param_names(node) -> list[str]:  # type: ignore[no-untyped-def]
    params_node = node.child_by_field_name("parameters")
    if params_node is None:
        single = node.child_by_field_name("parameter")  # a single-arg arrow fn: `x => ...`
        name = _param_name(single) if single is not None else None
        return [name] if name is not None else []
    return [n for p in params_node.named_children if (n := _param_name(p)) is not None]


__all__ = ["SOURCE", "analyze_function", "param_names"]
