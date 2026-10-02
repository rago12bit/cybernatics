"""Go intra-procedural taint flow (plan §20.3), via tree-sitter -- the same grammar
`core.codeintel.go_lang` already parses Go with. See `python_flow.py`'s module docstring for the
shared algorithm and its documented precision trade-offs (not path-sensitive, loops visited once);
everything there applies here unchanged.

No `try`/`catch` equivalent exists in Go (its error handling is ordinary `if err != nil` control
flow, already covered by the general `if_statement` case), and struct/slice/map composite literals
are not special-cased -- an honest gap, not a silent guess: a value built from a composite literal's
tainted fields is not tracked as tainted itself.
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


def _text(node: Any) -> str:
    return node.text.decode("utf-8", "replace") if node.text else ""


def _callee_name(func: Any) -> str | None:
    if func.type == "identifier":
        return _text(func)
    if func.type == "selector_expression":
        field = func.child_by_field_name("field")
        return _text(field) if field is not None else None
    return None


def _block_stmts(block: Any) -> list[Any]:
    """`block`'s children are `{`, an optional `statement_list`, `}` -- an empty block has no
    `statement_list` at all."""
    if block is None:
        return []
    lists = [c for c in block.named_children if c.type == "statement_list"]
    return list(lists[0].named_children) if lists else []


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

    def _call_taint(self, call: Any) -> TaintSet:
        args_node = call.child_by_field_name("arguments")
        args = list(args_node.named_children) if args_node is not None else []
        arg_taint = self._union([self.expr_taint(a) for a in args])
        fn = call.child_by_field_name("function")
        receiver_taint = (
            self.expr_taint(fn.child_by_field_name("operand"))
            if fn is not None and fn.type == "selector_expression"
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
            # not silently erase a receiver's real taint.
            return result | arg_taint | receiver_taint
        return arg_taint | receiver_taint

    def expr_taint(self, node: Any) -> TaintSet:
        if node is None:
            return frozenset()
        t = node.type
        if t == "identifier":
            return self.tainted.get(_text(node), frozenset())
        if t == "call_expression":
            return self._call_taint(node)
        if t == "selector_expression":
            return self.expr_taint(node.child_by_field_name("operand"))
        if t == "index_expression":
            return self.expr_taint(node.child_by_field_name("operand")) | self.expr_taint(
                node.child_by_field_name("index")
            )
        if t == "binary_expression":
            return self.expr_taint(node.child_by_field_name("left")) | self.expr_taint(
                node.child_by_field_name("right")
            )
        if t in ("unary_expression", "parenthesized_expression"):
            operand = node.child_by_field_name("operand")
            if operand is not None:
                return self.expr_taint(operand)
            children = node.named_children
            return self.expr_taint(children[0]) if children else frozenset()
        if t == "expression_list":
            return self._union([self.expr_taint(c) for c in node.named_children])
        return frozenset()  # a func literal, composite literal, or constant

    def _assign_one(self, target: Any, t: TaintSet) -> None:
        if target.type == "identifier":
            name = _text(target)
            if name == "_":
                return
            if t:
                self.tainted[name] = t
            else:
                self.tainted.pop(name, None)
        # selector/index assignment targets (obj.field = ..., s[i] = ...): no bare name to record
        # taint against, the same variable-name granularity gap `python_flow`/`js_flow` document.

    def _assign(self, left: Any, right: Any) -> None:
        targets = list(left.named_children) if left is not None else []
        values = list(right.named_children) if right is not None else []
        if len(values) == 1 and len(targets) > 1:
            # `a, b := f()`: a single multi-value-returning call -- no per-return-value precision,
            # every assigned name gets the whole call's taint.
            t = self.expr_taint(values[0])
            for target in targets:
                self._assign_one(target, t)
            return
        for target, value in zip(targets, values, strict=False):
            self._assign_one(target, self.expr_taint(value))

    def _visit_branches(self, branches: list[list[Any]], include_before: bool = False) -> None:
        """See `python_flow._visit_branches`: each branch starts from the same state and the
        results are merged by unioning tags, not visited sequentially into one shared map."""
        before = dict(self.tainted)
        results = [dict(before)] if include_before else []
        for branch in branches:
            self.tainted = dict(before)
            self.visit_body(branch)
            results.append(self.tainted)
        self.tainted = merge_taint_states(results)

    def visit_body(self, stmts: list[Any]) -> None:
        for s in stmts:
            self.visit_stmt(s)

    def visit_stmt(self, s: Any) -> None:
        t = s.type
        if t in ("short_var_declaration", "assignment_statement"):
            self._assign(s.child_by_field_name("left"), s.child_by_field_name("right"))
        elif t == "expression_statement":
            for c in s.named_children:
                self.expr_taint(c)  # a bare call statement: walked for its sink/summary effects
        elif t == "return_statement":
            values = [c for c in s.children if c.type == "expression_list"]
            if values:
                self.returns = self.returns | self.expr_taint(values[0])
        elif t == "if_statement":
            consequence = s.child_by_field_name("consequence")
            alternative = s.child_by_field_name("alternative")
            if alternative is not None and alternative.type == "if_statement":
                # an `else if`: visited as its own branch, alongside the `if`'s own consequence,
                # rather than nested -- both are alternatives from this point, which is what the
                # union-based merge needs.
                before = dict(self.tainted)
                self.tainted = dict(before)
                self.visit_body(_block_stmts(consequence))
                after_body = self.tainted
                self.tainted = dict(before)
                self.visit_stmt(alternative)
                after_alt = self.tainted
                self.tainted = merge_taint_states([after_body, after_alt])
            else:
                self._visit_branches([_block_stmts(consequence), _block_stmts(alternative)])
        elif t == "for_statement":
            range_clauses = [c for c in s.children if c.type == "range_clause"]
            for_clauses = [c for c in s.children if c.type == "for_clause"]
            if range_clauses:
                rc = range_clauses[0]
                left, right = rc.child_by_field_name("left"), rc.child_by_field_name("right")
                iter_taint = self.expr_taint(right)
                if iter_taint and left is not None:
                    for name_node in left.named_children:
                        if name_node.type == "identifier" and _text(name_node) != "_":
                            self.tainted[_text(name_node)] = (
                                self.tainted.get(_text(name_node), frozenset()) | iter_taint
                            )
            branches = []
            if for_clauses:
                # A C-style `for init; cond; post { }`'s clauses live inside their own
                # `for_clause` node, not as direct children of `for_statement` -- previously
                # nothing here looked inside it at all, so `initializer` (e.g. `i := evil()`) was
                # silently never visited. `initializer` always runs exactly once before the loop,
                # so (like `python_flow`/`js_flow`'s own equivalent fix) it is visited directly
                # into the surrounding state; `update` may run every iteration, so it is merged as
                # one more branch alongside `body`, same as `js_flow`'s `increment`.
                fc = for_clauses[0]
                initializer = fc.child_by_field_name("initializer")
                if initializer is not None:
                    self.visit_stmt(initializer)
                update = fc.child_by_field_name("update")
                if update is not None:
                    branches.append([update])
            body = s.child_by_field_name("body")
            self._visit_branches([_block_stmts(body), *branches], include_before=True)
        # function/method declarations and func literals encountered while walking a body are not
        # recursed into: they get their own Symbol and their own top-level call to `analyze_function`
        # (a func literal assigned to a variable is a documented gap, same as `python_flow`'s Lambda).


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
    flow.visit_body(_block_stmts(body))
    return flow.returns, flow.sinks


def param_names(node: Any) -> list[str]:
    params_node = node.child_by_field_name("parameters")
    if params_node is None:
        return []
    names = []
    for p in params_node.named_children:
        if p.type != "parameter_declaration":
            continue
        name = p.child_by_field_name("name")
        if name is not None:
            names.append(_text(name))
    return names


__all__ = ["SOURCE", "analyze_function", "param_names"]
