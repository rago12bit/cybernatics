"""Python intra-procedural taint flow (plan §20.3): given one function body and an initial set of
tainted names, tracks which local variables become tainted, records every sink hit, and reports
which of the initial tags reach the function's own return value.

The same function answers two different questions depending only on what `initial_taint` is seeded
with (see `core.taint.models`): "if parameter i is ever tainted, what happens?" (a `FunctionSummary`,
seeded with `{param_name: {i}}`) and "starting from this real entrypoint, what actually happens?"
(a `TaintFinding`, seeded with `{source_name: {SOURCE}}`).

Deliberately not path-sensitive, and not loop-fixed-pointed: `if`/`try` branches are each walked
from the same starting state and then merged back together by unioning every name's taint tags (see
`_visit_branches`), so a name tainted on only one branch is still seen as tainted afterward, and a
loop body is visited once, not iterated to convergence. This can report a finding no single concrete
execution path produces, and can miss one that only becomes tainted on a loop's second iteration
from a read earlier in the same iteration. That trade-off is deliberate: for a security tool, a
reviewable false positive costs far less than a silently missed real one, and a fully path- and
loop-sensitive analysis is a materially larger project than this module -- the plan itself calls this
whole feature "the most demanding piece of programming in the project" without that additional
precision. `docs/adr/0021-taint-analysis.md` records this trade-off and the validation against
Semgrep's own taint mode that was measured against it, not assumed.

A nested `def`/`class` encountered while walking a function's body is *not* recursed into here: it
gets its own `Symbol` and its own call to this function when `core.codeintel` visits it separately,
and analysing it twice under two different symbol ids would double-count its sinks.
"""

from __future__ import annotations

import ast
from collections.abc import Callable

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


def _arg_expr(call: ast.Call, tag: int, param_names: tuple[str, ...]) -> ast.expr | None:
    """The expression this call site actually passed for the callee's Nth parameter -- positional
    if passed positionally, by keyword if passed by name (Python allows either for a normal
    parameter, and a call site's re-exposure must not silently drop the keyword case). `None` when
    this call doesn't supply it at all (a default applies, or it only arrives via **kwargs, which
    cannot be matched to a specific tag by name)."""
    if tag < len(call.args):
        return call.args[tag]
    if tag < len(param_names):
        name = param_names[tag]
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
    return None


def _callee_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for el in target.elts:
            names.extend(_target_names(el.value if isinstance(el, ast.Starred) else el))
        return names
    return []  # ast.Attribute / ast.Subscript targets: no bare name to record taint against


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

    def _call_taint(self, call: ast.Call) -> TaintSet:
        arg_taint = self._union([self.expr_taint(a) for a in call.args])
        arg_taint = arg_taint | self._union([self.expr_taint(kw.value) for kw in call.keywords])
        # The receiver of a method call carries its own taint into the result too --
        # `request.args.get('id')` must come out tainted because `request.args` is, even though
        # 'id' (the only *argument*) plainly is not.
        receiver_taint = (
            self.expr_taint(call.func.value)
            if isinstance(call.func, ast.Attribute)
            else frozenset()
        )
        name = _callee_name(call.func)
        if name is None:
            return arg_taint | receiver_taint
        if self._catalog.is_sanitizer(name):
            return frozenset()
        sink = self._catalog.sink_for(name)
        if sink is not None and arg_taint:
            self.sinks.append(SinkHit(arg_taint, self._path, call.lineno, name, sink.category))
        callee_id = self._resolve_callee(name)
        summary = self._summaries.get(callee_id) if callee_id else None
        if summary is not None and callee_id is not None:
            # Re-expose every sink the callee's own summary already found, translated from the
            # callee's parameter indices into whatever tags this call site's actual arguments
            # carry -- the mechanism that lets a hit found one level away from the real sink
            # (a handler that calls a helper that calls cursor.execute) surface at every level of
            # the call graph, each analysed once, exactly as the plan's own wording asks for. Each
            # re-exposure prepends one hop describing this call site, so by the time a hit reaches
            # an entrypoint's own analysis, `hops` already reads in call order.
            hop = TaintHop(callee_id, self._path, call.lineno, f"calls {name}()")
            for hit in summary.sinks:
                if SOURCE in hit.params:
                    # Unconditional: the callee's own exposure came from a *global* source (Flask's
                    # `request`, referenced directly in its body), not one of its own parameters, so
                    # it fires on every call regardless of what this call site passes in.
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
                        self.expr_taint(expr)
                        for tag in hit.params
                        if isinstance(tag, int)
                        and (expr := _arg_expr(call, tag, summary.param_names)) is not None
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
                if isinstance(tag, int):
                    expr = _arg_expr(call, tag, summary.param_names)
                    if expr is not None:
                        result = result | self.expr_taint(expr)
            return result
        # Unresolved call, stdlib/third-party function, or a callee with no summary yet: assume
        # taint passes through -- see module docstring on the false-positive/false-negative trade-off.
        return arg_taint | receiver_taint

    def expr_taint(self, e: ast.expr | None) -> TaintSet:
        if e is None:
            return frozenset()
        if isinstance(e, ast.Name):
            return self.tainted.get(e.id, frozenset())
        if isinstance(e, ast.Call):
            return self._call_taint(e)
        if isinstance(e, ast.Attribute):
            return self.expr_taint(e.value)
        if isinstance(e, ast.Subscript):
            return self.expr_taint(e.value) | self.expr_taint(e.slice)
        if isinstance(e, ast.BinOp):
            return self.expr_taint(e.left) | self.expr_taint(e.right)
        if isinstance(e, ast.BoolOp):
            return self._union([self.expr_taint(v) for v in e.values])
        if isinstance(e, ast.Compare):
            return self.expr_taint(e.left) | self._union(
                [self.expr_taint(c) for c in e.comparators]
            )
        if isinstance(e, ast.IfExp):
            return self.expr_taint(e.body) | self.expr_taint(e.orelse)
        if isinstance(e, ast.UnaryOp):
            return self.expr_taint(e.operand)
        if isinstance(e, ast.JoinedStr):  # an f-string
            return self._union(
                [self.expr_taint(v.value) for v in e.values if isinstance(v, ast.FormattedValue)]
            )
        if isinstance(e, ast.FormattedValue):
            return self.expr_taint(e.value)
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            return self._union([self.expr_taint(el) for el in e.elts])
        if isinstance(e, ast.Dict):
            return self._union([self.expr_taint(k) for k in e.keys if k is not None]) | self._union(
                [self.expr_taint(v) for v in e.values]
            )
        if isinstance(e, ast.Starred):
            return self.expr_taint(e.value)
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._comprehension_taint(e.generators, [e.elt])
        if isinstance(e, ast.DictComp):
            return self._comprehension_taint(e.generators, [e.key, e.value])
        return frozenset()  # Lambda, constants, and anything else: no taint tracked through it

    def _comprehension_taint(
        self, generators: list[ast.comprehension], result_exprs: list[ast.expr]
    ) -> TaintSet:
        added: list[str] = []
        for gen in generators:
            t = self.expr_taint(gen.iter)
            if t:
                for name in _target_names(gen.target):
                    self.tainted[name] = self.tainted.get(name, frozenset()) | t
                    added.append(name)
        result = self._union([self.expr_taint(r) for r in result_exprs])
        for name in added:
            self.tainted.pop(name, None)
        return result

    def _assign(self, target: ast.expr, t: TaintSet) -> None:
        if isinstance(target, ast.Starred):
            target = target.value
        if isinstance(target, ast.Name):
            if t:
                self.tainted[target.id] = t
            else:
                self.tainted.pop(target.id, None)  # reassigned clean: no longer tainted
        elif isinstance(target, (ast.Tuple, ast.List)):
            for el in target.elts:
                self._assign(el, t)  # no per-element precision: every unpacked name gets it all

    def visit_body(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.visit_stmt(stmt)

    def _visit_branches(self, branches: list[list[ast.stmt]], include_before: bool = False) -> None:
        """Each branch is walked independently from the *same* starting state, then the resulting
        states are merged by unioning each name's tags -- not visited sequentially into one shared
        map. Sequential visiting would let one branch's clean reassignment wrongly erase taint an
        earlier branch introduced (an `if`/`else` where only one arm taints a name is exactly this
        case). `sinks`/`returns` need no such merge: they already accumulate on `self` regardless of
        which branch is being walked, which is the correct "may happen on some path" semantics for
        a security tool's over-approximation (module docstring)."""
        before = dict(self.tainted)
        results = [dict(before)] if include_before else []
        for branch in branches:
            self.tainted = dict(before)
            self.visit_body(branch)
            results.append(self.tainted)
        self._merge(results)

    def _merge(self, results: list[dict[str, TaintSet]]) -> None:
        self.tainted = merge_taint_states(results)

    def visit_stmt(self, s: ast.stmt) -> None:
        if isinstance(s, ast.Assign):
            t = self.expr_taint(s.value)
            for target in s.targets:
                self._assign(target, t)
        elif isinstance(s, ast.AnnAssign):
            if s.value is not None and s.target is not None:
                self._assign(s.target, self.expr_taint(s.value))
        elif isinstance(s, ast.AugAssign) and isinstance(s.target, ast.Name):
            self.tainted[s.target.id] = self.tainted.get(
                s.target.id, frozenset()
            ) | self.expr_taint(s.value)
        elif isinstance(s, ast.Expr):
            self.expr_taint(
                s.value
            )  # a bare call statement: still walked, for its sink/summary effects
        elif isinstance(s, ast.Return):
            if s.value is not None:
                self.returns = self.returns | self.expr_taint(s.value)
        elif isinstance(s, ast.If):
            self._visit_branches([s.body, s.orelse])
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            t = self.expr_taint(s.iter)
            if t:
                for name in _target_names(s.target):
                    self.tainted[name] = self.tainted.get(name, frozenset()) | t
            self._visit_branches([s.body, s.orelse], include_before=True)
        elif isinstance(s, ast.While):
            self._visit_branches([s.body, s.orelse], include_before=True)
        elif isinstance(s, ast.Try):
            # `else` is not just another parallel branch: it only ever runs once `body` has
            # completed *without* raising, so it must see `body`'s own effects, not the state from
            # before the try started -- a name `body` tainted and `else` merely reads (a common
            # shape: fetch in `try`, use the result once nothing went wrong in `else`) was
            # otherwise invisible here, a real false negative. A handler, in contrast, may run
            # after only part of `body` executed (which statement raised is unknowable), so each
            # still conservatively starts fresh from `before`, same as before this fix.
            before = dict(self.tainted)
            self.tainted = dict(before)
            self.visit_body(s.body)
            after_body = self.tainted
            self.tainted = dict(after_body)
            self.visit_body(s.orelse)
            results = [after_body, self.tainted]
            for h in s.handlers:
                self.tainted = dict(before)
                self.visit_body(h.body)
                results.append(self.tainted)
            self._merge(results)
            self.visit_body(s.finalbody)  # always runs, so applied after the merge above, not in it
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, self.expr_taint(item.context_expr))
            self.visit_body(s.body)
        # FunctionDef/AsyncFunctionDef/ClassDef: not recursed into -- see module docstring


def analyze_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    path: str,
    initial_taint: dict[str, TaintSet],
    resolve_callee: Callable[[str], str | None],
    summaries: dict[str, FunctionSummary],
    catalog: Catalog,
) -> tuple[TaintSet, list[SinkHit]]:
    flow = _FunctionFlow(path, resolve_callee, summaries, catalog)
    flow.tainted = dict(initial_taint)
    flow.visit_body(node.body)
    return flow.returns, flow.sinks


def param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = node.args
    return [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]


__all__ = ["SOURCE", "analyze_function", "param_names"]
