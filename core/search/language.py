"""The Issues query language (Week 73, plan §56), for experts, beside the filter panel:

    priority:P1 sla:breached project:payments-* -status:accepted

Grammar (whitespace separates terms; nothing else is an operator):

    query  := term*
    term   := "-"? key ":" values      a filter; "-" excludes instead
            | word | "quoted text"      free text, matched against the title
    values := value ("," value)*       any one of them (OR)
    value  := bare | "quoted"          `*` is a wildcard where the key allows one

Dates take a comparison: `first_seen:>30d` (more than 30 days ago), `first_seen:<7d` (within the
last 7 days), `first_seen:>=2026-01-01`, or a range `first_seen:2026-01-01..2026-02-01`.

This is the authoritative parser: the API parses `q` with it, and the web app's twin
(web/lib/issue-query.ts) parses the same text so the panel and the query bar stay in sync. Both run
the shared cases in tests/fixtures/issue_query_cases.json, so the two cannot drift apart silently.
Every token keeps its character span, so an error can point at the text that caused it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Literal

Kind = Literal["enum", "glob", "text", "date"]

# key -> (kind, allowed values for enums). Values are compared case-insensitively and stored in
# the case shown here.
KEYS: dict[str, tuple[Kind, tuple[str, ...]]] = {
    "status": ("enum", ("open", "accepted", "not_a_risk", "fixed")),
    "severity": ("enum", ("critical", "high", "medium", "low", "info")),
    "priority": ("enum", ("P1", "P2", "P3", "P4", "none")),
    "sla": ("enum", ("breached", "due_soon", "on_track")),
    "project": ("glob", ()),
    "portfolio": ("glob", ()),
    "path": ("glob", ()),
    "category": ("enum", ("sast", "sca", "secrets", "iac", "container", "dast")),
    "source": ("text", ()),
    "assignee": ("text", ()),
    "tag": ("text", ()),
    "retest": ("enum", ("requested", "passed", "failed")),
    "first_seen": ("date", ()),
    "last_seen": ("date", ()),
    "fixed": ("date", ()),
}
ALIASES = {"sev": "severity", "prio": "priority", "unit": "portfolio", "bu": "portfolio",
           "owner": "assignee", "state": "status"}  # fmt: skip
# The order a query is written back in (the panel's group order, then free text).
ORDER = tuple(KEYS)
MAX_LENGTH = 2000
MAX_TERMS = 40
MAX_VALUES = 50

_RELATIVE = re.compile(r"^(\d{1,4})d$")
_ABSOLUTE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_BARE_OK = re.compile(r"^[^\s\",:]+$")


class QueryError(ValueError):
    """A query that cannot be read, with the span of text at fault (`start` <= i < `end`)."""

    def __init__(self, message: str, start: int, end: int) -> None:
        super().__init__(message)
        self.message, self.start, self.end = message, start, end

    def to_dict(self) -> dict[str, Any]:
        return {"message": self.message, "start": self.start, "end": self.end}


Op = Literal[">", ">=", "<", "<="]
_FLIP: dict[str, Op] = {">": "<", ">=": "<=", "<": ">", "<=": ">="}


@dataclass
class DateBound:
    """One side of a date filter, kept as written: an absolute day (`>=2026-01-01`: on or after
    it), or an age (`>30d`: more than 30 days ago)."""

    op: Op
    days: int | None = None
    day: date | None = None

    def text(self) -> str:
        return f"{self.op}{self.days}d" if self.days is not None else f"{self.op}{self.day}"

    def bound(self, now: datetime) -> tuple[Op, datetime]:
        """The comparison to apply to the date column: an age compares the other way round
        (older than 30 days is a date before now - 30 days)."""
        if self.days is not None:
            return _FLIP[self.op], now - timedelta(days=self.days)
        assert self.day is not None
        day = datetime(self.day.year, self.day.month, self.day.day, tzinfo=timezone.utc)
        return self.op, day


@dataclass
class Clause:
    """Everything the query says about one key: values to keep, values to drop."""

    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    dates: list[DateBound] = field(default_factory=list)


@dataclass
class Query:
    clauses: dict[str, Clause] = field(default_factory=dict)
    text: list[str] = field(default_factory=list)

    def clause(self, key: str) -> Clause:
        return self.clauses.setdefault(key, Clause())

    def to_dict(self) -> dict[str, Any]:
        """A plain, ordered form (the shared test fixtures compare against this)."""
        out: dict[str, Any] = {}
        for key in ORDER:
            c = self.clauses.get(key)
            if c is None:
                continue
            entry: dict[str, Any] = {}
            if c.include:
                entry["include"] = c.include
            if c.exclude:
                entry["exclude"] = c.exclude
            if c.dates:
                entry["dates"] = [d.text() for d in c.dates]
            if entry:
                out[key] = entry
        if self.text:
            out["text"] = self.text
        return out


@dataclass
class Token:
    """A term as written, with its span: what autocomplete and error highlighting work from."""

    start: int
    end: int
    negated: bool
    key: str | None  # None: free text
    raw_values: list[tuple[str, int, int]]  # (value, start, end), quotes removed


def _quote(value: str) -> str:
    if _BARE_OK.match(value):
        return value
    return '"' + value.replace('"', "") + '"'


def tokenize(text: str) -> list[Token]:
    """Split into terms, keeping spans. Raises QueryError for an unterminated quote."""
    if len(text) > MAX_LENGTH:
        raise QueryError(f"A query is at most {MAX_LENGTH} characters.", MAX_LENGTH, len(text))
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            i += 1
            continue
        start = i
        negated = False
        if text[i] == "-" and i + 1 < n and not text[i + 1].isspace():
            negated, i = True, i + 1
        if text[i] == '"':
            value, i = _read_quoted(text, i)
            if i < n and not text[i].isspace():
                raise QueryError("Leave a space after the closing quote.", start, i + 1)
            tokens.append(Token(start, i, negated, None, [(value, start + negated, i)]))
            continue
        j = i
        while j < n and not text[j].isspace() and text[j] not in ':"':
            j += 1
        if j < n and text[j] == ":":
            key = text[i:j]
            values, i = _read_values(text, j + 1)
            tokens.append(Token(start, i, negated, key, values))
            continue
        while j < n and not text[j].isspace():
            if text[j] == '"':
                raise QueryError("Put quotes around the whole phrase.", start, j + 1)
            j += 1
        tokens.append(Token(start, j, negated, None, [(text[i:j], i, j)]))
        i = j
    return tokens


def _read_quoted(text: str, i: int) -> tuple[str, int]:
    end = text.find('"', i + 1)
    if end == -1:
        raise QueryError("This quote is never closed.", i, len(text))
    return text[i + 1 : end], end + 1


def _read_values(text: str, i: int) -> tuple[list[tuple[str, int, int]], int]:
    values: list[tuple[str, int, int]] = []
    n = len(text)
    while True:
        start = i
        if i < n and text[i] == '"':
            value, i = _read_quoted(text, i)
            if i < n and not text[i].isspace() and text[i] != ",":
                raise QueryError("Leave a space after the closing quote.", start, i + 1)
        else:
            while i < n and not text[i].isspace() and text[i] not in ',"':
                i += 1
            value = text[start:i]
        values.append((value, start, i))
        if i < n and text[i] == ",":
            i += 1
            continue
        return values, i


def _key(name: str, start: int, end: int) -> str:
    k = name.lower()
    k = ALIASES.get(k, k)
    if k not in KEYS:
        known = ", ".join(KEYS)
        raise QueryError(f"There is no filter called “{name}”. Filters: {known}.", start, end)
    return k


def _date(value: str, start: int, end: int) -> list[DateBound]:
    if ".." in value:
        lo, _, hi = value.partition("..")
        if lo.startswith(("<", ">")) or hi.startswith(("<", ">")):
            raise QueryError("A range is two dates: 2026-01-01..2026-02-01.", start, end)
        return [_one_date(">=" + lo, start, end), _one_date("<" + hi, start, end, next_day=True)]
    return [_one_date(value, start, end)]


def _one_date(value: str, start: int, end: int, next_day: bool = False) -> DateBound:
    m = re.match(r"^(>=|<=|>|<)?(.*)$", value)
    assert m is not None
    op = m.group(1) or ">="
    rest = m.group(2)
    rel = _RELATIVE.match(rest)
    if rel:
        # An age reads naturally as "older than": first_seen:>30d is more than 30 days ago.
        return DateBound(op, days=int(rel.group(1)))  # type: ignore[arg-type]
    if _ABSOLUTE.match(rest):
        try:
            day = date.fromisoformat(rest)
        except ValueError:
            raise QueryError(f"“{rest}” is not a real date.", start, end) from None
        if next_day:
            day += timedelta(days=1)
        return DateBound(op, day=day)  # type: ignore[arg-type]
    raise QueryError(
        "A date is like >30d (more than 30 days ago), <7d, >=2026-01-01, or "
        "2026-01-01..2026-02-01.",
        start,
        end,
    )


def parse(text: str) -> Query:
    """Read a query. Raises QueryError (with the span at fault) for anything it cannot read."""
    tokens = tokenize(text)
    if len(tokens) > MAX_TERMS:
        raise QueryError(
            f"A query has at most {MAX_TERMS} terms.", tokens[MAX_TERMS].start, len(text)
        )
    q = Query()
    for t in tokens:
        if t.key is None:
            word = t.raw_values[0][0].strip()
            if t.negated:
                raise QueryError("Free text cannot be excluded; use a filter.", t.start, t.end)
            if word and word.lower() not in (w.lower() for w in q.text):
                q.text.append(word)
            continue
        key = _key(t.key, t.start, t.start + len(t.key) + t.negated)
        kind, allowed = KEYS[key]
        clause = q.clause(key)
        for value, vs, ve in t.raw_values:
            if not value:
                raise QueryError(f"“{key}:” needs a value.", t.start, max(ve, t.end))
            if kind == "date":
                if t.negated:
                    raise QueryError(
                        "Write the opposite comparison instead of “-”.", t.start, t.end
                    )
                clause.dates.extend(_date(value, vs, ve))
                continue
            if kind == "enum":
                match = next((a for a in allowed if a.lower() == value.lower()), None)
                if match is None:
                    raise QueryError(
                        f"“{value}” is not a {key}. Choose from: {', '.join(allowed)}.", vs, ve
                    )
                value = match
            elif "*" in value and kind != "glob":
                raise QueryError(f"“*” works in project, portfolio and path, not {key}.", vs, ve)
            target = clause.exclude if t.negated else clause.include
            if value not in target:
                target.append(value)
            if len(clause.include) + len(clause.exclude) > MAX_VALUES:
                raise QueryError(f"At most {MAX_VALUES} values for {key}.", vs, ve)
    for key in [k for k, c in q.clauses.items() if not (c.include or c.exclude or c.dates)]:
        del q.clauses[key]
    return q


def format_query(q: Query) -> str:
    """Write a query back as text, in a fixed order: the panel's way of updating the query bar.
    `parse(format_query(q))` gives back `q`."""
    parts: list[str] = []
    for key in ORDER:
        c = q.clauses.get(key)
        if c is None:
            continue
        if c.include:
            parts.append(f"{key}:" + ",".join(_quote(v) for v in c.include))
        if c.exclude:
            parts.append(f"-{key}:" + ",".join(_quote(v) for v in c.exclude))
        parts.extend(f"{key}:{d.text()}" for d in c.dates)
    parts.extend(_quote(w) for w in q.text)
    return " ".join(parts)


def glob_to_like(pattern: str) -> str:
    """`payments-*` as a SQL LIKE pattern (escape character `\\`)."""
    escaped = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%")


def glob_match(pattern: str, value: str) -> bool:
    """Case-insensitive `*` matching. A pattern without "/" also matches a label's last part, so
    `payments-*` matches the project `acme/payments-api`."""
    rx = re.compile("^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$", re.IGNORECASE)
    if rx.match(value):
        return True
    return "/" not in pattern and bool(rx.match(value.rsplit("/", 1)[-1]))
