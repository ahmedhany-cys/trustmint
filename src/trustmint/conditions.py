"""Claim conditions as a small three-valued expression tree.

Each cloud says "which tokens may use this identity" in its own language: AWS
condition operators, Google CEL, Entra subject matching. The sources translate
them into this tree so the analyzer only evaluates one thing.

Evaluation returns True, False, or None. None means the tree contains a
construct TrustMint does not model, and the answer is "could not decide",
never a guess.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

Claims = Mapping[str, Any]
Tri = bool | None


def all_of(values: Iterable[Tri]) -> Tri:
    result: Tri = True
    for value in values:
        if value is False:
            return False
        if value is None:
            result = None
    return result


def any_of(values: Iterable[Tri]) -> Tri:
    result: Tri = False
    for value in values:
        if value is True:
            return True
        if value is None:
            result = None
    return result


@dataclass(frozen=True)
class Literal:
    """A string a condition compares a claim against.

    ``claim`` is the token claim the literal is compared with, when known.
    ``kind`` says how it is compared: exact, glob, prefix, suffix, contains
    or regex. Platforms use literals to build candidate tokens.
    """

    claim: str | None
    value: str
    kind: str = "exact"


@lru_cache(maxsize=4096)
def glob_regex(pattern: str, ignore_case: bool = False) -> re.Pattern[str]:
    """AWS StringLike semantics: ``*`` is any run of characters, ``?`` one character."""
    parts = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    flags = re.DOTALL | (re.IGNORECASE if ignore_case else 0)
    return re.compile("".join(parts), flags)


def glob_match(pattern: str, value: str, ignore_case: bool = False) -> bool:
    return glob_regex(pattern, ignore_case).fullmatch(value) is not None


class Node:
    def evaluate(self, claims: Claims) -> Tri:
        raise NotImplementedError

    def literals(self) -> Iterator[Literal]:
        return iter(())

    def describe(self) -> str:
        raise NotImplementedError

    def unknown_reasons(self) -> Iterator[str]:
        return iter(())


@dataclass
class Always(Node):
    value: bool
    reason: str = ""

    def evaluate(self, claims: Claims) -> Tri:
        return self.value

    def describe(self) -> str:
        return "true" if self.value else "false"


@dataclass
class Unknown(Node):
    reason: str

    def evaluate(self, claims: Claims) -> Tri:
        return None

    def describe(self) -> str:
        return f"<undecidable: {self.reason}>"

    def unknown_reasons(self) -> Iterator[str]:
        yield self.reason


@dataclass
class AllOf(Node):
    children: list[Node]

    def evaluate(self, claims: Claims) -> Tri:
        return all_of(child.evaluate(claims) for child in self.children)

    def literals(self) -> Iterator[Literal]:
        for child in self.children:
            yield from child.literals()

    def describe(self) -> str:
        if not self.children:
            return "true"
        return " AND ".join(_wrap(child) for child in self.children)

    def unknown_reasons(self) -> Iterator[str]:
        for child in self.children:
            yield from child.unknown_reasons()


@dataclass
class AnyOf(Node):
    children: list[Node]

    def evaluate(self, claims: Claims) -> Tri:
        return any_of(child.evaluate(claims) for child in self.children)

    def literals(self) -> Iterator[Literal]:
        for child in self.children:
            yield from child.literals()

    def describe(self) -> str:
        if not self.children:
            return "false"
        return " OR ".join(_wrap(child) for child in self.children)

    def unknown_reasons(self) -> Iterator[str]:
        for child in self.children:
            yield from child.unknown_reasons()


@dataclass
class Not(Node):
    child: Node

    def evaluate(self, claims: Claims) -> Tri:
        value = self.child.evaluate(claims)
        return None if value is None else not value

    def literals(self) -> Iterator[Literal]:
        return self.child.literals()

    def describe(self) -> str:
        return f"NOT {_wrap(self.child)}"

    def unknown_reasons(self) -> Iterator[str]:
        return self.child.unknown_reasons()


_OPS = {"equals", "glob", "prefix", "suffix", "contains", "regex", "present"}


@dataclass
class Match(Node):
    """``claim`` compared with any of ``values``.

    ``if_exists``: a missing claim satisfies the match (AWS ...IfExists).
    ``set_mode``: "all" gives AWS ForAllValues semantics, under which a
    missing claim also satisfies the match. Multi-valued claims match when
    any element matches, or every element for "all".
    """

    claim: str
    op: str
    values: tuple[str, ...] = ()
    ignore_case: bool = False
    if_exists: bool = False
    set_mode: str | None = None

    def __post_init__(self) -> None:
        if self.op not in _OPS:
            raise ValueError(f"unknown match op {self.op}")

    def evaluate(self, claims: Claims) -> Tri:
        if self.claim not in claims or claims[self.claim] is None:
            if self.op == "present":
                return False
            return self.if_exists or self.set_mode == "all"
        if self.op == "present":
            return True
        actual = claims[self.claim]
        items = actual if isinstance(actual, (list, tuple)) else [actual]
        hits = [self._one(str(item)) for item in items]
        if self.set_mode == "all":
            return all(hits)
        return any(hits)

    def _one(self, actual: str) -> bool:
        for expected in self.values:
            a, e = (actual.lower(), expected.lower()) if self.ignore_case else (actual, expected)
            if self.op == "equals" and a == e:
                return True
            if self.op == "glob" and glob_match(expected, actual, self.ignore_case):
                return True
            if self.op == "prefix" and a.startswith(e):
                return True
            if self.op == "suffix" and a.endswith(e):
                return True
            if self.op == "contains" and e in a:
                return True
            if self.op == "regex" and re.search(expected, actual):
                return True
        return False

    def literals(self) -> Iterator[Literal]:
        kind = {"equals": "exact"}.get(self.op, self.op)
        for value in self.values:
            if kind == "glob" and "*" not in value and "?" not in value:
                yield Literal(self.claim, value, "exact")
            else:
                yield Literal(self.claim, value, kind)

    def describe(self) -> str:
        if self.op == "present":
            return f"{self.claim} is present"
        symbol = {
            "equals": "==",
            "glob": "like",
            "prefix": "startsWith",
            "suffix": "endsWith",
            "contains": "contains",
            "regex": "matches",
        }[self.op]
        shown = ", ".join(repr(v) for v in self.values)
        if len(self.values) != 1:
            shown = f"[{shown}]"
        suffix = " (if present)" if self.if_exists else ""
        return f"{self.claim} {symbol} {shown}{suffix}"


def _wrap(node: Node) -> str:
    text = node.describe()
    if isinstance(node, (AllOf, AnyOf)) and len(node.children) > 1:
        return f"({text})"
    return text
