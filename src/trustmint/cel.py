"""A deliberately small subset of CEL, enough for Google workload identity providers.

Supported: string, int, bool and list literals; ``assertion``/``attribute``/
``google`` variables with ``.field`` and ``['field']`` access; ``== != < <= >
>=``, ``&& || !``, ``in``, ``+``; the methods ``startsWith endsWith contains
matches`` and the functions ``size`` and ``has``.

Anything else raises :class:`CelUnsupported`, which the caller turns into an
"undecidable" answer instead of guessing. Runtime errors such as reading a
missing claim raise :class:`CelError`; Google rejects the token in that case.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class CelUnsupported(Exception):
    pass


class CelError(Exception):
    pass


_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<str>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")
  | (?P<num>\d+)
  | (?P<op>&&|\|\||==|!=|<=|>=|[()\[\].,!<>+])
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)


def tokenize(source: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(source):
        match = _TOKEN.match(source, pos)
        if not match:
            raise CelUnsupported(f"unexpected character {source[pos]!r} at {pos}")
        pos = match.end()
        kind = match.lastgroup
        if kind == "ws":
            continue
        text = match.group()
        if kind == "str":
            text = bytes(text[1:-1], "utf-8").decode("unicode_escape")
        tokens.append((kind or "", text))
    tokens.append(("end", ""))
    return tokens


@dataclass
class Lit:
    value: Any


@dataclass
class Var:
    name: str


@dataclass
class Member:
    target: Any
    field: str


@dataclass
class Call:
    target: Any | None
    name: str
    args: list[Any]


@dataclass
class Binary:
    op: str
    left: Any
    right: Any


@dataclass
class Unary:
    op: str
    operand: Any


@dataclass
class ListExpr:
    items: list[Any]


class _Parser:
    def __init__(self, source: str) -> None:
        self.tokens = tokenize(source)
        self.pos = 0

    def peek(self) -> tuple[str, str]:
        return self.tokens[self.pos]

    def take(self, text: str | None = None) -> tuple[str, str]:
        token = self.tokens[self.pos]
        if text is not None and token[1] != text:
            raise CelUnsupported(f"expected {text!r}, found {token[1]!r}")
        self.pos += 1
        return token

    def parse(self) -> Any:
        node = self.or_expr()
        if self.peek()[0] != "end":
            raise CelUnsupported(f"unexpected {self.peek()[1]!r}")
        return node

    def or_expr(self) -> Any:
        node = self.and_expr()
        while self.peek()[1] == "||":
            self.take()
            node = Binary("||", node, self.and_expr())
        return node

    def and_expr(self) -> Any:
        node = self.relation()
        while self.peek()[1] == "&&":
            self.take()
            node = Binary("&&", node, self.relation())
        return node

    def relation(self) -> Any:
        node = self.additive()
        while self.peek()[1] in {"==", "!=", "<", "<=", ">", ">=", "in"}:
            op = self.take()[1]
            node = Binary(op, node, self.additive())
        return node

    def additive(self) -> Any:
        node = self.unary()
        while self.peek()[1] == "+":
            self.take()
            node = Binary("+", node, self.unary())
        return node

    def unary(self) -> Any:
        if self.peek()[1] == "!":
            self.take()
            return Unary("!", self.unary())
        return self.postfix()

    def postfix(self) -> Any:
        node = self.primary()
        while True:
            text = self.peek()[1]
            if text == ".":
                self.take()
                kind, name = self.take()
                if kind != "ident":
                    raise CelUnsupported("expected a field name after '.'")
                if self.peek()[1] == "(":
                    node = Call(node, name, self.arguments())
                else:
                    node = Member(node, name)
            elif text == "[":
                self.take()
                index = self.or_expr()
                self.take("]")
                if not isinstance(index, Lit) or not isinstance(index.value, str):
                    raise CelUnsupported("only constant string indexes are supported")
                node = Member(node, index.value)
            else:
                return node

    def arguments(self) -> list[Any]:
        self.take("(")
        args: list[Any] = []
        if self.peek()[1] != ")":
            args.append(self.or_expr())
            while self.peek()[1] == ",":
                self.take()
                args.append(self.or_expr())
        self.take(")")
        return args

    def primary(self) -> Any:
        kind, text = self.take()
        if kind == "str":
            return Lit(text)
        if kind == "num":
            return Lit(int(text))
        if kind == "ident":
            if text in {"true", "false"}:
                return Lit(text == "true")
            if text == "null":
                return Lit(None)
            if self.peek()[1] == "(":
                return Call(None, text, self.arguments())
            return Var(text)
        if text == "(":
            node = self.or_expr()
            self.take(")")
            return node
        if text == "[":
            items: list[Any] = []
            if self.peek()[1] != "]":
                items.append(self.or_expr())
                while self.peek()[1] == ",":
                    self.take()
                    items.append(self.or_expr())
            self.take("]")
            return ListExpr(items)
        raise CelUnsupported(f"unexpected {text!r}")


def parse(source: str) -> Any:
    return _Parser(source).parse()


_MISSING = object()


def evaluate(node: Any, env: dict[str, Any]) -> Any:
    if isinstance(node, Lit):
        return node.value
    if isinstance(node, Var):
        if node.name not in env:
            raise CelUnsupported(f"unknown variable {node.name}")
        return env[node.name]
    if isinstance(node, ListExpr):
        return [evaluate(item, env) for item in node.items]
    if isinstance(node, Member):
        target = evaluate(node.target, env)
        if not isinstance(target, dict):
            raise CelError(f"cannot read .{node.field} of a non-map")
        value = target.get(node.field, _MISSING)
        if value is _MISSING:
            raise CelError(f"no such key: {node.field}")
        return value
    if isinstance(node, Unary):
        value = evaluate(node.operand, env)
        if not isinstance(value, bool):
            raise CelError("'!' needs a bool")
        return not value
    if isinstance(node, Binary):
        return _binary(node, env)
    if isinstance(node, Call):
        return _call(node, env)
    raise CelUnsupported(f"cannot evaluate {node!r}")


def _binary(node: Binary, env: dict[str, Any]) -> Any:
    if node.op in {"&&", "||"}:
        # CEL's commutative logic: an error on one side is absorbed when the
        # other side alone decides the result.
        results = []
        for side in (node.left, node.right):
            try:
                results.append(evaluate(side, env))
            except CelError as exc:
                results.append(exc)
        decisive = node.op == "||"
        if any(r is decisive for r in results):
            return decisive
        for r in results:
            if isinstance(r, CelError):
                raise r
            if not isinstance(r, bool):
                raise CelError(f"'{node.op}' needs bools")
        return not decisive
    left = evaluate(node.left, env)
    right = evaluate(node.right, env)
    if node.op == "==":
        return left == right
    if node.op == "!=":
        return left != right
    if node.op == "in":
        if isinstance(right, (list, dict)):
            return left in right
        raise CelError("'in' needs a list or map")
    if node.op == "+":
        if type(left) is not type(right):
            raise CelError("'+' needs operands of one type")
        return left + right
    try:
        return {
            "<": left < right,
            "<=": left <= right,
            ">": left > right,
            ">=": left >= right,
        }[node.op]
    except TypeError as exc:
        raise CelError(str(exc)) from exc


def _call(node: Call, env: dict[str, Any]) -> Any:
    if node.target is None:
        if node.name == "has":
            arg = node.args[0] if len(node.args) == 1 else None
            if not isinstance(arg, Member):
                raise CelUnsupported("has() needs a field selection")
            target = evaluate(arg.target, env)
            return isinstance(target, dict) and arg.field in target
        if node.name == "size" and len(node.args) == 1:
            value = evaluate(node.args[0], env)
            try:
                return len(value)
            except TypeError as exc:
                raise CelError(str(exc)) from exc
        raise CelUnsupported(f"function {node.name}() is not supported")
    target = evaluate(node.target, env)
    args = [evaluate(arg, env) for arg in node.args]
    if node.name in {"startsWith", "endsWith", "contains", "matches"}:
        if not isinstance(target, str) or len(args) != 1 or not isinstance(args[0], str):
            raise CelError(f"{node.name}() needs strings")
        if node.name == "startsWith":
            return target.startswith(args[0])
        if node.name == "endsWith":
            return target.endswith(args[0])
        if node.name == "contains":
            return args[0] in target
        return re.search(args[0], target) is not None
    if node.name == "size" and not args:
        return len(target)
    raise CelUnsupported(f"method {node.name}() is not supported")


def walk(node: Any):
    yield node
    if isinstance(node, Member):
        yield from walk(node.target)
    elif isinstance(node, Call):
        if node.target is not None:
            yield from walk(node.target)
        for arg in node.args:
            yield from walk(arg)
    elif isinstance(node, Binary):
        yield from walk(node.left)
        yield from walk(node.right)
    elif isinstance(node, Unary):
        yield from walk(node.operand)
    elif isinstance(node, ListExpr):
        for item in node.items:
            yield from walk(item)


def reference(node: Any) -> tuple[str, str] | None:
    """``assertion.repository`` -> ("assertion", "repository")."""
    if isinstance(node, Member) and isinstance(node.target, Var):
        return node.target.name, node.field
    return None
