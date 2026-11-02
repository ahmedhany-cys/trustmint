"""Microsoft Entra federated identity credentials on app registrations and managed identities.

A classic credential matches ``issuer`` and ``subject`` exactly. A flexible
credential carries a ``claimsMatchingExpression`` such as::

    claims['sub'] matches 'repo:contoso/*' and claims['repository_id'] eq '42'

TrustMint models ``eq``, ``matches`` (``*`` wildcard), ``and``, ``or`` and
parentheses; anything else is reported as undecidable. Inputs are the JSON
of ``az ad app federated-credential list`` and ``az identity
federated-credential list``.
"""

from __future__ import annotations

import re

from trustmint import privilege
from trustmint.conditions import AllOf, AnyOf, Match, Node, Unknown
from trustmint.context import normalize_issuer
from trustmint.model import Trust

_TOKEN = re.compile(
    r"\s*(?:(?P<claim>claims\[\s*'(?P<name>[^']+)'\s*\])|(?P<str>'(?:[^'\\]|\\.)*')"
    r"|(?P<word>[A-Za-z]+)|(?P<paren>[()]))"
)


class _ExpressionParser:
    def __init__(self, text: str) -> None:
        self.tokens: list[tuple[str, str]] = []
        pos = 0
        text = text.strip()
        while pos < len(text):
            match = _TOKEN.match(text, pos)
            if not match or match.end() == pos:
                raise ValueError(f"unexpected text at {pos}: {text[pos : pos + 20]!r}")
            pos = match.end()
            if match["claim"]:
                self.tokens.append(("claim", match["name"]))
            elif match["str"]:
                self.tokens.append(("str", match["str"][1:-1].replace("\\'", "'")))
            elif match["word"]:
                self.tokens.append(("word", match["word"].lower()))
            else:
                self.tokens.append(("paren", match["paren"]))
        self.pos = 0

    def peek(self) -> tuple[str, str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ("end", "")

    def take(self) -> tuple[str, str]:
        token = self.peek()
        self.pos += 1
        return token

    def parse(self) -> Node:
        node = self.or_expr()
        if self.peek()[0] != "end":
            raise ValueError(f"unexpected {self.peek()[1]!r}")
        return node

    def or_expr(self) -> Node:
        items = [self.and_expr()]
        while self.peek() == ("word", "or"):
            self.take()
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else AnyOf(items)

    def and_expr(self) -> Node:
        items = [self.term()]
        while self.peek() == ("word", "and"):
            self.take()
            items.append(self.term())
        return items[0] if len(items) == 1 else AllOf(items)

    def term(self) -> Node:
        kind, value = self.take()
        if (kind, value) == ("paren", "("):
            node = self.or_expr()
            if self.take() != ("paren", ")"):
                raise ValueError("missing ')'")
            return node
        if kind != "claim":
            raise ValueError(f"expected claims['...'], found {value!r}")
        op_kind, op = self.take()
        lit_kind, literal = self.take()
        if op_kind != "word" or lit_kind != "str":
            raise ValueError("expected an operator and a quoted value")
        if op == "eq":
            return Match(value, "equals", (literal,))
        if op == "matches":
            return Match(value, "glob", (literal,))
        raise ValueError(f"operator {op!r} is not modeled")


def parse_expression(text: str) -> Node:
    try:
        return _ExpressionParser(text).parse()
    except ValueError as exc:
        return Unknown(f"claims matching expression not modeled: {exc}")


def credential_condition(credential: dict) -> Node:
    expression = credential.get("claimsMatchingExpression")
    if expression:
        value = expression.get("value", "") if isinstance(expression, dict) else str(expression)
        return parse_expression(value)
    subject = credential.get("subject")
    if subject is None:
        return Unknown("credential has neither subject nor claimsMatchingExpression")
    return Match("sub", "equals", (subject,))


def load(section: dict, source: str) -> list[Trust]:
    trusts: list[Trust] = []
    for i, identity in enumerate(section.get("identities", [])):
        name = identity.get("name") or identity.get("id") or f"identity-{i}"
        level = privilege.azure_assignments(
            identity.get("role_assignments", []), identity.get("privilege")
        )
        kind = identity.get("kind", "app")
        for j, credential in enumerate(identity.get("federated_credentials", [])):
            audiences = credential.get("audiences") or credential.get("audience") or []
            if isinstance(audiences, str):
                audiences = [audiences]
            trusts.append(
                Trust(
                    id=f"azure:{name}#{credential.get('name', j)}",
                    cloud="azure",
                    identity=name,
                    issuer=normalize_issuer(credential.get("issuer", "")),
                    condition=credential_condition(credential),
                    audience=Match("aud", "equals", tuple(audiences)) if audiences else None,
                    privilege=level,
                    source=f"{source} azure.identities[{i}].federated_credentials[{j}]",
                    kind="federated credential on "
                    + ("managed identity" if kind == "managed_identity" else "app registration"),
                    raw=credential,
                )
            )
    return trusts
