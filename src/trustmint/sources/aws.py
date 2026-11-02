"""AWS IAM role trust policies that allow sts:AssumeRoleWithWebIdentity."""

from __future__ import annotations

from typing import Any

from trustmint import privilege
from trustmint.conditions import AllOf, Always, Match, Node, Not, Unknown
from trustmint.context import normalize_issuer
from trustmint.model import Trust

WEB_IDENTITY = {"sts:assumerolewithwebidentity", "sts:*", "*"}
STRING_OPS = {
    "StringEquals": ("equals", False, False),
    "StringNotEquals": ("equals", False, True),
    "StringEqualsIgnoreCase": ("equals", True, False),
    "StringNotEqualsIgnoreCase": ("equals", True, True),
    "StringLike": ("glob", False, False),
    "StringNotLike": ("glob", False, True),
}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def issuer_for_principal(principal: str) -> str:
    """arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com -> https://..."""
    if ":oidc-provider/" in principal:
        return normalize_issuer(principal.split(":oidc-provider/", 1)[1])
    return normalize_issuer(principal)


def claim_for_key(key: str, issuer_key: str) -> str | None:
    lowered = key.lower()
    if lowered.startswith(issuer_key.lower() + ":"):
        return key[len(issuer_key) + 1 :]
    if lowered.startswith(("aws:", "sts:", "iam:")):
        return None
    # A key for some other identity provider: never present in this issuer's tokens.
    return f"<other issuer> {key}"


def condition_tree(block: dict | None, issuer_key: str) -> Node:
    children: list[Node] = []
    for raw_op, pairs in (block or {}).items():
        op, set_mode = raw_op, None
        if op.startswith("ForAnyValue:"):
            op, set_mode = op[len("ForAnyValue:") :], "any"
        elif op.startswith("ForAllValues:"):
            op, set_mode = op[len("ForAllValues:") :], "all"
        if_exists = op.endswith("IfExists")
        if if_exists:
            op = op[: -len("IfExists")]
        for key, values in (pairs or {}).items():
            values = [str(v) for v in _as_list(values)]
            claim = claim_for_key(key, issuer_key)
            if claim is None:
                children.append(Unknown(f"condition key {key} is not a token claim"))
                continue
            if any("${" in v for v in values):
                children.append(Unknown(f"policy variable in {raw_op} {key}"))
                continue
            if op in STRING_OPS:
                kind, ignore_case, negate = STRING_OPS[op]
                node: Node = Match(claim, kind, tuple(values), ignore_case, if_exists, set_mode)
                children.append(Not(node) if negate else node)
            elif op == "Null":
                present = Match(claim, "present")
                wants_absent = values and values[0].lower() == "true"
                children.append(Not(present) if wants_absent else present)
            else:
                children.append(Unknown(f"operator {raw_op} is not modeled"))
    return AllOf(children)


def _statements(document: Any) -> list[dict]:
    statements = privilege.load_policy(document).get("Statement", [])
    return [statements] if isinstance(statements, dict) else list(statements)


def _web_identity(statement: dict) -> bool:
    actions = {a.lower() for a in _as_list(statement.get("Action"))}
    return bool(actions & WEB_IDENTITY)


def _federated(statement: dict) -> list[str]:
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        return [str(p) for p in _as_list(principal.get("Federated"))]
    return []


def role_trusts(role: dict, providers: list[dict], source: str) -> list[Trust]:
    arn = role.get("Arn") or role.get("RoleName", "unknown-role")
    statements = _statements(role.get("AssumeRolePolicyDocument"))
    level = privilege.aws_role(role)
    denies = [s for s in statements if s.get("Effect") == "Deny" and _web_identity(s)]
    trusts: list[Trust] = []
    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow" or not _web_identity(statement):
            continue
        for principal in _federated(statement):
            if principal == "*":
                issuer, condition = "*", Unknown('Principal "*" with web identity')
            else:
                issuer = issuer_for_principal(principal)
                issuer_key = issuer.removeprefix("https://")
                parts: list[Node] = [condition_tree(statement.get("Condition"), issuer_key)]
                for deny in denies:
                    deny_principals = _federated(deny)
                    if "*" in deny_principals or principal in deny_principals:
                        if deny.get("Condition"):
                            parts.append(Not(condition_tree(deny["Condition"], issuer_key)))
                        else:
                            parts.append(Always(False, "an unconditional Deny"))
                condition = AllOf(parts)
            audience = None
            provider = _provider(providers, principal, issuer)
            notes = []
            if provider and provider.get("ClientIDList"):
                audience = Match("aud", "equals", tuple(provider["ClientIDList"]))
            elif principal != "*" and ":oidc-provider/" in principal and not provider:
                notes.append("OIDC provider not in snapshot; its client ID list was not checked")
            trusts.append(
                Trust(
                    id=f"aws:{arn}#{index}:{issuer.removeprefix('https://')}",
                    cloud="aws",
                    identity=arn,
                    issuer=issuer,
                    condition=condition,
                    audience=audience,
                    privilege=level,
                    source=f"{source} Statement[{index}]",
                    kind="IAM role trust policy",
                    raw=statement,
                    notes=notes,
                )
            )
    return trusts


def _provider(providers: list[dict], principal: str, issuer: str) -> dict | None:
    for provider in providers:
        if provider.get("Arn") == principal:
            return provider
    for provider in providers:
        if provider.get("Url") and normalize_issuer(provider["Url"]) == issuer:
            return provider
    return None


def load(section: dict, source: str) -> list[Trust]:
    providers = section.get("oidc_providers", [])
    trusts: list[Trust] = []
    for i, role in enumerate(section.get("roles", [])):
        trusts.extend(role_trusts(role, providers, f"{source} aws.roles[{i}]"))
    return trusts
