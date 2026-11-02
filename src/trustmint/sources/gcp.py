"""Google Cloud workload identity pool providers and the IAM bindings that use them.

A token reaches a Google identity in three steps, all modeled here:

1. the provider maps token claims to ``google.subject`` and ``attribute.*``
   with CEL (``attributeMapping``); a missing ``google.subject`` rejects it;
2. the provider's ``attributeCondition`` (CEL) must be true;
3. an IAM binding names the federated principal: one subject, every identity
   with an attribute value, or the whole pool (``principalSet://.../*``).

Inputs are ``gcloud iam workload-identity-pools providers describe
--format=json`` objects and ``gcloud iam service-accounts get-iam-policy
--format=json`` policies.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from trustmint import cel, privilege
from trustmint.conditions import Claims, Literal, Match, Node, Tri, Unknown
from trustmint.context import normalize_issuer
from trustmint.model import Trust

IMPERSONATION_ROLES = {
    "roles/iam.workloadIdentityUser",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountOpenIdTokenCreator",
}
MEMBER = re.compile(
    r"^(?P<type>principal|principalSet)://iam\.googleapis\.com/projects/(?P<project>[^/]+)"
    r"/locations/global/workloadIdentityPools/(?P<pool>[^/]+)/(?P<rest>.+)$"
)
PROVIDER = re.compile(
    r"projects/(?P<project>[^/]+)/locations/global/workloadIdentityPools/(?P<pool>[^/]+)"
    r"/providers/(?P<provider>[^/]+)"
)


class GcpFederation(Node):
    """Provider mapping, provider condition and binding filter evaluated together."""

    def __init__(self, mapping: dict[str, str], condition: str | None, member: dict) -> None:
        self.mapping_source = mapping
        self.condition_source = condition
        self.member = member
        self.problem: str | None = None
        self.mapping: dict[str, Any] = {}
        self.condition = None
        try:
            self.mapping = {key: cel.parse(expr) for key, expr in mapping.items()}
            if condition:
                self.condition = cel.parse(condition)
        except cel.CelUnsupported as exc:
            self.problem = f"CEL not modeled: {exc}"

    def evaluate(self, claims: Claims) -> Tri:
        if self.problem:
            return None
        assertion = dict(claims)
        attributes: dict[str, Any] = {}
        google: dict[str, Any] = {}
        for key, expr in self.mapping.items():
            try:
                value = cel.evaluate(expr, {"assertion": assertion})
            except cel.CelError:
                continue
            except cel.CelUnsupported:
                return None
            scope, _, name = key.partition(".")
            (google if scope == "google" else attributes)[name] = value
        if "subject" not in google:
            return False
        if self.condition is not None:
            env = {"assertion": assertion, "attribute": attributes, "google": google}
            try:
                result = cel.evaluate(self.condition, env)
            except cel.CelError:
                return False
            except cel.CelUnsupported:
                return None
            if result is not True:
                return False
        kind = self.member["kind"]
        if kind == "subject":
            return str(google.get("subject")) == self.member["value"]
        if kind == "attribute":
            return str(attributes.get(self.member["name"], "\0")) == self.member["value"]
        if kind == "group":
            return None
        return True

    def _claim_for(self, node: Any) -> str | None:
        ref = cel.reference(node)
        if not ref:
            return None
        scope, name = ref
        if scope == "assertion":
            return name
        key = f"google.{name}" if scope == "google" else f"attribute.{name}"
        target = cel.reference(self.mapping.get(key))
        return target[1] if target and target[0] == "assertion" else None

    def literals(self) -> Iterator[Literal]:
        nodes = list(cel.walk(self.condition)) if self.condition is not None else []
        claimed: set[int] = set()
        for node in nodes:
            if isinstance(node, cel.Binary) and node.op in ("==", "!="):
                for side, other in ((node.left, node.right), (node.right, node.left)):
                    if isinstance(other, cel.Lit) and isinstance(other.value, str):
                        claimed.add(id(other))
                        yield Literal(self._claim_for(side), other.value, "exact")
            elif (
                isinstance(node, cel.Binary)
                and node.op == "in"
                and isinstance(node.right, cel.ListExpr)
            ):
                for item in node.right.items:
                    if isinstance(item, cel.Lit) and isinstance(item.value, str):
                        claimed.add(id(item))
                        yield Literal(self._claim_for(node.left), item.value, "exact")
            elif isinstance(node, cel.Call) and node.target is not None and node.args:
                kind = {
                    "startsWith": "prefix",
                    "endsWith": "suffix",
                    "contains": "contains",
                    "matches": "regex",
                }.get(node.name)
                arg = node.args[0]
                if kind and isinstance(arg, cel.Lit) and isinstance(arg.value, str):
                    claimed.add(id(arg))
                    yield Literal(self._claim_for(node.target), arg.value, kind)
        for node in nodes:
            if (
                isinstance(node, cel.Lit)
                and isinstance(node.value, str)
                and id(node) not in claimed
            ):
                yield Literal(None, node.value, "exact")
        if self.member["kind"] in ("subject", "attribute"):
            key = (
                "google.subject"
                if self.member["kind"] == "subject"
                else f"attribute.{self.member['name']}"
            )
            target = cel.reference(self.mapping.get(key))
            claim = target[1] if target and target[0] == "assertion" else None
            yield Literal(claim, self.member["value"], "exact")

    def describe(self) -> str:
        parts = [f"mapping {self.mapping_source}"]
        if self.condition_source:
            parts.append(f"condition `{self.condition_source}`")
        else:
            parts.append("no attribute condition")
        member = self.member
        if member["kind"] == "all":
            parts.append("binding: every identity in the pool")
        elif member["kind"] == "attribute":
            parts.append(f"binding: attribute.{member['name']} == {member['value']!r}")
        else:
            parts.append(f"binding: {member['kind']} {member.get('value')!r}")
        return "; ".join(parts)

    def unknown_reasons(self) -> Iterator[str]:
        if self.problem:
            yield self.problem
        if self.member["kind"] == "group":
            yield "google.groups bindings are not modeled"


def parse_member(member: str) -> dict | None:
    match = MEMBER.match(member)
    if not match:
        return None
    rest = match["rest"]
    info = {"project": match["project"], "pool": match["pool"]}
    if match["type"] == "principal" and rest.startswith("subject/"):
        return {**info, "kind": "subject", "value": rest[len("subject/") :]}
    if rest == "*":
        return {**info, "kind": "all"}
    if rest.startswith("attribute."):
        name, _, value = rest[len("attribute.") :].partition("/")
        return {**info, "kind": "attribute", "name": name, "value": value}
    if rest.startswith("group/"):
        return {**info, "kind": "group", "value": rest[len("group/") :]}
    return {**info, "kind": "unknown", "value": rest}


def _providers_for(providers: list[dict], member: dict) -> list[dict]:
    out = []
    for provider in providers:
        match = PROVIDER.search(provider.get("name", ""))
        if not match or match["pool"] != member["pool"]:
            continue
        if (
            "-" not in (match["project"], member["project"])
            and match["project"] != member["project"]
        ):
            continue
        out.append(provider)
    return out


def _trusts_for_policy(
    identity: str,
    policy: dict,
    providers: list[dict],
    roles_filter: set[str] | None,
    level,
    source: str,
    kind: str,
) -> list[Trust]:
    trusts = []
    for b_index, binding in enumerate(policy.get("bindings", [])):
        role = binding.get("role", "")
        if roles_filter is not None and role not in roles_filter:
            continue
        for member_text in binding.get("members", []):
            member = parse_member(member_text)
            if not member:
                continue
            for provider in _providers_for(providers, member):
                if provider.get("disabled") or provider.get("state") == "DELETED":
                    continue
                oidc = provider.get("oidc")
                if not oidc:
                    continue
                name = provider["name"]
                condition: Node = GcpFederation(
                    provider.get("attributeMapping", {}), provider.get("attributeCondition"), member
                )
                if member["kind"] == "unknown":
                    condition = Unknown(f"member form not modeled: {member_text}")
                if binding.get("condition"):
                    condition = Unknown("IAM condition on the binding is not modeled")
                audiences = oidc.get("allowedAudiences") or [
                    f"https://iam.googleapis.com/{name}",
                    f"//iam.googleapis.com/{name}",
                ]
                binding_level = level if level is not None else privilege.gcp_roles([role])
                trusts.append(
                    Trust(
                        id=f"gcp:{identity}#{b_index}:{name.rsplit('/', 1)[-1]}:"
                        + "/".join(member_text.rsplit("/", 2)[-2:]),
                        cloud="gcp",
                        identity=identity,
                        issuer=normalize_issuer(oidc.get("issuerUri", "")),
                        condition=condition,
                        audience=Match("aud", "equals", tuple(audiences)),
                        privilege=binding_level,
                        source=f"{source} bindings[{b_index}] via {name}",
                        kind=kind,
                        raw={"member": member_text, "role": role, "provider": name},
                    )
                )
    return trusts


def load(section: dict, source: str) -> list[Trust]:
    providers = section.get("providers", [])
    trusts: list[Trust] = []
    for i, account in enumerate(section.get("service_accounts", [])):
        level = privilege.gcp_roles(account.get("roles", []), account.get("privilege"))
        trusts += _trusts_for_policy(
            account.get("email", f"service-account-{i}"),
            account.get("iam_policy", {}),
            providers,
            IMPERSONATION_ROLES,
            level,
            f"{source} gcp.service_accounts[{i}]",
            "service account impersonation",
        )
    for i, resource in enumerate(section.get("resource_policies", [])):
        trusts += _trusts_for_policy(
            resource.get("resource", f"resource-{i}"),
            resource.get("iam_policy", {}),
            providers,
            None,
            None,
            f"{source} gcp.resource_policies[{i}]",
            "direct resource access",
        )
    return trusts
