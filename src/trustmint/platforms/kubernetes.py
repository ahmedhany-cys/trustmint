"""Kubernetes service account tokens (EKS IRSA and other cluster issuers).

    sub = system:serviceaccount:NAMESPACE:NAME

Each cluster has its own issuer, so only principals inside that cluster can
mint a token. Anyone allowed to create a service account (or a pod using one)
in a namespace controls the NAME part; anyone allowed to create namespaces
controls both. The audience is chosen in the projected volume, so it is not a
boundary either.
"""

from __future__ import annotations

import re

from trustmint.conditions import Literal
from trustmint.model import Candidate, Reach, Trust
from trustmint.platforms.base import PROBE, Platform

SUB = re.compile(r"^system:serviceaccount:(?P<ns>[^:]+):(?P<sa>[^:]+)$")
EXACT_NS = re.compile(r"^system:serviceaccount:([^:*?]+):")
EXACT_SA = re.compile(r"^system:serviceaccount:([^:*?]+):([^:*?]+)$")


class Kubernetes(Platform):
    name = "kubernetes"
    label = "Kubernetes"
    fillers = ["", "attacker", "-attacker", ":attacker", "attacker:attacker"]

    def __init__(self, issuer, scope, context) -> None:
        super().__init__(issuer, "tenant", context)

    def candidates(self, trust: Trust, literals: list[Literal]) -> list[Candidate]:
        namespaces: set[str] = set()
        accounts: set[tuple[str, str]] = set()
        for lit in literals:
            if lit.claim in (None, "sub"):
                namespaces.update(EXACT_NS.findall(lit.value))
                if lit.kind == "exact":
                    accounts.update(EXACT_SA.findall(lit.value))
        for repo in self.context.repos:
            if repo.startswith("k8s:") and repo.count("/") == 1:
                ns, sa = repo[4:].split("/")
                namespaces.add(ns)
                accounts.add((ns, sa))
        pairs = {(f"{PROBE}-ns", f"{PROBE}-sa")} | accounts
        pairs |= {(ns, f"{PROBE}-sa") for ns in namespaces}
        for seed in self.seeds(literals):
            match = SUB.match(seed.value) if seed.claim in (None, "sub") else None
            if match:
                pairs.add((match["ns"], match["sa"]))
        out = []
        for ns, sa in sorted(pairs):
            claims = {"iss": self.issuer, "sub": f"system:serviceaccount:{ns}:{sa}"}
            if ns not in namespaces:
                reach = Reach.TENANT
                actor = (
                    f"anyone in the cluster who can create a service account in namespace `{ns}`"
                )
            elif (ns, sa) not in accounts:
                reach = Reach.PROJECT
                actor = (
                    f"anyone who can create a service account or pod in namespace `{ns}` "
                    f"(here `{sa}`)"
                )
            else:
                reach = Reach.PROTECTED
                actor = f"pods running as `{ns}/{sa}`"
            out.append(Candidate(claims, reach, actor, []))
        return out

    def remediation(self, trust: Trust, reach: Reach) -> str:
        return (
            "Use StringEquals on `<issuer>:sub` with the exact "
            "`system:serviceaccount:NAMESPACE:NAME`, and `<issuer>:aud` = `sts.amazonaws.com`."
        )
