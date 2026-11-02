"""Shared machinery for CI platform models.

A platform model knows the shape of the tokens one issuer mints and which
parts of a token each class of actor controls. Given the literals a trust
compares against, it builds candidate tokens: the token an outsider could
mint, the one any org member could mint, and so on. The analyzer evaluates
the trust against each; the broadest actor whose token passes is the reach.

Candidates are built from the trust's own literals, with wildcards filled by
attacker-chosen strings, so a pattern such as ``repo:acme*`` produces the
token of an organization called ``acmeattacker``. This is a witness search, not a
proof: a match is a concrete token that works, while "no match" means no
candidate TrustMint built works.
"""

from __future__ import annotations

import hashlib
import itertools
import re
from collections.abc import Iterable
from dataclasses import dataclass

from trustmint.conditions import Literal
from trustmint.context import Context
from trustmint.model import Candidate, Reach, Trust

PROBE = "tm-probe"


@dataclass(frozen=True)
class Seed:
    claim: str | None
    value: str
    exact: bool  # the value appears verbatim in the trust, no wildcard filled in


def regex_to_glob(pattern: str) -> str:
    text = pattern.strip("^$")
    text = re.sub(r"\.\*|\.\+|\[[^\]]*\][*+]?|\\[dws][*+]?", "*", text)
    text = re.sub(r"\\(.)", r"\1", text)
    text = re.sub(r"[()|?+]", "", text)
    return text


def instantiate(literal: Literal, fillers: list[str], limit: int = 2) -> list[Seed]:
    """Turn one literal into concrete strings an attacker could produce."""
    if literal.kind == "exact":
        return [Seed(literal.claim, literal.value, True)]
    pattern = {
        "prefix": literal.value + "*",
        "suffix": "*" + literal.value,
        "contains": "*" + literal.value + "*",
        "regex": regex_to_glob(literal.value),
    }.get(literal.kind, literal.value)
    pattern = pattern.replace("?", "x")
    pieces = pattern.split("*")
    holes = len(pieces) - 1
    if holes == 0:
        return [Seed(literal.claim, pattern, False)]
    if holes <= limit:
        combos: Iterable[tuple[str, ...]] = itertools.product(fillers, repeat=holes)
    else:
        combos = ((f,) * holes for f in fillers)
    seeds = []
    for combo in combos:
        text = pieces[0] + "".join(f + p for f, p in zip(combo, pieces[1:], strict=True))
        seeds.append(Seed(literal.claim, text, False))
    return seeds


_BAD_REF = re.compile(r"[:?*\[\\^~\s]|\.\.|@\{|^/|/$|\.lock$")


def valid_git_ref(name: str) -> bool:
    """git check-ref-format rules, roughly: branch and tag names cannot contain ':' etc."""
    return bool(name) and not _BAD_REF.search(name)


def stable_id(*parts: str) -> str:
    digest = hashlib.sha1("/".join(parts).encode()).hexdigest()
    return str(100000 + int(digest[:7], 16) % 89999999)


class Platform:
    name = "generic"
    label = "an unrecognized issuer"
    controls_audience = True
    fillers: list[str] = ["", "attacker", "-attacker"]

    def __init__(self, issuer: str, scope: str, context: Context) -> None:
        self.issuer = issuer
        self.scope = scope
        self.context = context

    def seeds(self, literals: Iterable[Literal]) -> list[Seed]:
        out: list[Seed] = []
        seen: set[tuple[str | None, str, bool]] = set()
        for literal in literals:
            for seed in instantiate(literal, self.fillers):
                key = (seed.claim, seed.value, seed.exact)
                if key not in seen:
                    seen.add(key)
                    out.append(seed)
        return out

    def candidates(self, trust: Trust, literals: list[Literal]) -> list[Candidate]:
        return []

    def recycled(self, trust: Trust, witness: Candidate) -> Candidate | None:
        """The same token minted after the names in it are reused by someone else."""
        return None

    def remediation(self, trust: Trust, reach: Reach) -> str:
        return "Restrict the trust to the exact subject of the pipeline that needs it."

    def cap(self, reach: Reach) -> Reach:
        """Dedicated issuers (one per org or cluster) cannot be reached by outsiders."""
        if self.scope != "public" and reach == Reach.PUBLIC:
            return Reach.TENANT
        return reach

    def audience_options(self, literals: list[Literal]) -> list[str | None]:
        """Audiences the token holder may request; None means use the platform default."""
        options: list[str | None] = []
        for literal in literals:
            if literal.claim == "aud":
                for seed in instantiate(literal, ["", "attacker"]):
                    if seed.value not in options:
                        options.append(seed.value)
        return options or [None]


def owned_or_inferred(declared: set[str], inferred: set[str]) -> tuple[set[str], bool]:
    """Declared context wins; otherwise fall back to what the trust itself names."""
    if declared:
        return declared, True
    return inferred, False
