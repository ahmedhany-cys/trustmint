"""Core data types shared by sources, platforms, the analyzer and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from trustmint.conditions import Node


class Reach(IntEnum):
    """Who can mint a token that satisfies a trust, broadest last.

    NONE        no token TrustMint could build satisfies it (likely a dead trust)
    PROTECTED   only pipelines on protected refs, environments, apply runs or a
                specific service account
    PROJECT     anyone who can run a pipeline in the trusted repository or
                project on an unprotected ref (push a branch, open a PR, plan)
    TENANT      any member of the owning organization, group, workspace org or
                cluster, from a repository or project the trust never named
    PUBLIC      anyone who can sign up to the CI platform
    """

    NONE = 0
    PROTECTED = 1
    PROJECT = 2
    TENANT = 3
    PUBLIC = 4


class Privilege(IntEnum):
    UNKNOWN = 0
    READ = 1
    WRITE = 2
    ADMIN = 3


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class PrivilegeAssessment:
    level: Privilege = Privilege.UNKNOWN
    evidence: list[str] = field(default_factory=list)


@dataclass
class Trust:
    """One way an external OIDC token can become a cloud identity."""

    id: str
    cloud: str  # aws | gcp | azure
    identity: str  # role ARN, service account email, app/managed identity name
    issuer: str  # normalized: https://host/path, no trailing slash
    condition: Node
    audience: Node | None = None
    privilege: PrivilegeAssessment = field(default_factory=PrivilegeAssessment)
    source: str = ""  # where it came from: file and JSON path or Terraform address
    kind: str = ""  # e.g. "iam-role trust statement 0", "gcp sa binding"
    raw: Any = None
    notes: list[str] = field(default_factory=list)


@dataclass
class Candidate:
    """A token some class of actor could obtain from the CI platform."""

    claims: dict[str, Any]
    reach: Reach
    actor: str  # plain-language description of who can mint it
    assumptions: list[str] = field(default_factory=list)
    preferred: bool = True  # tie-breaker: prefer realistic formats in reports


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    trust_id: str | None
    cloud: str | None
    identity: str | None
    issuer: str | None
    platform: str | None
    reach: str | None
    privilege: str | None
    message: str
    remediation: str
    witness: dict[str, Any] | None = None
    actor: str | None = None
    assumptions: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class TrustResult:
    trust: Trust
    platform: str
    reach: Reach | None  # None: undecidable
    witness: Candidate | None
    candidates_tried: int
    undecided: int
    findings: list[Finding] = field(default_factory=list)
    used_by: list[str] = field(default_factory=list)
