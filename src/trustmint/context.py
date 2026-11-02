"""What the user tells TrustMint about their own estate.

All fields are optional. Without them TrustMint infers owners, repositories
and protected refs from the literal values in each trust, and every finding
says which facts were inferred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Context:
    # GitHub owners, GitLab top-level groups, HCP Terraform organizations.
    owners: set[str] = field(default_factory=set)
    # "owner/repo", "group/sub/project", "org/workspace", "namespace/serviceaccount",
    # or a CircleCI project id.
    repos: set[str] = field(default_factory=set)
    # repo -> names of protected branches, tags or environments in it.
    protected_refs: dict[str, set[str]] = field(default_factory=dict)
    # issuer URL -> {"platform": "github|gitlab|terraform|circleci|kubernetes", "scope":
    # "public|tenant"} for self-hosted issuers TrustMint cannot recognize by host.
    issuers: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Context:
        data = data or {}
        return cls(
            owners=set(data.get("owners", [])),
            repos=set(data.get("repos", [])),
            protected_refs={k: set(v) for k, v in data.get("protected_refs", {}).items()},
            issuers={normalize_issuer(k): v for k, v in data.get("issuers", {}).items()},
        )

    def merge(self, other: Context) -> Context:
        protected = {k: set(v) for k, v in self.protected_refs.items()}
        for key, names in other.protected_refs.items():
            protected.setdefault(key, set()).update(names)
        return Context(
            owners=self.owners | other.owners,
            repos=self.repos | other.repos,
            protected_refs=protected,
            issuers={**self.issuers, **other.issuers},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "owners": sorted(self.owners),
            "repos": sorted(self.repos),
            "protected_refs": {k: sorted(v) for k, v in sorted(self.protected_refs.items())},
            "issuers": self.issuers,
        }


def normalize_issuer(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value.startswith(("https://", "http://")):
        value = "https://" + value
    return value
