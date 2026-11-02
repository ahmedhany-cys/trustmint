"""Map an issuer URL to the model of the CI platform behind it."""

from __future__ import annotations

import re

from trustmint.context import Context
from trustmint.platforms.base import Platform
from trustmint.platforms.circleci import CircleCI
from trustmint.platforms.github import GitHubActions
from trustmint.platforms.gitlab import GitLabCI
from trustmint.platforms.kubernetes import Kubernetes
from trustmint.platforms.terraform import HcpTerraform

GITHUB = "https://token.actions.githubusercontent.com"

_BY_NAME = {
    "github": GitHubActions,
    "gitlab": GitLabCI,
    "terraform": HcpTerraform,
    "circleci": CircleCI,
    "kubernetes": Kubernetes,
}


def resolve(issuer: str, context: Context) -> Platform:
    declared = context.issuers.get(issuer)
    if declared:
        cls = _BY_NAME.get(declared.get("platform", ""), Platform)
        scope = declared.get("scope", "tenant")
        if cls is GitHubActions:
            return GitHubActions(issuer, scope, context, immutable_supported=False)
        return cls(issuer, scope, context)
    if issuer == GITHUB:
        return GitHubActions(issuer, "public", context)
    if issuer.startswith(GITHUB + "/"):
        # Enterprise-specific issuer: only that enterprise's repositories get tokens.
        return GitHubActions(issuer, "tenant", context)
    if issuer == "https://gitlab.com":
        return GitLabCI(issuer, "public", context)
    if issuer == "https://app.terraform.io":
        return HcpTerraform(issuer, "public", context)
    if re.match(r"^https://oidc\.circleci\.com/org/[^/]+$", issuer):
        return CircleCI(issuer, "tenant", context)
    if re.match(
        r"^https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Za-z0-9]+$", issuer
    ) or re.match(r"^https://container\.googleapis\.com/v1/projects/.+/clusters/.+$", issuer):
        return Kubernetes(issuer, "tenant", context)
    return Platform(issuer, "unknown", context)


__all__ = ["Platform", "resolve"]
