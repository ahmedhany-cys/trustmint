"""CircleCI OIDC tokens (V1 format).

    iss = https://oidc.circleci.com/org/ORG_ID      one issuer per organization
    sub = org/ORG_ID/project/PROJECT_ID/user/USER_ID
    aud = ORG_ID                                    fixed, not chosen by the job

Because the issuer is per organization, outsiders cannot mint a matching
token: the broadest reach is any project in the organization. The V1 subject
has no branch, so restricting by branch needs the ``oidc.circleci.com/vcs-ref``
claim, which AWS trust policies cannot read.
"""

from __future__ import annotations

import re

from trustmint.conditions import Literal
from trustmint.model import Candidate, Reach, Trust
from trustmint.platforms.base import PROBE, Platform

UUID = r"[0-9a-fA-F-]{8,}"
SUB = re.compile(r"^org/(?P<org>[^/]+)/project/(?P<project>[^/]+)/user/(?P<user>[^/]+)$")
EXACT_PROJECT = re.compile(rf"/project/({UUID})/")
PROBE_PROJECT = "00000000-0000-4000-8000-00000000c1c1"
PROBE_USER = "00000000-0000-4000-8000-0000000000aa"


class CircleCI(Platform):
    name = "circleci"
    label = "CircleCI"
    controls_audience = False
    fillers = [
        "",
        "attacker",
        f"{PROBE_PROJECT}/user/{PROBE_USER}",
        PROBE_USER,
        f"attacker/user/{PROBE_USER}",
    ]

    def __init__(self, issuer, scope, context) -> None:
        super().__init__(issuer, "tenant", context)
        self.org_id = issuer.rstrip("/").rsplit("/", 1)[-1]

    def candidates(self, trust: Trust, literals: list[Literal]) -> list[Candidate]:
        projects: set[str] = set()
        refs: set[str] = set()
        contexts: set[str] = set()
        for lit in literals:
            if lit.claim in (None, "sub"):
                projects.update(EXACT_PROJECT.findall(lit.value + "/"))
            if lit.claim == "oidc.circleci.com/project-id" and lit.kind == "exact":
                projects.add(lit.value)
            if lit.claim == "oidc.circleci.com/vcs-ref" and lit.kind == "exact":
                refs.add(lit.value)
            if lit.claim == "oidc.circleci.com/context-ids" and lit.kind == "exact":
                contexts.add(lit.value)
        known = {r for r in self.context.repos if re.fullmatch(UUID, r)} | projects
        users = {PROBE_USER}
        for seed in self.seeds(literals):
            match = SUB.match(seed.value) if seed.claim in (None, "sub") else None
            if match:
                users.add(match["user"])
        out = []
        for project in sorted(known | {PROBE_PROJECT}):
            for ref in sorted(refs | {"refs/heads/main", f"refs/heads/{PROBE}-branch"}):
                for ctx_ids in [[], *[[c] for c in sorted(contexts)]]:
                    for user in sorted(users):
                        claims = {
                            "iss": self.issuer,
                            "aud": self.org_id,
                            "sub": f"org/{self.org_id}/project/{project}/user/{user}",
                            "oidc.circleci.com/project-id": project,
                            "oidc.circleci.com/vcs-ref": ref,
                            "oidc.circleci.com/context-ids": ctx_ids,
                        }
                        assumptions = []
                        if project not in known:
                            reach = Reach.TENANT
                            actor = "any member of the CircleCI organization, from another project"
                        elif ctx_ids:
                            reach = Reach.PROTECTED
                            actor = f"jobs allowed to use the context `{ctx_ids[0]}`"
                            assumptions.append(
                                "Assumes the context is restricted to a security group"
                            )
                        elif ref in refs:
                            reach = Reach.PROTECTED
                            actor = f"pipelines on `{ref}` of project `{project}`"
                            assumptions.append(f"Assumes `{ref}` is a protected branch")
                        else:
                            reach = Reach.PROJECT
                            actor = (
                                f"anyone who can trigger a pipeline in project `{project}`, "
                                "from any branch"
                            )
                        out.append(Candidate(claims, reach, actor, assumptions))
        return out

    def remediation(self, trust: Trust, reach: Reach) -> str:
        return (
            "Match the subject prefix `org/ORG_ID/project/PROJECT_ID/` and, where the cloud can "
            "read custom claims, `oidc.circleci.com/vcs-ref` or a restricted context id."
        )
