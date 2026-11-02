"""GitHub Actions OIDC tokens.

Subject formats (default template):

    repo:OWNER/REPO:ref:refs/heads/BRANCH          name-based ("legacy")
    repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:...       immutable, since 2026
    ...:ref:refs/tags/TAG | :environment:ENV | :pull_request

GitHub.com issues immutable subjects automatically for repositories created,
renamed or transferred from 15 July 2026; older repositories keep name-based
subjects until they opt in. GitHub Enterprise Server has no immutable
subjects. The ``repository`` claim stays name-based in both formats.

Who controls what: any GitHub user controls the owner and repository of
tokens from their own repositories; any org member who can create or push to
a repository controls the repository part; anyone who can push a branch
controls the ref. The job chooses the audience, so audience checks are not a
security boundary.
"""

from __future__ import annotations

import re

from trustmint.conditions import Literal
from trustmint.model import Candidate, Reach, Trust
from trustmint.platforms.base import (
    PROBE,
    Platform,
    Seed,
    owned_or_inferred,
    stable_id,
    valid_git_ref,
)

NAME = r"[A-Za-z0-9_.-]+"
SUB = re.compile(
    rf"^repo:(?P<owner>{NAME})(?:@(?P<oid>\d+))?/(?P<repo>{NAME})(?:@(?P<rid>\d+))?:(?P<ctx>.+)$"
)
CONTEXT = re.compile(
    r"^(?:ref:refs/heads/(?P<branch>.+)|ref:refs/tags/(?P<tag>.+)"
    r"|environment:(?P<env>.+)|(?P<pr>pull_request))$"
)
EXACT_OWNER = re.compile(rf"repo:({NAME})(?:@(\d+))?[/@]")
EXACT_REPO = re.compile(rf"repo:({NAME})(?:@\d+)?/({NAME})(?:@(\d+))?:")
EXACT_REF = re.compile(r":(?:ref:refs/(heads|tags)/|(environment):)([^*?]+)$")
WORKFLOW_REF = re.compile(rf"^({NAME})/({NAME})/(.+)@(refs/.+)$")

FRESH_OWNER = f"{PROBE}-owner"
FRESH_REPO = f"{PROBE}-repo"
FRESH_BRANCH = f"{PROBE}-branch"

LEGACY_NOTE = (
    "Needs a repository that still emits name-based subjects (created before 2026-07-15 "
    "and never renamed or transferred). New repositories get immutable subjects, which "
    "narrows this path but does not close it: plenty of such repositories already exist."
)


class GitHubActions(Platform):
    name = "github"
    label = "GitHub Actions"
    fillers = [
        "",
        "attacker",
        "-attacker",
        "/attacker",
        "attacker/attacker",
        "attacker:ref:refs/heads/attacker",
        "attacker/attacker:ref:refs/heads/attacker",
        ":ref:refs/heads/attacker",
        "ref:refs/heads/attacker",
        "heads/attacker",
        "attacker:pull_request",
        "pull_request",
        "environment:attacker",
    ]

    def __init__(self, issuer, scope, context, immutable_supported: bool = True) -> None:
        super().__init__(issuer, scope, context)
        self.immutable_supported = immutable_supported

    # -- reading the trust ----------------------------------------------------

    def _infer(self, literals: list[Literal]) -> dict:
        owners: set[str] = set()
        repos: set[tuple[str, str]] = set()
        refs: set[str] = set()
        owner_ids: dict[str, str] = {}
        repo_ids: dict[tuple[str, str], str] = {}
        workflow_refs: set[str] = set()
        for lit in literals:
            value = lit.value
            if lit.claim in (None, "sub"):
                for owner, oid in EXACT_OWNER.findall(value):
                    owners.add(owner)
                    if oid:
                        owner_ids[owner] = oid
                for owner, repo, rid in EXACT_REPO.findall(value):
                    repos.add((owner, repo))
                    if rid:
                        repo_ids[(owner, repo)] = rid
                match = EXACT_REF.search(value)
                if match:
                    refs.add(match.group(3))
            if lit.claim in ("repository", "repository_owner", None) and "*" not in value:
                if lit.claim == "repository_owner":
                    owners.add(value)
                elif re.fullmatch(rf"{NAME}/{NAME}", value):
                    owner, repo = value.split("/")
                    owners.add(owner)
                    repos.add((owner, repo))
            if lit.claim == "repository" and lit.kind in ("glob", "prefix"):
                head = re.match(rf"^({NAME})/", value)
                if head:
                    owners.add(head.group(1))
            if lit.claim in ("job_workflow_ref", "workflow_ref") and lit.kind == "exact":
                match = WORKFLOW_REF.match(value)
                if match:
                    owners.add(match.group(1))
                    if lit.claim == "workflow_ref":
                        repos.add((match.group(1), match.group(2)))
                    else:
                        workflow_refs.add(value)
            if lit.claim in ("ref", "environment") and lit.kind == "exact":
                refs.add(re.sub(r"^refs/(heads|tags)/", "", value))
        return {
            "owners": owners,
            "repos": repos,
            "refs": refs,
            "owner_ids": owner_ids,
            "repo_ids": repo_ids,
            "workflow_refs": workflow_refs,
        }

    def _gather(self, seeds: list[Seed]) -> dict:
        owners: dict[str, str | None] = {}
        repos: dict[str, str | None] = {}
        contexts: set[tuple[str, str]] = set()
        events: set[str] = set()
        job_refs: set[str] = set()
        for seed in seeds:
            value = seed.value
            if seed.claim in (None, "sub"):
                match = SUB.match(value)
                if match:
                    owners.setdefault(match["owner"], match["oid"])
                    repos.setdefault(match["repo"], match["rid"])
                    ctx = CONTEXT.match(match["ctx"])
                    if ctx:
                        if ctx["branch"]:
                            contexts.add(("branch", ctx["branch"]))
                        elif ctx["tag"]:
                            contexts.add(("tag", ctx["tag"]))
                        elif ctx["env"]:
                            contexts.add(("environment", ctx["env"]))
                        else:
                            contexts.add(("pull_request", ""))
            if seed.claim in (None, "repository") and re.fullmatch(rf"{NAME}/{NAME}", value):
                owner, repo = value.split("/")
                owners.setdefault(owner, None)
                repos.setdefault(repo, None)
            if seed.claim == "repository_owner" and re.fullmatch(NAME, value):
                owners.setdefault(value, None)
            if seed.claim == "ref":
                if value.startswith("refs/heads/"):
                    contexts.add(("branch", value[len("refs/heads/") :]))
                elif value.startswith("refs/tags/"):
                    contexts.add(("tag", value[len("refs/tags/") :]))
            if seed.claim == "environment" and value:
                contexts.add(("environment", value))
            if seed.claim == "event_name" and value:
                events.add(value)
            if seed.claim == "job_workflow_ref" and WORKFLOW_REF.match(value):
                job_refs.add(value)
        return {
            "owners": owners,
            "repos": repos,
            "contexts": contexts,
            "events": events,
            "job_refs": job_refs,
        }

    # -- building tokens ---------------------------------------------------------

    def token(
        self,
        owner: str,
        owner_id: str,
        repo: str,
        repo_id: str,
        kind: str,
        value: str,
        fmt: str,
        event: str,
        job_workflow_ref: str | None = None,
        env_branch: str = "main",
    ) -> dict:
        if fmt == "immutable":
            head = f"repo:{owner}@{owner_id}/{repo}@{repo_id}"
        else:
            head = f"repo:{owner}/{repo}"
        if kind == "branch":
            ctx, ref = f"ref:refs/heads/{value}", f"refs/heads/{value}"
        elif kind == "tag":
            ctx, ref = f"ref:refs/tags/{value}", f"refs/tags/{value}"
        elif kind == "environment":
            ctx, ref = f"environment:{value}", f"refs/heads/{env_branch}"
        else:
            ctx, ref = "pull_request", "refs/pull/1/merge"
        workflow_ref = f"{owner}/{repo}/.github/workflows/deploy.yml@{ref}"
        claims = {
            "iss": self.issuer,
            "sub": f"{head}:{ctx}",
            "repository": f"{owner}/{repo}",
            "repository_owner": owner,
            "repository_owner_id": owner_id,
            "repository_id": repo_id,
            "ref": ref,
            "ref_type": "tag" if kind == "tag" else "branch",
            "event_name": event,
            "workflow_ref": workflow_ref,
            "job_workflow_ref": job_workflow_ref or workflow_ref,
            "runner_environment": "github-hosted",
        }
        if kind == "environment":
            claims["environment"] = value
        return claims

    def candidates(self, trust: Trust, literals: list[Literal]) -> list[Candidate]:
        inferred = self._infer(literals)
        found = self._gather(self.seeds(literals))
        ctx = self.context

        declared_owners = {o for o in ctx.owners if "/" not in o}
        owned, owners_declared = owned_or_inferred(declared_owners, inferred["owners"])
        declared_repos = {tuple(r.split("/", 1)) for r in ctx.repos if r.count("/") == 1}
        # Repositories the trust names are taken as existing ones the owner controls.
        known = declared_repos | inferred["repos"]
        repos_declared = bool(declared_repos)

        owner_ids = dict(inferred["owner_ids"])
        repo_ids = dict(inferred["repo_ids"])
        # A bare repository_owner_id / repository_id literal belongs to the one owner or
        # repository in scope, when there is exactly one.
        id_literals = {
            claim: [lit.value for lit in literals if lit.claim == claim and lit.kind == "exact"]
            for claim in ("repository_owner_id", "repository_id")
        }
        if len(owned) == 1 and len(id_literals["repository_owner_id"]) == 1:
            owner_ids.setdefault(next(iter(owned)), id_literals["repository_owner_id"][0])
        if len(known) == 1 and len(id_literals["repository_id"]) == 1:
            repo_ids.setdefault(next(iter(known)), id_literals["repository_id"][0])
        owners = dict(found["owners"])
        for owner in owned:
            owners.setdefault(owner, owner_ids.get(owner))
        owners.setdefault(FRESH_OWNER, None)
        repos = dict(found["repos"])
        for _, repo in known:
            repos.setdefault(repo, None)
        repos.setdefault(FRESH_REPO, None)

        contexts = {
            (kind, value)
            for kind, value in found["contexts"]
            if kind not in ("branch", "tag") or valid_git_ref(value)
        }
        contexts |= {
            ("branch", "main"),
            ("branch", FRESH_BRANCH),
            ("tag", f"{PROBE}-tag"),
            ("environment", f"{PROBE}-env"),
            ("pull_request", ""),
        }
        events = found["events"] or {"push"}
        formats = ["legacy", "immutable"] if self.immutable_supported else ["legacy"]

        out: list[Candidate] = []
        for owner, oid in sorted(owners.items()):
            owner_id = oid or owner_ids.get(owner) or stable_id("owner", owner)
            for repo, rid in sorted(repos.items()):
                repo_id = rid or repo_ids.get((owner, repo)) or stable_id("repo", owner, repo)
                for kind, value in sorted(contexts):
                    for fmt in formats:
                        for event in sorted(
                            events | ({"pull_request"} if kind == "pull_request" else set())
                        ):
                            if kind == "pull_request" and event != "pull_request":
                                continue
                            # Environment jobs run from some branch; that branch is in `ref`.
                            branches = ["main", FRESH_BRANCH] if kind == "environment" else ["main"]
                            for job_ref in [None, *sorted(found["job_refs"])]:
                                for branch in branches:
                                    claims = self.token(
                                        owner,
                                        owner_id,
                                        repo,
                                        repo_id,
                                        kind,
                                        value,
                                        fmt,
                                        event,
                                        job_ref,
                                        branch,
                                    )
                                    out.append(
                                        self._classify(
                                            claims,
                                            owner,
                                            repo,
                                            kind,
                                            value,
                                            fmt,
                                            job_ref,
                                            owned,
                                            owners_declared,
                                            known,
                                            repos_declared,
                                            inferred,
                                            branch,
                                        )
                                    )
        return out

    def _classify(
        self,
        claims,
        owner,
        repo,
        kind,
        value,
        fmt,
        job_ref,
        owned,
        owners_declared,
        known,
        repos_declared,
        inferred,
        env_branch="main",
    ) -> Candidate:
        assumptions: list[str] = []
        if owner not in owned:
            reach = Reach.PUBLIC
            if owner == FRESH_OWNER:
                actor = "any GitHub user, from a repository in an account they create"
            else:
                actor = f"whoever owns or registers the GitHub account or organization `{owner}`"
            if owners_declared:
                assumptions.append(f"`{owner}` is not one of the declared owners")
            else:
                assumptions.append(
                    "Owners were inferred from the trust itself: "
                    + (", ".join(f"`{o}`" for o in sorted(owned)) or "none could be")
                )
            if fmt == "legacy":
                assumptions.append(LEGACY_NOTE)
            if self.scope != "public":
                actor = f"any user of the {self.label} instance or enterprise behind {self.issuer}"
        elif (owner, repo) not in known:
            reach = Reach.TENANT
            actor = (
                f"any member of `{owner}` who can create or push to a repository the trust "
                f"does not name (here `{owner}/{repo}`)"
            )
            if not repos_declared:
                assumptions.append(
                    "Repositories were inferred from the trust: "
                    + (", ".join(f"`{o}/{r}`" for o, r in sorted(known)) or "none could be")
                )
            if fmt == "legacy":
                assumptions.append(LEGACY_NOTE)
        else:
            protected = self._protected(f"{owner}/{repo}", inferred["refs"])
            full = f"{owner}/{repo}"
            if kind == "pull_request":
                reach = Reach.PROJECT
                actor = (
                    f"anyone with push access to `{full}` who opens a pull request from a branch "
                    "(pull requests from forks do not receive id-token: write)"
                )
            elif kind == "environment" and value not in protected and env_branch in protected:
                reach = Reach.PROTECTED
                actor = (
                    f"jobs on the protected branch `{env_branch}` of `{full}` that use the "
                    f"environment `{value}`"
                )
                if full not in self.context.protected_refs:
                    assumptions.append(
                        f"Assumes branch `{env_branch}` is protected in `{full}`; declare "
                        "protected_refs to make this a fact"
                    )
            elif value in protected:
                reach = Reach.PROTECTED
                noun = {"branch": "branch", "tag": "tag", "environment": "environment"}[kind]
                actor = f"workflows running on the protected {noun} `{value}` of `{full}`"
                if full not in self.context.protected_refs:
                    assumptions.append(
                        f"Assumes {noun} `{value}` is protected in `{full}` "
                        + (
                            "(deployment protection rules restrict which branches can deploy to it)"
                            if kind == "environment"
                            else "(branch protection or a ruleset limits who can push to it)"
                        )
                        + "; declare protected_refs to make this a fact"
                    )
            else:
                reach = Reach.PROJECT
                noun = {
                    "branch": "push a branch",
                    "tag": "push a tag",
                    "environment": "run a job against the environment",
                }[kind]
                actor = f"anyone who can {noun} in `{full}` (e.g. `{value}`)"
        if job_ref and reach >= Reach.TENANT:
            assumptions.append(
                f"The caller can use the reusable workflow `{job_ref}` (public repository, "
                "or access shared with the caller)"
            )
        preferred = (fmt == "immutable") if reach >= Reach.TENANT else (fmt == "legacy")
        return Candidate(claims, self.cap(reach), actor, assumptions, preferred)

    def _protected(self, full: str, inferred_refs: set[str]) -> set[str]:
        if full in self.context.protected_refs:
            return set(self.context.protected_refs[full])
        return {"main", "master"} | inferred_refs

    def recycled(self, trust: Trust, witness: Candidate) -> Candidate | None:
        claims = dict(witness.claims)
        owner, repo = claims["repository"].split("/")
        new_owner_id = stable_id("recycled-owner", owner)
        new_repo_id = stable_id("recycled-repo", owner, repo)
        sub = SUB.match(claims["sub"])
        if not sub:
            return None
        fmt = "immutable" if self.immutable_supported else "legacy"
        head = (
            f"repo:{owner}@{new_owner_id}/{repo}@{new_repo_id}"
            if fmt == "immutable"
            else f"repo:{owner}/{repo}"
        )
        claims.update(
            sub=f"{head}:{sub['ctx']}",
            repository_owner_id=new_owner_id,
            repository_id=new_repo_id,
        )
        return Candidate(
            claims,
            witness.reach,
            f"whoever takes over the name `{owner}/{repo}` after it is renamed, transferred "
            "or deleted",
        )

    def remediation(self, trust: Trust, reach: Reach) -> str:
        cloud_hint = {
            "aws": "Use StringEquals on `token.actions.githubusercontent.com:sub` (not StringLike)",
            "gcp": "Use an attribute condition on `assertion.repository_id` and "
            "`assertion.repository_owner_id`, and bind the service account to a single "
            "`attribute.repository_id/...` principalSet",
            "azure": "Use one federated credential per exact subject; in flexible credentials "
            "also match `repository_id` and `repository_owner_id`",
        }.get(trust.cloud, "Match the exact subject")
        return (
            f"{cloud_hint}. Pin it to the immutable subject of the one workflow context that "
            "needs it, e.g. `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production` with "
            "deployment protection rules on that environment, or `...:ref:refs/heads/main` with "
            "branch protection. Remove wildcards in the owner and repository parts."
        )
