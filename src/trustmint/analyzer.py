"""Evaluate every trust against the tokens each class of actor can mint."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from trustmint import platforms
from trustmint.conditions import Match, Node, Tri, all_of
from trustmint.context import Context
from trustmint.model import (
    SEVERITY_ORDER,
    Candidate,
    Finding,
    Privilege,
    Reach,
    Trust,
    TrustResult,
)
from trustmint.platforms.base import PROBE, Platform, stable_id
from trustmint.platforms.github import GitHubActions
from trustmint.workflows import OidcJob

RULES: dict[str, str] = {
    "TM001": "Anyone on the CI platform can assume this identity",
    "TM002": "Any repository or project in the organization can assume this identity",
    "TM003": "Unprotected branches, pull requests or plans can assume this identity",
    "TM004": "A workflow with an untrusted trigger can mint a token this identity accepts",
    "TM005": "The trust is bound to names that someone else could take over",
    "TM006": "No token satisfies this trust (dead or broken trust)",
    "TM007": "The issuer is not a CI platform TrustMint models",
    "TM008": "The trust could not be fully evaluated",
    "TM009": "A workflow runs untrusted code with id-token: write",
    "TM010": "The trust only accepts name-based GitHub subjects",
}

DEFAULT_AUDIENCE = {"aws": "sts.amazonaws.com", "azure": "api://AzureADTokenExchange"}
# Branch pushes read more naturally in a witness than tags or environments.
WITNESS_CONTEXT = [(":ref:refs/heads/", 3), (":pull_request", 2), (":ref:refs/tags/", 1)]
IMMUTABLE_SUB = re.compile(r"^repo:[^/:]+@\d+/")
WITNESS_KEYS = [
    "sub",
    "aud",
    "repository",
    "repository_owner",
    "ref",
    "environment",
    "event_name",
    "job_workflow_ref",
    "project_path",
    "ref_protected",
    "terraform_run_phase",
    "oidc.circleci.com/vcs-ref",
]


@dataclass
class Report:
    results: list[TrustResult]
    findings: list[Finding]
    jobs: list[OidcJob] = field(default_factory=list)
    context: Context = field(default_factory=Context)
    inputs: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts


def severity(reach: Reach, level: Privilege) -> str:
    if reach == Reach.PUBLIC:
        return "critical"
    if reach == Reach.TENANT:
        return "critical" if level == Privilege.ADMIN else "high"
    if reach == Reach.PROJECT:
        return "high" if level >= Privilege.WRITE else "medium"
    return "info"


def check(
    trust: Trust, platform: Platform, candidate: Candidate, audiences: list[str | None]
) -> tuple[Tri, dict | None]:
    outcomes: list[Tri] = []
    for audience in audiences:
        claims = dict(candidate.claims)
        if platform.controls_audience:
            claims["aud"] = (
                audience
                if audience is not None
                else DEFAULT_AUDIENCE.get(trust.cloud, "tm-probe-audience")
            )
        parts: list[Tri] = [trust.condition.evaluate(claims)]
        if trust.audience is not None:
            parts.append(trust.audience.evaluate(claims))
        verdict = all_of(parts)
        if verdict is True:
            return True, claims
        outcomes.append(verdict)
    return (None if None in outcomes else False), None


def _rank(candidate: Candidate) -> tuple:
    """Broadest reach first; among equals, the most readable witness token."""
    sub = str(candidate.claims.get("sub", ""))
    head = re.split(r":(?:ref:|environment:|pull_request)", sub)[0]
    kind = next((score for marker, score in WITNESS_CONTEXT if marker in sub), 0)
    return (
        candidate.reach,
        candidate.preferred,
        head.count(PROBE) + head.count("attacker"),
        kind,
        -len(sub),
    )


def _literals(trust: Trust):
    literals = list(trust.condition.literals())
    if trust.audience is not None:
        literals += list(trust.audience.literals())
    return literals


def _witness_view(claims: dict) -> dict[str, Any]:
    return {k: claims[k] for k in WITNESS_KEYS if k in claims}


def _base(
    trust: Trust, platform: Platform, rule: str, sev: str, message: str, remediation: str, **extra
) -> Finding:
    return Finding(
        rule_id=rule,
        severity=sev,
        title=RULES[rule],
        trust_id=trust.id,
        cloud=trust.cloud,
        identity=trust.identity,
        issuer=trust.issuer,
        platform=platform.label,
        reach=extra.pop("reach", None),
        privilege=trust.privilege.level.name.lower(),
        message=message,
        remediation=remediation,
        source=trust.source,
        evidence=[f"condition: {trust.condition.describe()}"]
        + ([f"audience: {trust.audience.describe()}"] if trust.audience else [])
        + [f"privilege: {e}" for e in trust.privilege.evidence]
        + trust.notes,
        **extra,
    )


def _dead_reason(node: Node) -> str | None:
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, Match) and current.op == "equals":
            for value in current.values:
                if "*" in value or "?" in value:
                    return (
                        f"`{current.claim}` is compared with {value!r} using exact equality, so "
                        "the wildcard is matched literally (use StringLike, or better, an exact "
                        "subject)"
                    )
        stack.extend(getattr(current, "children", []))
        if hasattr(current, "child"):
            stack.append(current.child)
    return None


def analyze_trust(trust: Trust, context: Context) -> TrustResult:
    platform = platforms.resolve(trust.issuer, context)
    literals = _literals(trust)
    candidates = platform.candidates(trust, literals)
    if not candidates:
        return _unmodeled(trust, platform)
    audiences = platform.audience_options(literals) if platform.controls_audience else [None]
    best: Candidate | None = None
    undecided = 0
    immutable_seen = False
    for candidate in candidates:
        verdict, claims = check(trust, platform, candidate, audiences)
        if verdict is None:
            undecided += 1
            continue
        if not verdict:
            continue
        if IMMUTABLE_SUB.match(str(candidate.claims.get("sub", ""))):
            immutable_seen = True
        hit = Candidate(
            claims or candidate.claims,
            candidate.reach,
            candidate.actor,
            candidate.assumptions,
            candidate.preferred,
        )
        if best is None or _rank(hit) > _rank(best):
            best = hit

    reach = best.reach if best else (None if undecided else Reach.NONE)
    result = TrustResult(trust, platform.name, reach, best, len(candidates), undecided)
    level = trust.privilege.level

    if best and best.reach >= Reach.PROJECT:
        rule = {Reach.PUBLIC: "TM001", Reach.TENANT: "TM002", Reach.PROJECT: "TM003"}[best.reach]
        result.findings.append(
            _base(
                trust,
                platform,
                rule,
                severity(best.reach, level),
                f"Reachable by {best.actor}. The witness token below satisfies the trust"
                + (" and its audience check" if trust.audience else "")
                + ".",
                platform.remediation(trust, best.reach),
                reach=best.reach.name,
                witness=_witness_view(best.claims),
                actor=best.actor,
                assumptions=best.assumptions,
            )
        )
    if best and best.reach <= Reach.PROJECT:
        recycled = platform.recycled(trust, best)
        if recycled is not None:
            verdict, claims = check(trust, platform, recycled, audiences)
            if verdict:
                result.findings.append(
                    _base(
                        trust,
                        platform,
                        "TM005",
                        "medium" if level == Privilege.ADMIN else "low",
                        f"The trust still matches when the owner and repository IDs change, so "
                        f"{recycled.actor} would inherit it. It checks names, which can be reused, "
                        "rather than immutable IDs.",
                        "Bind to immutable identifiers: GitHub `repository_id` / "
                        "`repository_owner_id` or the immutable `sub` format, GitLab `project_id`.",
                        reach=best.reach.name,
                        witness=_witness_view(claims or {}),
                        actor=recycled.actor,
                    )
                )
    if (
        best
        and best.reach <= Reach.PROJECT
        and isinstance(platform, GitHubActions)
        and platform.immutable_supported
        and not immutable_seen
    ):
        result.findings.append(
            _base(
                trust,
                platform,
                "TM010",
                "info",
                "Only name-based subjects (`repo:OWNER/REPO:...`) satisfy this trust. It keeps "
                "working for repositories that have not opted in, and will stop matching once the "
                "repository is renamed, transferred or opted into immutable subjects.",
                "Plan the migration: add the immutable subject "
                "`repo:OWNER@OWNER_ID/REPO@REPO_ID:...` before opting the repository in, "
                "then remove "
                "the name-based one.",
                reach=best.reach.name,
            )
        )
    if reach == Reach.NONE:
        reason = _dead_reason(trust.condition)
        result.findings.append(
            _base(
                trust,
                platform,
                "TM006",
                "info",
                (reason + ". ")
                if reason
                else "None of the tokens TrustMint built for this platform satisfy the trust. "
                "It may be "
                "unused, mistyped, or written for a subject format TrustMint does not model.",
                "Remove the trust if nothing uses it, or correct it so it names exactly the "
                "pipeline "
                "that needs it.",
                reach="NONE",
            )
        )
    if undecided and (best is None or best.reach < Reach.PUBLIC):
        reasons = sorted(set(trust.condition.unknown_reasons()))
        result.findings.append(
            _base(
                trust,
                platform,
                "TM008",
                "info",
                f"{undecided} of {len(candidates)} candidate tokens could not be decided"
                + (f" ({'; '.join(reasons)})" if reasons else "")
                + ". The reach shown is a lower bound.",
                "Review the undecidable parts by hand, or simplify the condition to constructs "
                "TrustMint models.",
                reach=best.reach.name if best else None,
            )
        )
    return result


def _unmodeled(trust: Trust, platform: Platform) -> TrustResult:
    unconditional = trust.condition.evaluate({}) is True
    finding = _base(
        trust,
        platform,
        "TM007",
        "high" if unconditional else "info",
        (
            f"The trust accepts any token from {trust.issuer}: it checks no claims. "
            "For a shared issuer that means anyone with an account there."
            if unconditional
            else f"{trust.issuer} is not a platform TrustMint models, so its reach is unknown."
        ),
        "Declare the platform behind this issuer in the context file (`issuers`), or review the "
        "trust by hand and require an exact subject.",
    )
    return TrustResult(trust, platform.name, None, None, 0, 0, [finding])


def _workflow_findings(job: OidcJob, results: list[TrustResult], context: Context) -> list[Finding]:
    findings: list[Finding] = []
    if not job.untrusted_triggers:
        return findings
    owner, _, repo = job.repo.partition("/")
    matched = False
    for result in results:
        trust = result.trust
        platform = platforms.resolve(trust.issuer, context)
        if not isinstance(platform, GitHubActions):
            continue
        if result.reach == Reach.PUBLIC:
            continue  # already reachable by anyone; the workflow adds nothing
        literals = _literals(trust)
        inferred = platform._infer(literals)
        owner_id = inferred["owner_ids"].get(owner) or stable_id("owner", owner)
        repo_id = inferred["repo_ids"].get((owner, repo)) or stable_id("repo", owner, repo)
        if job.environment:
            contexts = [("environment", job.environment)]
        else:
            branches = context.protected_refs.get(job.repo, {"main", "master"})
            contexts = [("branch", b) for b in sorted(branches)]
        audiences = platform.audience_options(literals)
        for kind, value in contexts:
            hit = None
            for fmt in ("legacy", "immutable"):
                for event in job.untrusted_triggers:
                    claims = platform.token(owner, owner_id, repo, repo_id, kind, value, fmt, event)
                    verdict, final = check(
                        trust, platform, Candidate(claims, Reach.PUBLIC, ""), audiences
                    )
                    if verdict:
                        hit = final
                        break
                if hit:
                    break
            if not hit:
                continue
            matched = True
            named = any(ref == trust.identity or ref in str(trust.raw) for ref in job.cloud_refs)
            if job.runs_untrusted_code:
                sev, how = (
                    "critical",
                    (
                        "checks out and runs pull request code, so anyone who can open a pull "
                        "request controls a job that can mint this token"
                    ),
                )
            else:
                sev, how = (
                    "medium",
                    (
                        "can mint this token from an event outsiders can trigger; any script "
                        "injection in the job hands over the identity"
                    ),
                )
            findings.append(
                Finding(
                    rule_id="TM004",
                    severity=sev,
                    title=RULES["TM004"],
                    trust_id=trust.id,
                    cloud=trust.cloud,
                    identity=trust.identity,
                    issuer=trust.issuer,
                    platform=platform.label,
                    reach="PUBLIC" if job.runs_untrusted_code else None,
                    privilege=trust.privilege.level.name.lower(),
                    message=(
                        f"`{job.location}` runs on `{', '.join(job.untrusted_triggers)}` with "
                        f"id-token: write and {how}. Its tokens carry the base "
                        f"{'environment' if kind == 'environment' else 'branch'} `{value}`, which "
                        "this trust accepts."
                        + (" The job names this identity directly." if named else "")
                    ),
                    remediation=(
                        "Do not grant id-token: write to jobs triggered by pull_request_target, "
                        "workflow_run or issue_comment. Run untrusted code in a `pull_request` job "
                        "without cloud access, and deploy from a separate job on push to a "
                        "protected branch, behind an environment with required reviewers."
                    ),
                    witness=_witness_view(hit),
                    actor="anyone who can open a pull request or comment",
                    evidence=[
                        f"workflow: {job.location}",
                        f"condition: {trust.condition.describe()}",
                    ],
                    source=job.location,
                )
            )
            break  # one finding per trust and job is enough
    if job.runs_untrusted_code and not matched:
        findings.append(
            Finding(
                rule_id="TM009",
                severity="high",
                title=RULES["TM009"],
                trust_id=None,
                cloud=None,
                identity=", ".join(job.cloud_refs) or None,
                issuer=platforms.GITHUB,
                platform="GitHub Actions",
                reach=None,
                privilege=None,
                message=(
                    f"`{job.location}` runs on `{', '.join(job.untrusted_triggers)}`, checks out "
                    "pull request code and has id-token: write. No trust in the inputs accepts its "
                    "tokens, but any cloud trust on the base branch would."
                ),
                remediation=(
                    "Remove id-token: write from this job, or stop running pull request code in it."
                ),
                source=job.location,
                evidence=[f"workflow: {job.location}"],
            )
        )
    return findings


def _link_usage(results: list[TrustResult], jobs: list[OidcJob]) -> None:
    for result in results:
        for job in jobs:
            for ref in job.cloud_refs:
                if ref == result.trust.identity or (
                    isinstance(result.trust.raw, dict) and ref == result.trust.raw.get("provider")
                ):
                    result.used_by.append(job.location)


def analyze(
    trusts: list[Trust],
    context: Context,
    jobs: list[OidcJob] | None = None,
    inputs: list[str] | None = None,
    skipped: list[str] | None = None,
) -> Report:
    jobs = jobs or []
    results = [analyze_trust(trust, context) for trust in trusts]
    _link_usage(results, jobs)
    findings = [f for r in results for f in r.findings]
    for job in jobs:
        findings += _workflow_findings(job, results, context)
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.rule_id, f.identity or ""))
    return Report(results, findings, jobs, context, inputs or [], skipped or [])
