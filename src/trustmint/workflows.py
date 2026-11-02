"""GitHub Actions workflows that mint OIDC tokens from untrusted triggers.

``pull_request_target``, ``workflow_run`` and ``issue_comment`` run in the
base repository's context, so their tokens carry the base branch in ``sub``
(``repo:acme/app:ref:refs/heads/main``). A trust pinned to ``main`` is then
reachable by anyone who can open a pull request or comment, if the job runs
their code. This module finds such jobs and the cloud identities they name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

UNTRUSTED_TRIGGERS = {"pull_request_target", "workflow_run", "issue_comment"}
HEAD_CHECKOUT = re.compile(
    r"github\.event\.pull_request\.head|github\.head_ref|refs/pull/|"
    r"github\.event\.workflow_run\.head|gh pr checkout|git fetch \S+ pull/"
)
CLOUD_INPUTS = {
    "aws-actions/configure-aws-credentials": ("role-to-assume",),
    "google-github-actions/auth": ("workload_identity_provider", "service_account"),
    "azure/login": ("client-id",),
}


@dataclass
class OidcJob:
    repo: str
    path: str
    job: str
    triggers: list[str]
    untrusted_triggers: list[str]
    runs_untrusted_code: bool
    environment: str | None
    cloud_refs: list[str] = field(default_factory=list)

    @property
    def location(self) -> str:
        return f"{self.path}#{self.job}"


def _triggers(doc: dict) -> list[str]:
    # PyYAML reads the bare key `on` as boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(t) for t in on]
    if isinstance(on, dict):
        return [str(t) for t in on]
    return []


def _id_token_write(permissions: Any) -> bool:
    if permissions == "write-all":
        return True
    return isinstance(permissions, dict) and permissions.get("id-token") == "write"


def _environment(job: dict) -> str | None:
    env = job.get("environment")
    if isinstance(env, dict):
        env = env.get("name")
    return str(env) if env else None


def scan_file(repo: str, path: Path, display: str) -> list[OidcJob]:
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    triggers = _triggers(doc)
    untrusted = sorted(set(triggers) & UNTRUSTED_TRIGGERS)
    top_permissions = doc.get("permissions")
    jobs = []
    for name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        permissions = job.get("permissions", top_permissions)
        if not _id_token_write(permissions):
            continue
        steps = job.get("steps") or []
        text = yaml.safe_dump(steps, sort_keys=False)
        refs = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            action = str(step.get("uses", "")).split("@", 1)[0].lower()
            for known, inputs in CLOUD_INPUTS.items():
                if action == known:
                    for key in inputs:
                        value = (step.get("with") or {}).get(key)
                        if value:
                            refs.append(str(value))
        jobs.append(
            OidcJob(
                repo=repo,
                path=display,
                job=str(name),
                triggers=triggers,
                untrusted_triggers=untrusted,
                runs_untrusted_code=bool(untrusted) and bool(HEAD_CHECKOUT.search(text)),
                environment=_environment(job),
                cloud_refs=refs,
            )
        )
    return jobs


def scan(repo: str, directory: str) -> list[OidcJob]:
    root = Path(directory)
    if (root / ".github" / "workflows").is_dir():
        root = root / ".github" / "workflows"
    files = sorted([*root.glob("*.yml"), *root.glob("*.yaml")])
    jobs = []
    for file in files:
        jobs += scan_file(repo, file, str(file))
    return jobs
