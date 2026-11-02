"""GitLab CI ID tokens.

    sub = project_path:GROUP[/SUBGROUP...]/PROJECT:ref_type:branch|tag:ref:REF

GitLab also issues ``ref_protected`` and ``environment_protected`` claims,
which Google and flexible Entra credentials can check but AWS cannot. On
gitlab.com anyone can create a top-level group, so a trust that does not pin
the group is reachable by any GitLab user. The job chooses the audience.
"""

from __future__ import annotations

import re

from trustmint.conditions import Literal
from trustmint.model import Candidate, Reach, Trust
from trustmint.platforms.base import PROBE, Platform, owned_or_inferred, stable_id, valid_git_ref

SEG = r"[A-Za-z0-9_.-]+"
SUB = re.compile(
    rf"^project_path:(?P<path>{SEG}(?:/{SEG})+):ref_type:(?P<type>branch|tag):ref:(?P<ref>.+)$"
)
EXACT_PATH = re.compile(rf"project_path:({SEG}(?:/{SEG})+):")
EXACT_GROUP = re.compile(rf"project_path:({SEG})/")
EXACT_REF = re.compile(r":ref_type:(branch|tag):ref:([^*?]+)$")


class GitLabCI(Platform):
    name = "gitlab"
    label = "GitLab CI"
    fillers = [
        "",
        "attacker",
        "-attacker",
        "/attacker",
        "attacker/attacker",
        ":ref_type:branch:ref:attacker",
        "attacker:ref_type:branch:ref:attacker",
        "attacker/attacker:ref_type:branch:ref:attacker",
        "branch:ref:attacker",
        "tag:ref:attacker",
    ]

    def candidates(self, trust: Trust, literals: list[Literal]) -> list[Candidate]:
        groups: set[str] = set()
        paths: set[str] = set()
        refs: set[str] = set()
        for lit in literals:
            if lit.claim in (None, "sub"):
                groups.update(EXACT_GROUP.findall(lit.value))
                paths.update(EXACT_PATH.findall(lit.value))
                match = EXACT_REF.search(lit.value)
                if match:
                    refs.add(match.group(2))
            if lit.claim == "project_path" and lit.kind == "exact":
                paths.add(lit.value)
                groups.add(lit.value.split("/")[0])
            if lit.claim == "namespace_path" and lit.kind in ("exact", "prefix", "glob"):
                head = re.match(rf"^({SEG})", lit.value)
                if head and (lit.kind == "exact" or "/" in lit.value):
                    groups.add(head.group(1))
            if lit.claim == "ref" and lit.kind == "exact":
                refs.add(lit.value)
        for path in paths:
            groups.add(path.split("/")[0])

        owned, owners_declared = owned_or_inferred(
            {o for o in self.context.owners if "/" not in o}, groups
        )
        known = {r for r in self.context.repos if "/" in r} | paths

        cand_paths = (
            set(paths)
            | {f"{g}/{PROBE}-project" for g in owned}
            | {f"{PROBE}-group/{PROBE}-project"}
        )
        cand_refs = {("branch", "main"), ("branch", f"{PROBE}-branch"), ("tag", f"{PROBE}-tag")}
        cand_refs |= {("branch", r) for r in refs}
        for seed in self.seeds(literals):
            if seed.claim in (None, "sub"):
                match = SUB.match(seed.value)
                if match:
                    cand_paths.add(match["path"])
                    if valid_git_ref(match["ref"]):
                        cand_refs.add((match["type"], match["ref"]))
            elif seed.claim == "project_path" and "/" in seed.value:
                cand_paths.add(seed.value)
            elif seed.claim == "namespace_path" and seed.value:
                cand_paths.add(f"{seed.value}/{PROBE}-project")

        out = []
        for path in sorted(cand_paths):
            namespace, project = path.rsplit("/", 1)
            top = path.split("/")[0]
            protected = self.context.protected_refs.get(path, {"main", "master"} | refs)
            for ref_type, ref in sorted(cand_refs):
                is_protected = ref in protected
                claims = {
                    "iss": self.issuer,
                    "sub": f"project_path:{path}:ref_type:{ref_type}:ref:{ref}",
                    "namespace_path": namespace,
                    "namespace_id": stable_id("ns", namespace),
                    "project_path": path,
                    "project_id": stable_id("project", path),
                    "ref": ref,
                    "ref_type": ref_type,
                    "ref_protected": "true" if is_protected else "false",
                    "pipeline_source": "push",
                }
                assumptions = []
                if top not in owned:
                    reach = Reach.PUBLIC
                    actor = f"any GitLab user who creates the group `{top}`"
                    if not owners_declared:
                        assumptions.append(
                            "Groups were inferred from the trust: "
                            + (", ".join(f"`{g}`" for g in sorted(owned)) or "none could be")
                        )
                elif path not in known:
                    reach = Reach.TENANT
                    actor = f"any member of `{top}` who can create a project (here `{path}`)"
                elif not is_protected:
                    reach = Reach.PROJECT
                    actor = f"any Developer in `{path}` who pushes the {ref_type} `{ref}`"
                else:
                    reach = Reach.PROTECTED
                    actor = f"pipelines on the protected {ref_type} `{ref}` of `{path}`"
                    if path not in self.context.protected_refs:
                        assumptions.append(f"Assumes `{ref}` is a protected {ref_type} in `{path}`")
                out.append(Candidate(claims, self.cap(reach), actor, assumptions))
        return out

    def recycled(self, trust: Trust, witness: Candidate) -> Candidate | None:
        claims = dict(witness.claims)
        claims["namespace_id"] = stable_id("recycled-ns", claims["namespace_path"])
        claims["project_id"] = stable_id("recycled-project", claims["project_path"])
        return Candidate(
            claims,
            witness.reach,
            f"whoever takes over the path `{claims['project_path']}` after it is renamed, "
            "transferred or deleted",
        )

    def remediation(self, trust: Trust, reach: Reach) -> str:
        return (
            "Pin the full subject `project_path:GROUP/PROJECT:ref_type:branch:ref:main` with an "
            "exact match. Where the cloud can read extra claims (Google, flexible Entra "
            "credentials), also require `ref_protected == 'true'` and `project_id`, which "
            "survives renames."
        )
