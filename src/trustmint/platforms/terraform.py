"""HCP Terraform (Terraform Cloud) workload identity tokens.

    sub = organization:ORG:project:PROJECT:workspace:WORKSPACE:run_phase:plan|apply

Anyone can create an HCP Terraform organization, so a trust that does not pin
the organization is reachable by any HCP Terraform user. Plan-phase tokens are
available to anyone who can queue a plan in the workspace, a wider group than
those who can approve an apply.
"""

from __future__ import annotations

import re

from trustmint.conditions import Literal
from trustmint.model import Candidate, Reach, Trust
from trustmint.platforms.base import PROBE, Platform, owned_or_inferred, stable_id

SUB = re.compile(
    r"^organization:(?P<org>[^:]+):project:(?P<project>[^:]+):workspace:(?P<ws>[^:]+)"
    r":run_phase:(?P<phase>plan|apply)$"
)
EXACT_ORG = re.compile(r"organization:([^:*?]+):")
EXACT_WS = re.compile(r"organization:([^:*?]+):project:[^:]*:workspace:([^:*?]+):")
EXACT_PROJECT = re.compile(r"organization:([^:*?]+):project:([^:*?]+):workspace:([^:*?]+):")


class HcpTerraform(Platform):
    name = "terraform"
    label = "HCP Terraform"
    fillers = [
        "",
        "attacker",
        "-attacker",
        "plan",
        "apply",
        ":run_phase:plan",
        "attacker:run_phase:plan",
        ":workspace:attacker:run_phase:plan",
        "attacker:workspace:attacker:run_phase:plan",
        "attacker:project:attacker:workspace:attacker:run_phase:plan",
    ]

    def candidates(self, trust: Trust, literals: list[Literal]) -> list[Candidate]:
        orgs: set[str] = set()
        workspaces: set[tuple[str, str]] = set()
        projects: dict[tuple[str, str], str] = {}
        for lit in literals:
            if lit.claim in (None, "sub"):
                orgs.update(EXACT_ORG.findall(lit.value))
                workspaces.update(EXACT_WS.findall(lit.value))
                for org, project, ws in EXACT_PROJECT.findall(lit.value):
                    projects[(org, ws)] = project
            if lit.claim == "terraform_organization_name" and lit.kind == "exact":
                orgs.add(lit.value)
        owned, owners_declared = owned_or_inferred(set(self.context.owners), orgs)
        declared_ws = {tuple(r.split("/", 1)) for r in self.context.repos if r.count("/") == 1}
        known = declared_ws | workspaces

        combos: set[tuple[str, str, str]] = set()
        for org in owned | {f"{PROBE}-org"}:
            combos.add((org, "Default Project", f"{PROBE}-workspace"))
        for org, ws in known:
            combos.add((org, projects.get((org, ws), "Default Project"), ws))
        for seed in self.seeds(literals):
            match = SUB.match(seed.value) if seed.claim in (None, "sub") else None
            if match:
                project = match["project"]
                if (match["org"], match["ws"]) in known:
                    # The workspace already exists, so its project is not the attacker's choice.
                    project = projects.get((match["org"], match["ws"]), "Default Project")
                combos.add((match["org"], project, match["ws"]))

        out = []
        for org, project, ws in sorted(combos):
            for phase in ("plan", "apply"):
                claims = {
                    "iss": self.issuer,
                    "sub": f"organization:{org}:project:{project}:workspace:{ws}:run_phase:{phase}",
                    "terraform_organization_name": org,
                    "terraform_organization_id": stable_id("org", org),
                    "terraform_project_name": project,
                    "terraform_workspace_name": ws,
                    "terraform_workspace_id": stable_id("ws", org, ws),
                    "terraform_run_phase": phase,
                }
                assumptions = []
                if org not in owned:
                    reach, actor = (
                        Reach.PUBLIC,
                        f"any HCP Terraform user who creates the organization `{org}`",
                    )
                    if not owners_declared:
                        assumptions.append(
                            "Organizations were inferred from the trust: "
                            + (", ".join(f"`{o}`" for o in sorted(owned)) or "none could be")
                        )
                elif (org, ws) not in known:
                    reach = Reach.TENANT
                    actor = f"any member of `{org}` who can create a workspace (here `{ws}`)"
                elif phase == "plan":
                    reach = Reach.PROJECT
                    actor = f"anyone who can queue a plan in workspace `{ws}`"
                else:
                    reach = Reach.PROTECTED
                    actor = f"apply runs in workspace `{ws}`"
                    assumptions.append(
                        "Assumes applies in this workspace need approval or restricted permissions"
                    )
                out.append(Candidate(claims, self.cap(reach), actor, assumptions))
        return out

    def remediation(self, trust: Trust, reach: Reach) -> str:
        return (
            "Pin the organization, project and workspace exactly, and use separate roles for "
            "`run_phase:plan` (read-only) and `run_phase:apply`. Never wildcard the organization."
        )
