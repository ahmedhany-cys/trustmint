"""Rough privilege levels for the identity a trust unlocks.

This only scales severity. It reads policy names and actions; it is not an
IAM evaluator, and every level carries the evidence it was derived from.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote

from trustmint.model import Privilege, PrivilegeAssessment

AWS_ADMIN_POLICIES = {"AdministratorAccess", "IAMFullAccess"}
READ_VERBS = re.compile(r"^(Get|List|Describe|Head|Search|Lookup|Query|Scan|Select|View|BatchGet)")
ADMIN_ACTIONS = re.compile(
    r"^(\*|iam:\*|iam:(Create|Put|Attach|Update|Pass)\w*|sts:\*|organizations:\*)$", re.I
)

GCP_ADMIN_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.workloadIdentityPoolAdmin",
}
AZURE_ADMIN_ROLES = {
    "Owner",
    "User Access Administrator",
    "Role Based Access Control Administrator",
}

LEVELS = {name.lower(): level for name, level in Privilege.__members__.items()}


def explicit(value: Any) -> PrivilegeAssessment | None:
    if isinstance(value, str) and value.lower() in LEVELS:
        return PrivilegeAssessment(LEVELS[value.lower()], [f"declared in snapshot: {value}"])
    return None


def load_policy(document: Any) -> dict:
    if isinstance(document, str):
        text = document.strip()
        if text.startswith("%7B") or text.startswith("%7b"):
            text = unquote(text)
        return json.loads(text)
    return document or {}


def _statements(document: Any) -> list[dict]:
    statements = load_policy(document).get("Statement", [])
    return [statements] if isinstance(statements, dict) else list(statements)


def aws_role(role: dict) -> PrivilegeAssessment:
    declared = explicit(role.get("Privilege"))
    if declared:
        return declared
    level, evidence = Privilege.UNKNOWN, []
    attached = role.get("AttachedManagedPolicies", [])
    inline = role.get("InlinePolicies", {})
    if not attached and not inline:
        return PrivilegeAssessment(Privilege.UNKNOWN, ["no permission policies in snapshot"])
    for policy in attached:
        name = policy.get("PolicyName") or str(policy.get("PolicyArn", "")).rsplit("/", 1)[-1]
        if name in AWS_ADMIN_POLICIES:
            found = Privilege.ADMIN
        elif "ReadOnly" in name or name.endswith("ViewOnlyAccess") or "SecurityAudit" in name:
            found = Privilege.READ
        elif "FullAccess" in name or name == "PowerUserAccess":
            found = Privilege.WRITE
        else:
            found = Privilege.UNKNOWN
        if found > level:
            level = found
        evidence.append(f"managed policy {name}: {found.name.lower()}")
    for name, document in inline.items():
        found = Privilege.READ
        for statement in _statements(document):
            if statement.get("Effect") != "Allow":
                continue
            actions = statement.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            for action in actions:
                verb = action.split(":", 1)[-1]
                if ADMIN_ACTIONS.match(action):
                    found = Privilege.ADMIN
                elif found < Privilege.WRITE and (verb.endswith("*") or not READ_VERBS.match(verb)):
                    found = Privilege.WRITE
        if found > level:
            level = found
        evidence.append(f"inline policy {name}: {found.name.lower()}")
    return PrivilegeAssessment(level, evidence)


def gcp_roles(roles: list[str], declared: Any = None) -> PrivilegeAssessment:
    explicit_level = explicit(declared)
    if explicit_level:
        return explicit_level
    if not roles:
        return PrivilegeAssessment(Privilege.UNKNOWN, ["no role grants in snapshot"])
    level, evidence = Privilege.UNKNOWN, []
    for role in roles:
        name = role.rsplit("/", 1)[-1]
        if role in GCP_ADMIN_ROLES:
            found = Privilege.ADMIN
        elif name.endswith(("viewer", "Viewer", "reader", "Reader")) or ".get" in name:
            found = Privilege.READ
        else:
            found = Privilege.WRITE
        level = max(level, found)
        evidence.append(f"{role}: {found.name.lower()}")
    return PrivilegeAssessment(level, evidence)


def azure_assignments(assignments: list[dict], declared: Any = None) -> PrivilegeAssessment:
    explicit_level = explicit(declared)
    if explicit_level:
        return explicit_level
    if not assignments:
        return PrivilegeAssessment(Privilege.UNKNOWN, ["no role assignments in snapshot"])
    level, evidence = Privilege.UNKNOWN, []
    for assignment in assignments:
        role = assignment.get("role") or assignment.get("roleDefinitionName", "")
        scope = assignment.get("scope", "")
        if role in AZURE_ADMIN_ROLES:
            found = Privilege.ADMIN
        elif role.endswith("Contributor") or role.endswith("Administrator"):
            found = Privilege.WRITE
        elif "Reader" in role:
            found = Privilege.READ
        else:
            found = Privilege.UNKNOWN
        level = max(level, found)
        evidence.append(f"{role} on {scope or 'unknown scope'}: {found.name.lower()}")
    return PrivilegeAssessment(level, evidence)
