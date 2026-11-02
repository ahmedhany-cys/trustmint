"""Read federation trusts from ``terraform show -json plan.out`` before they are applied.

The plan is converted into the snapshot shape so the same loaders apply.
Values Terraform only learns at apply time (for example a policy that
references an OIDC provider created in the same plan) are absent from
``planned_values``; those resources are reported as skipped, not guessed.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any


def _resources(module: dict) -> Iterator[dict]:
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _resources(child)


def _first(value: Any) -> dict:
    if isinstance(value, list):
        return value[0] if value else {}
    return value or {}


def to_snapshot(plan: dict) -> tuple[dict, list[str]]:
    root = plan.get("planned_values", {}).get("root_module", {})
    resources = list(_resources(root))
    skipped: list[str] = []
    aws: dict[str, list] = {"roles": [], "oidc_providers": []}
    gcp: dict[str, list] = {"providers": [], "service_accounts": [], "resource_policies": []}
    azure: dict[str, list] = {"identities": []}
    roles: dict[str, dict] = {}
    accounts: dict[str, dict] = {}
    identities: dict[str, dict] = {}

    for res in resources:
        rtype, values, address = res.get("type"), res.get("values", {}), res.get("address", "")
        if rtype == "aws_iam_openid_connect_provider":
            url = values.get("url")
            if url:
                host = url.removeprefix("https://")
                aws["oidc_providers"].append(
                    {
                        "Arn": f"arn:aws:iam::000000000000:oidc-provider/{host}",
                        "Url": url,
                        "ClientIDList": values.get("client_id_list") or [],
                        "Source": address,
                    }
                )
        elif rtype == "aws_iam_role":
            policy = values.get("assume_role_policy")
            if not policy:
                skipped.append(f"{address}: assume_role_policy is unknown until apply")
                continue
            name = values.get("name") or address
            role = {
                "RoleName": name,
                "Arn": f"{address} (role {name})",
                "AssumeRolePolicyDocument": json.loads(policy),
                "AttachedManagedPolicies": [
                    {"PolicyArn": arn, "PolicyName": arn.rsplit("/", 1)[-1]}
                    for arn in values.get("managed_policy_arns") or []
                ],
                "InlinePolicies": {
                    p.get("name", f"inline-{i}"): json.loads(p["policy"])
                    for i, p in enumerate(values.get("inline_policy") or [])
                    if p.get("policy")
                },
            }
            roles[name] = role
            aws["roles"].append(role)
        elif rtype in ("aws_iam_role_policy_attachment",):
            role = roles.get(values.get("role", ""))
            arn = values.get("policy_arn")
            if role is not None and arn:
                role["AttachedManagedPolicies"].append(
                    {"PolicyArn": arn, "PolicyName": arn.rsplit("/", 1)[-1]}
                )
        elif rtype == "aws_iam_role_policy":
            role = roles.get(values.get("role", ""))
            if role is not None and values.get("policy"):
                role["InlinePolicies"][values.get("name", address)] = json.loads(values["policy"])
        elif rtype == "google_iam_workload_identity_pool_provider":
            oidc = _first(values.get("oidc"))
            if not oidc:
                continue
            project = values.get("project") or "-"
            gcp["providers"].append(
                {
                    "name": (
                        f"projects/{project}/locations/global/workloadIdentityPools/"
                        f"{values.get('workload_identity_pool_id')}/providers/"
                        f"{values.get('workload_identity_pool_provider_id')}"
                    ),
                    "oidc": {
                        "issuerUri": oidc.get("issuer_uri", ""),
                        "allowedAudiences": oidc.get("allowed_audiences") or [],
                    },
                    "attributeMapping": values.get("attribute_mapping") or {},
                    "attributeCondition": values.get("attribute_condition"),
                    "disabled": bool(values.get("disabled")),
                }
            )
        elif rtype in ("google_service_account_iam_member", "google_service_account_iam_binding"):
            sa = str(values.get("service_account_id", address)).rsplit("/", 1)[-1]
            members = values.get("members") or ([values["member"]] if values.get("member") else [])
            if not members:
                skipped.append(f"{address}: member is unknown until apply")
                continue
            account = accounts.setdefault(sa, {"email": sa, "iam_policy": {"bindings": []}})
            account["iam_policy"]["bindings"].append(
                {"role": values.get("role"), "members": members}
            )
        elif rtype in ("google_project_iam_member", "google_project_iam_binding"):
            members = values.get("members") or ([values["member"]] if values.get("member") else [])
            if any("workloadIdentityPools" in m for m in members):
                gcp["resource_policies"].append(
                    {
                        "resource": f"projects/{values.get('project', '?')}",
                        "iam_policy": {
                            "bindings": [{"role": values.get("role"), "members": members}]
                        },
                    }
                )
        elif rtype in (
            "azuread_application_federated_identity_credential",
            "azurerm_federated_identity_credential",
        ):
            owner = (
                values.get("application_id")
                or values.get("application_object_id")
                or values.get("parent_id")
                or address
            )
            kind = "managed_identity" if rtype.startswith("azurerm") else "app"
            identity = identities.setdefault(
                owner, {"name": owner, "kind": kind, "federated_credentials": []}
            )
            credential = {
                "name": values.get("display_name") or values.get("name") or address,
                "issuer": values.get("issuer", ""),
                "subject": values.get("subject"),
                "audiences": values.get("audiences") or values.get("audience") or [],
            }
            if credential["subject"] is None:
                skipped.append(f"{address}: subject is unknown until apply")
                continue
            identity["federated_credentials"].append(credential)

    gcp["service_accounts"] = list(accounts.values())
    azure["identities"] = list(identities.values())
    return {"schema": "trustmint/snapshot@1", "aws": aws, "gcp": gcp, "azure": azure}, skipped
