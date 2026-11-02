"""Optional, read-only collection of an AWS account into a TrustMint snapshot.

Calls only iam:List* and iam:Get* APIs. Requires ``pip install trustmint[aws]``.
Permissions needed: iam:ListRoles, iam:ListAttachedRolePolicies,
iam:ListRolePolicies, iam:GetRolePolicy, iam:ListOpenIDConnectProviders,
iam:GetOpenIDConnectProvider. The AWS managed SecurityAudit policy covers them.
"""

from __future__ import annotations

from typing import Any

from trustmint.sources.aws import _statements, _web_identity


def collect(session: Any) -> dict:
    iam = session.client("iam")
    providers = []
    for item in iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", []):
        arn = item["Arn"]
        detail = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        providers.append(
            {
                "Arn": arn,
                "Url": detail.get("Url", ""),
                "ClientIDList": detail.get("ClientIDList", []),
            }
        )
    roles = []
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            document = role.get("AssumeRolePolicyDocument", {})
            if not any(_web_identity(s) for s in _statements(document)):
                continue
            name = role["RoleName"]
            attached = []
            for apage in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
                attached += apage["AttachedPolicies"]
            inline = {}
            for ipage in iam.get_paginator("list_role_policies").paginate(RoleName=name):
                for policy_name in ipage["PolicyNames"]:
                    inline[policy_name] = iam.get_role_policy(
                        RoleName=name, PolicyName=policy_name
                    )["PolicyDocument"]
            roles.append(
                {
                    "RoleName": name,
                    "Arn": role["Arn"],
                    "AssumeRolePolicyDocument": document,
                    "AttachedManagedPolicies": attached,
                    "InlinePolicies": inline,
                }
            )
    account = session.client("sts").get_caller_identity().get("Account")
    return {
        "schema": "trustmint/snapshot@1",
        "aws": {"account_id": account, "oidc_providers": providers, "roles": roles},
    }
