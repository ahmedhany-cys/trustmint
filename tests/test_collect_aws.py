import json
from urllib.parse import quote

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber  # noqa: E402

from trustmint.collect_aws import collect  # noqa: E402

TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {
                "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
            },
            "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*"}},
        }
    ],
}
SERVICE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"Service": "ec2.amazonaws.com"},
        }
    ],
}


class FakeSession:
    def __init__(self):
        self.iam = boto3.client(
            "iam", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
        )
        self.sts = boto3.client(
            "sts", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
        )

    def client(self, name):
        return {"iam": self.iam, "sts": self.sts}[name]


def test_collect_reads_only_web_identity_roles():
    session = FakeSession()
    provider = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
    created = "2026-01-01T00:00:00Z"
    with Stubber(session.iam) as iam, Stubber(session.sts) as sts:
        iam.add_response(
            "list_open_id_connect_providers", {"OpenIDConnectProviderList": [{"Arn": provider}]}
        )
        iam.add_response(
            "get_open_id_connect_provider",
            {"Url": "token.actions.githubusercontent.com", "ClientIDList": ["sts.amazonaws.com"]},
            {"OpenIDConnectProviderArn": provider},
        )
        iam.add_response(
            "list_roles",
            {
                "Roles": [
                    {
                        "Path": "/",
                        "RoleName": "ci",
                        "RoleId": "AROAAAAAAAAAAAAAAAAAA",
                        "Arn": "arn:aws:iam::111111111111:role/ci",
                        "CreateDate": created,
                        "AssumeRolePolicyDocument": quote(json.dumps(TRUST)),
                    },
                    {
                        "Path": "/",
                        "RoleName": "ec2",
                        "RoleId": "AROAAAAAAAAAAAAAAAAAB",
                        "Arn": "arn:aws:iam::111111111111:role/ec2",
                        "CreateDate": created,
                        "AssumeRolePolicyDocument": quote(json.dumps(SERVICE)),
                    },
                ],
                "IsTruncated": False,
            },
        )
        iam.add_response(
            "list_attached_role_policies",
            {
                "AttachedPolicies": [
                    {
                        "PolicyName": "ReadOnlyAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    }
                ]
            },
            {"RoleName": "ci"},
        )
        iam.add_response("list_role_policies", {"PolicyNames": []}, {"RoleName": "ci"})
        sts.add_response(
            "get_caller_identity",
            {
                "Account": "111111111111",
                "Arn": "arn:aws:iam::111111111111:user/auditor",
                "UserId": "u",
            },
        )
        snapshot = collect(session)
    assert [r["RoleName"] for r in snapshot["aws"]["roles"]] == ["ci"]
    assert snapshot["aws"]["oidc_providers"][0]["ClientIDList"] == ["sts.amazonaws.com"]
