import json

from trustmint.conditions import Unknown
from trustmint.sources import aws, azure, from_snapshot, terraform_plan


def test_aws_condition_keys_map_to_claims():
    node = aws.condition_tree(
        {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:a/*"}},
        "token.actions.githubusercontent.com",
    )
    assert node.evaluate({"sub": "repo:a/b:ref:refs/heads/main"}) is True
    assert node.evaluate({"sub": "repo:b/a"}) is False


def test_aws_unknown_operator_and_global_key_are_undecidable():
    node = aws.condition_tree(
        {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, "token.actions.githubusercontent.com"
    )
    assert node.evaluate({"sub": "x"}) is None


def test_aws_trust_policy_as_url_encoded_string():
    doc = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Principal": {"Federated": "arn:aws:iam::1:oidc-provider/gitlab.com"},
                }
            ]
        }
    )
    from urllib.parse import quote

    role = {"RoleName": "r", "Arn": "arn:aws:iam::1:role/r", "AssumeRolePolicyDocument": quote(doc)}
    trusts = aws.role_trusts(role, [], "test")
    assert len(trusts) == 1
    assert trusts[0].issuer == "https://gitlab.com"


def test_aws_ignores_non_web_identity_statements():
    role = {
        "Arn": "r",
        "AssumeRolePolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
    }
    assert aws.role_trusts(role, [], "t") == []


def test_azure_expression_parser():
    node = azure.parse_expression(
        "claims['sub'] matches 'repo:a/*' and (claims['x'] eq '1' or claims['x'] eq '2')"
    )
    assert node.evaluate({"sub": "repo:a/b", "x": "2"}) is True
    assert node.evaluate({"sub": "repo:a/b", "x": "3"}) is False
    assert isinstance(azure.parse_expression("claims['sub'] startswith 'a'"), Unknown)


def test_gcp_member_parsing_and_pool_matching():
    from trustmint.sources.gcp import parse_member

    base = "iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p"
    assert parse_member(f"principalSet://{base}/*")["kind"] == "all"
    assert parse_member(f"principalSet://{base}/attribute.repository/acme/app") == {
        "project": "1",
        "pool": "p",
        "kind": "attribute",
        "name": "repository",
        "value": "acme/app",
    }
    assert (
        parse_member(f"principal://{base}/subject/repo:a/b:ref:refs/heads/main")["value"]
        == "repo:a/b:ref:refs/heads/main"
    )
    assert parse_member("serviceAccount:x@y") is None


def test_terraform_plan_conversion(tmp_path):
    from pathlib import Path

    plan = json.loads(Path("examples/terraform/plan.json").read_text())
    snapshot, skipped = terraform_plan.to_snapshot(plan)
    loaded = from_snapshot(snapshot, "plan")
    clouds = sorted(t.cloud for t in loaded.trusts)
    assert clouds == ["aws", "azure", "gcp"]
    assert any("aws_iam_role.pending" in s for s in skipped)
    role = snapshot["aws"]["roles"][0]
    assert role["AttachedManagedPolicies"][0]["PolicyName"] == "AdministratorAccess"
