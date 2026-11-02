from trustmint import analyzer, platforms
from trustmint.conditions import Match
from trustmint.context import Context
from trustmint.model import Reach, Trust


def trust(issuer, sub_pattern, op="glob", cloud="aws"):
    return Trust(
        id="t", cloud=cloud, identity="t", issuer=issuer, condition=Match("sub", op, (sub_pattern,))
    )


def reach(issuer, pattern, op="glob", context=None):
    result = analyzer.analyze_trust(trust(issuer, pattern, op), context or Context())
    return result.reach


GH = "https://token.actions.githubusercontent.com"


def test_github_inference_without_context():
    assert reach(GH, "repo:acme/*") == Reach.TENANT
    assert reach(GH, "repo:acme/app:*") == Reach.PROJECT
    assert reach(GH, "repo:*") == Reach.PUBLIC
    assert reach(GH, "repo:acme/app:ref:refs/heads/main", "equals") == Reach.PROTECTED


def test_declared_owners_expose_lookalike_pins():
    ctx = Context(owners={"acme"})
    assert reach(GH, "repo:acme-tools/app:ref:refs/heads/main", "equals", ctx) == Reach.PUBLIC


def test_declared_protected_refs_override_defaults():
    ctx = Context(owners={"acme"}, protected_refs={"acme/app": {"release"}})
    assert reach(GH, "repo:acme/app:ref:refs/heads/main", "equals", ctx) == Reach.PROJECT


def test_ghes_issuer_declared_in_context_is_capped_to_tenant():
    issuer = "https://ghe.example.com/_services/token"
    ctx = Context(issuers={issuer: {"platform": "github", "scope": "tenant"}})
    assert reach(issuer, "repo:*", context=ctx) == Reach.TENANT


def test_gitlab_subgroups_and_protection():
    gl = "https://gitlab.com"
    assert reach(gl, "project_path:acme/*") == Reach.TENANT
    assert reach(gl, "project_path:acme/team/api:ref_type:branch:ref:*") == Reach.PROJECT
    assert reach(gl, "project_path:acme*") == Reach.PUBLIC


def test_terraform_phases():
    tf = "https://app.terraform.io"
    assert reach(tf, "organization:acme:project:p:workspace:w:run_phase:*") == Reach.PROJECT
    assert (
        reach(tf, "organization:acme:project:p:workspace:w:run_phase:apply", "equals")
        == Reach.PROTECTED
    )
    assert reach(tf, "organization:*") == Reach.PUBLIC


def test_kubernetes_tiers():
    eks = "https://oidc.eks.us-east-1.amazonaws.com/id/ABC123"
    assert reach(eks, "system:serviceaccount:*") == Reach.TENANT
    assert reach(eks, "system:serviceaccount:ns:*") == Reach.PROJECT
    assert reach(eks, "system:serviceaccount:ns:sa", "equals") == Reach.PROTECTED


def test_resolve_issuers():
    ctx = Context()
    assert platforms.resolve(GH, ctx).scope == "public"
    assert platforms.resolve(GH + "/acme-ent", ctx).scope == "tenant"
    assert platforms.resolve("https://oidc.circleci.com/org/abc", ctx).name == "circleci"
    assert platforms.resolve("https://example.com", ctx).name == "generic"


def test_no_impossible_branch_names_in_witnesses():
    result = analyzer.analyze_trust(trust(GH, "repo:acme*:ref:refs/heads/main"), Context())
    for value in [result.witness.claims["ref"]]:
        assert ":" not in value.removeprefix("refs/heads/")
