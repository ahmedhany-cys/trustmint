from trustmint import analyzer, sources, workflows
from trustmint.model import Reach

EXPECTED = {
    "arn:aws:iam::111122223333:role/gh-deploy-prod": "PROTECTED",
    "arn:aws:iam::111122223333:role/gh-ci-readonly": "PUBLIC",
    "arn:aws:iam::111122223333:role/gh-org-admin": "TENANT",
    "arn:aws:iam::111122223333:role/gh-release-main": "PUBLIC",
    "arn:aws:iam::111122223333:role/gh-infra-any-branch": "PROJECT",
    "arn:aws:iam::111122223333:role/gh-web-broken": "NONE",
    "arn:aws:iam::111122223333:role/gh-payments-immutable": "PROTECTED",
    "arn:aws:iam::111122223333:role/eks-payments-irsa": "PROJECT",
    "arn:aws:iam::111122223333:role/tfc-prod-network": "PROJECT",
    "arn:aws:iam::111122223333:role/circleci-deploy": "PROJECT",
    "arn:aws:iam::111122223333:role/google-sso-broker": None,
    "gitlab-deployer@acme-prod.iam.gserviceaccount.com": "PROTECTED",
    "projects/acme-artifacts": "PUBLIC",
    "payments-deployer": "PROTECTED",
    "platform-automation": "TENANT",
    "aks-orders-workload": "PROTECTED",
}


def report(snapshot, workflow_spec=None):
    loaded = sources.load([snapshot], [])
    jobs = []
    if workflow_spec:
        repo, _, path = workflow_spec.partition("=")
        jobs = workflows.scan(repo, path)
    return analyzer.analyze(loaded.trusts, loaded.context, jobs)


def test_demo_reach_per_identity(acme_snapshot):
    rep = report(acme_snapshot)
    seen = {}
    for result in rep.results:
        seen.setdefault(result.trust.identity, set()).add(
            result.reach.name if result.reach is not None else None
        )
    for identity, reach in EXPECTED.items():
        assert seen[identity] == {reach}, identity
    # One bad provider in a shared pool makes the pool-wide binding public.
    assert seen["analytics-reader@acme-prod.iam.gserviceaccount.com"] == {"PUBLIC", "TENANT"}


def test_witness_tokens_really_satisfy_the_trust(acme_snapshot):
    rep = report(acme_snapshot)
    for result in rep.results:
        if result.witness is None:
            continue
        claims = result.witness.claims
        assert result.trust.condition.evaluate(claims) is True
        if result.trust.audience is not None:
            assert result.trust.audience.evaluate(claims) is True


def test_prefix_typo_yields_lookalike_owner(acme_snapshot):
    rep = report(acme_snapshot)
    result = next(r for r in rep.results if r.trust.identity.endswith("gh-release-main"))
    owner = result.witness.claims["repository_owner"]
    assert owner.startswith("acme") and owner != "acme"


def test_subject_recycling_only_for_name_based_bindings(acme_snapshot):
    rep = report(acme_snapshot)
    recycled = {f.identity for f in rep.findings if f.rule_id == "TM005"}
    assert "deployer@acme-prod.iam.gserviceaccount.com" in recycled
    # Exact name-based AWS subjects stop matching once a recreated repo gets an immutable subject.
    assert "arn:aws:iam::111122223333:role/gh-deploy-prod" not in recycled
    assert "arn:aws:iam::111122223333:role/gh-payments-immutable" not in recycled


def test_pull_request_target_escalates_pinned_trusts(acme_snapshot, acme_workflows):
    rep = report(acme_snapshot, acme_workflows)
    tm004 = {f.identity: f for f in rep.findings if f.rule_id == "TM004"}
    pinned = tm004["arn:aws:iam::111122223333:role/gh-payments-immutable"]
    assert pinned.severity == "critical"
    assert "names this identity directly" in pinned.message
    # Environment-pinned trusts are not reachable from the pull_request_target job.
    assert "arn:aws:iam::111122223333:role/gh-deploy-prod" not in tm004
    # Trusts that are already public are not repeated.
    assert "arn:aws:iam::111122223333:role/gh-ci-readonly" not in tm004


def test_dead_trust_explains_literal_wildcard(acme_snapshot):
    rep = report(acme_snapshot)
    dead = next(f for f in rep.findings if f.rule_id == "TM006")
    assert "matched literally" in dead.message


def test_findings_sorted_by_severity(acme_snapshot):
    rep = report(acme_snapshot)
    order = ["critical", "high", "medium", "low", "info"]
    indexes = [order.index(f.severity) for f in rep.findings]
    assert indexes == sorted(indexes)


def test_reach_ordering():
    assert Reach.PUBLIC > Reach.TENANT > Reach.PROJECT > Reach.PROTECTED > Reach.NONE
