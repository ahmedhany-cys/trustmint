from trustmint.conditions import AllOf, AnyOf, Match, Not, Unknown, glob_match


def test_glob_semantics_match_aws_string_like():
    assert glob_match("repo:acme/*", "repo:acme/app:ref:refs/heads/main")
    assert glob_match("repo:acme*", "repo:acmeevil/x:ref:refs/heads/main")
    assert glob_match("a?c", "abc")
    assert not glob_match("a?c", "ac")
    assert not glob_match("repo:acme/app", "repo:acme/app2")
    assert glob_match("[x]", "[x]")  # no character classes in AWS globs


def test_missing_claim_semantics():
    claims = {"sub": "x"}
    assert Match("ref", "equals", ("main",)).evaluate(claims) is False
    assert Match("ref", "equals", ("main",), if_exists=True).evaluate(claims) is True
    # ForAllValues on a missing key is vacuously true in AWS.
    assert Match("ref", "equals", ("main",), set_mode="all").evaluate(claims) is True
    assert Not(Match("ref", "equals", ("main",))).evaluate(claims) is True


def test_three_valued_logic():
    unknown = Unknown("not modeled")
    false = Match("sub", "equals", ("nope",))
    true = Match("sub", "equals", ("x",))
    claims = {"sub": "x"}
    assert AllOf([unknown, false]).evaluate(claims) is False
    assert AllOf([unknown, true]).evaluate(claims) is None
    assert AnyOf([unknown, true]).evaluate(claims) is True
    assert AnyOf([unknown, false]).evaluate(claims) is None
    assert Not(unknown).evaluate(claims) is None


def test_list_claims_match_any_element():
    node = Match("groups", "equals", ("admins",))
    assert node.evaluate({"groups": ["users", "admins"]}) is True
    assert (
        Match("groups", "equals", ("admins",), set_mode="all").evaluate(
            {"groups": ["users", "admins"]}
        )
        is False
    )


def test_ignore_case_and_literals():
    node = Match("sub", "equals", ("REPO:A/B",), ignore_case=True)
    assert node.evaluate({"sub": "repo:a/b"}) is True
    lits = list(Match("sub", "glob", ("repo:a/*", "repo:a/b")).literals())
    assert [lit.kind for lit in lits] == ["glob", "exact"]
