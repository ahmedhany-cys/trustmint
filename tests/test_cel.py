import pytest

from trustmint import cel


def run(expr, **env):
    return cel.evaluate(cel.parse(expr), env)


def test_comparisons_and_logic():
    a = {"repository_owner": "acme", "ref": "refs/heads/main"}
    assert run(
        "assertion.repository_owner == 'acme' && assertion.ref == 'refs/heads/main'", assertion=a
    )
    assert not run("assertion.repository_owner != 'acme' || false", assertion=a)
    assert run("assertion['repository_owner'] in ['acme', 'other']", assertion=a)
    assert run("!(assertion.ref == 'refs/heads/dev')", assertion=a)


def test_string_methods_and_concat():
    a = {"repository": "acme/app", "ref": "refs/heads/main"}
    assert run("assertion.repository.startsWith('acme/')", assertion=a)
    assert run("assertion.repository.endsWith('/app')", assertion=a)
    assert run("assertion.repository.contains('me/a')", assertion=a)
    assert run("assertion.ref.matches('^refs/heads/(main|release)$')", assertion=a)
    assert (
        run("assertion.repository + '@' + assertion.ref", assertion=a) == "acme/app@refs/heads/main"
    )
    assert run("size(assertion.repository) == 8", assertion=a)
    assert run("has(assertion.ref) && !has(assertion.environment)", assertion=a)


def test_missing_key_is_a_runtime_error_but_short_circuit_absorbs_it():
    with pytest.raises(cel.CelError):
        run("assertion.environment == 'prod'", assertion={})
    assert run("true || assertion.environment == 'prod'", assertion={}) is True
    assert run("assertion.environment == 'prod' && false", assertion={}) is False


def test_unsupported_constructs_are_flagged():
    with pytest.raises(cel.CelUnsupported):
        run("assertion.sub.extract('{x}') == 'a'", assertion={"sub": "a"})
    with pytest.raises(cel.CelUnsupported):
        cel.parse("assertion.sub ? 1 : 2")
