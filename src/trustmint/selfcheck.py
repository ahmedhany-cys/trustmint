"""Built-in scenarios with known answers, run by ``trustmint selfcheck``.

Each scenario is a snapshot plus the reach every trust must get. They pin
down the semantics most likely to regress: AWS operator behaviour, CEL, Entra
expressions, issuer scoping and wildcard tricks.
"""

from __future__ import annotations

import json
from importlib import resources

from trustmint import analyzer, sources


def scenarios() -> list[dict]:
    folder = resources.files("trustmint") / "scenarios"
    return [
        json.loads(item.read_text())
        for item in sorted(folder.iterdir(), key=lambda p: p.name)
        if item.name.endswith(".json")
    ]


def run() -> tuple[int, int, list[str]]:
    passed, failed, lines = 0, 0, []
    for scenario in scenarios():
        loaded = sources.from_snapshot(scenario["snapshot"], scenario["name"])
        report = analyzer.analyze(loaded.trusts, loaded.context)
        by_identity: dict[str, list[str]] = {}
        for result in report.results:
            reach = result.reach.name if result.reach is not None else "UNDECIDED"
            by_identity.setdefault(result.trust.identity, []).append(reach)
        for identity, expected in scenario["expect"].items():
            actual = by_identity.get(identity, ["MISSING"])
            # A string applies to every trust of the identity; a list lists them all.
            wanted = expected if isinstance(expected, list) else [expected] * len(actual)
            ok = sorted(actual) == sorted(wanted)
            passed += ok
            failed += not ok
            mark = "ok  " if ok else "FAIL"
            lines.append(
                f"{mark} {scenario['name']}: {identity} -> {'/'.join(actual)}"
                + ("" if ok else f" (expected {expected})")
            )
    return passed, failed, lines
