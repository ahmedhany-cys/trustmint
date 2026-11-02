import json

from trustmint.cli import main


def test_scan_exit_codes(acme_snapshot, capsys):
    assert main(["scan", "-s", acme_snapshot]) == 1
    assert main(["scan", "-s", acme_snapshot, "--fail-on", "never"]) == 0
    capsys.readouterr()


def test_scan_formats(acme_snapshot, acme_workflows, tmp_path):
    for fmt in ("json", "markdown", "sarif", "text"):
        out = tmp_path / f"report.{fmt}"
        main(
            [
                "scan",
                "-s",
                acme_snapshot,
                "-w",
                acme_workflows,
                "-f",
                fmt,
                "-o",
                str(out),
                "--fail-on",
                "never",
            ]
        )
        assert out.stat().st_size > 1000
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["summary"]["trusts"] == 20
    sarif = json.loads((tmp_path / "report.sarif").read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert all("security-severity" in r["properties"] for r in run["results"])


def test_explain_and_errors(acme_snapshot, capsys):
    assert main(["explain", "-s", acme_snapshot, "gh-org-admin"]) == 0
    out = capsys.readouterr().out
    assert "TENANT     MATCH" in out and "PUBLIC     no" in out
    assert main(["explain", "-s", acme_snapshot, "does-not-exist"]) == 2
    assert main(["scan", "-s", "missing.json"]) == 2
    assert main(["scan"]) == 2


def test_selfcheck_and_rules(capsys):
    assert main(["selfcheck"]) == 0
    assert "0 failed" in capsys.readouterr().out
    assert main(["rules"]) == 0


def test_assemble_round_trip(tmp_path, capsys):
    providers = tmp_path / "p.json"
    providers.write_text(
        json.dumps(
            [
                {
                    "name": "projects/1/locations/global/workloadIdentityPools/p/providers/gh",
                    "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                    "attributeMapping": {"google.subject": "assertion.sub"},
                }
            ]
        )
    )
    policy = tmp_path / "pol.json"
    policy.write_text(
        json.dumps(
            {
                "bindings": [
                    {
                        "role": "roles/iam.workloadIdentityUser",
                        "members": [
                            "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*"
                        ],
                    }
                ]
            }
        )
    )
    creds = tmp_path / "c.json"
    creds.write_text(
        json.dumps(
            [
                {
                    "name": "x",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:a/b:ref:refs/heads/main",
                    "audiences": ["api://AzureADTokenExchange"],
                }
            ]
        )
    )
    out = tmp_path / "snap.json"
    assert (
        main(
            [
                "assemble",
                "--gcp-providers",
                str(providers),
                "--gcp-sa-policy",
                f"sa@x={policy}",
                "--azure-app",
                f"app={creds}",
                "-o",
                str(out),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "scan",
                "-s",
                str(out),
                "-f",
                "json",
                "-o",
                str(tmp_path / "r.json"),
                "--fail-on",
                "never",
            ]
        )
        == 0
    )
    data = json.loads((tmp_path / "r.json").read_text())
    reaches = sorted(t["reach"] for t in data["trusts"])
    assert reaches == ["PROTECTED", "PUBLIC"]
