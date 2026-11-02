"""Render a :class:`~trustmint.analyzer.Report` as text, Markdown, JSON or SARIF."""

from __future__ import annotations

import json
from typing import Any

from trustmint import __version__
from trustmint.analyzer import RULES, Report
from trustmint.model import SEVERITY_ORDER, Reach, TrustResult

REACH_TEXT = {
    "PUBLIC": "anyone on the CI platform",
    "TENANT": "any repo/project in the org",
    "PROJECT": "unprotected refs in the repo",
    "PROTECTED": "protected refs only",
    "NONE": "nothing (dead trust)",
    None: "undecided",
}


def reach_name(result: TrustResult) -> str | None:
    return result.reach.name if result.reach is not None else None


def to_dict(report: Report) -> dict[str, Any]:
    return {
        "tool": "trustmint",
        "version": __version__,
        "inputs": report.inputs,
        "context": report.context.to_dict(),
        "summary": {
            "trusts": len(report.results),
            "findings": report.counts(),
            "reach": {
                name: sum(1 for r in report.results if reach_name(r) == name)
                for name in [*(m.name for m in reversed(Reach)), None]
            },
        },
        "trusts": [
            {
                "id": r.trust.id,
                "cloud": r.trust.cloud,
                "identity": r.trust.identity,
                "issuer": r.trust.issuer,
                "platform": r.platform,
                "kind": r.trust.kind,
                "reach": reach_name(r),
                "actor": r.witness.actor if r.witness else None,
                "privilege": r.trust.privilege.level.name.lower(),
                "condition": r.trust.condition.describe(),
                "witness": r.witness.claims if r.witness else None,
                "candidates_tried": r.candidates_tried,
                "undecided": r.undecided,
                "used_by": r.used_by,
                "source": r.trust.source,
            }
            for r in report.results
        ],
        "findings": [f.to_dict() for f in report.findings],
        "workflow_jobs": [job.__dict__ for job in report.jobs],
        "skipped": report.skipped,
    }


def render_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, default=str) + "\n"


# -- text ---------------------------------------------------------------------

COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def _paint(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color else text


def render_text(report: Report, color: bool = False, show_passing: bool = True) -> str:
    out: list[str] = []
    counts = report.counts()
    out.append(
        f"TrustMint {__version__}: {len(report.results)} federation trusts from "
        f"{', '.join(report.inputs) or 'no inputs'}"
    )
    if report.jobs:
        out.append(f"Workflow jobs with id-token: write: {len(report.jobs)}")
    out.append(
        "Findings: "
        + ", ".join(
            _paint(f"{counts[s]} {s}", COLORS[s], color and counts[s] > 0) for s in SEVERITY_ORDER
        )
    )
    out.append("")
    out.append("WHO CAN MINT A TOKEN EACH IDENTITY ACCEPTS")
    rows = sorted(
        report.results, key=lambda r: (-(r.reach if r.reach is not None else -1), r.trust.identity)
    )
    width = min(60, max((len(r.trust.identity) for r in rows), default=10))
    for r in rows:
        name = reach_name(r) or "UNDECIDED"
        if not show_passing and r.reach in (Reach.PROTECTED,):
            continue
        identity = r.trust.identity
        if len(identity) > width:
            identity = "..." + identity[-(width - 3) :]
        out.append(
            f"  {name:<10} {identity:<{width}}  {r.trust.cloud:<5} <- {r.platform:<10} "
            f"{r.trust.privilege.level.name.lower()}"
        )
    out.append("")
    for finding in report.findings:
        head = f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}"
        out.append(_paint(head, COLORS[finding.severity], color))
        if finding.identity:
            out.append(
                f"  identity : {finding.identity} ({finding.cloud or '-'}, "
                f"privilege {finding.privilege or 'n/a'})"
            )
        if finding.issuer:
            out.append(f"  issuer   : {finding.issuer} ({finding.platform})")
        out.append(f"  why      : {finding.message}")
        if finding.witness:
            out.append("  witness  :")
            for key, value in finding.witness.items():
                out.append(f"      {key} = {value}")
        for assumption in finding.assumptions:
            out.append(f"  assumes  : {assumption}")
        out.append(f"  fix      : {finding.remediation}")
        if finding.source:
            out.append(f"  source   : {finding.source}")
        out.append("")
    if report.skipped:
        out.append("Skipped (values unknown until apply):")
        out += [f"  - {s}" for s in report.skipped]
    return "\n".join(out).rstrip() + "\n"


# -- markdown -----------------------------------------------------------------


def _md(text: str) -> str:
    return text.replace("|", "\\|")


def render_markdown(report: Report) -> str:
    counts = report.counts()
    lines = [
        "# TrustMint report",
        "",
        f"{len(report.results)} federation trusts analysed from "
        + ", ".join(f"`{i}`" for i in report.inputs)
        + ".",
        "",
        "| Severity | Findings |",
        "|---|---|",
        *[f"| {s} | {counts[s]} |" for s in SEVERITY_ORDER],
        "",
        "## Reach per identity",
        "",
        "| Reach | Identity | Cloud | Issuer | Privilege | Who can mint a matching token |",
        "|---|---|---|---|---|---|",
    ]
    rows = sorted(
        report.results, key=lambda r: (-(r.reach if r.reach is not None else -1), r.trust.identity)
    )
    for r in rows:
        actor = r.witness.actor if r.witness else REACH_TEXT[reach_name(r)]
        lines.append(
            f"| **{reach_name(r) or 'UNDECIDED'}** | `{_md(r.trust.identity)}` | {r.trust.cloud} | "
            f"{r.platform} | {r.trust.privilege.level.name.lower()} | {_md(actor)} |"
        )
    lines += ["", "## Findings", ""]
    for finding in report.findings:
        lines.append(f"### {finding.severity.upper()} · {finding.rule_id} · {finding.title}")
        lines.append("")
        if finding.identity:
            lines.append(
                f"- **Identity:** `{finding.identity}` ({finding.cloud}, privilege "
                f"{finding.privilege})"
            )
        if finding.issuer:
            lines.append(f"- **Issuer:** `{finding.issuer}` ({finding.platform})")
        lines.append(f"- **Why:** {finding.message}")
        for assumption in finding.assumptions:
            lines.append(f"- **Assumes:** {assumption}")
        lines.append(f"- **Fix:** {finding.remediation}")
        if finding.source:
            lines.append(f"- **Source:** `{finding.source}`")
        if finding.witness:
            lines += ["", "```json", json.dumps(finding.witness, indent=2), "```"]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# -- SARIF ----------------------------------------------------------------------

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def render_sarif(report: Report) -> str:
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": title},
            "helpUri": f"https://github.com/ahmedhany-cys/trustmint/blob/main/docs/rules.md#{rule_id.lower()}",
            "properties": {"tags": ["security", "oidc", "workload-identity"]},
        }
        for rule_id, title in RULES.items()
    ]
    results = []
    for finding in report.findings:
        uri = (finding.source or "trustmint").split(" ", 1)[0].split("#", 1)[0]
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {
                    "text": (
                        f"{finding.identity or ''}: {finding.message} Fix: {finding.remediation}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {"artifactLocation": {"uri": uri}},
                        "logicalLocations": [
                            {"name": finding.identity or finding.source or "", "kind": "resource"}
                        ],
                    }
                ],
                "partialFingerprints": {
                    "trustmint/v1": f"{finding.rule_id}:{finding.trust_id or finding.source}"
                },
                "properties": {
                    "security-severity": SECURITY_SEVERITY[finding.severity],
                    "reach": finding.reach,
                    "witness": finding.witness,
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TrustMint",
                        "version": __version__,
                        "informationUri": "https://github.com/ahmedhany-cys/trustmint",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str) + "\n"


RENDERERS = {"json": render_json, "markdown": render_markdown, "sarif": render_sarif}
