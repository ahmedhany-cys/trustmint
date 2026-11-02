"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

from trustmint import __version__, analyzer, platforms, selfcheck, sources, workflows
from trustmint.context import Context
from trustmint.model import SEVERITY_ORDER, Reach
from trustmint.report import RENDERERS, render_text

EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _context(args: argparse.Namespace, loaded: sources.Loaded) -> Context:
    context = loaded.context
    if args.context:
        data = json.loads(Path(args.context).read_text())
        context = context.merge(Context.from_dict(data.get("context", data)))
    if args.owner:
        context = context.merge(Context(owners=set(args.owner)))
    return context


def _jobs(specs: list[str]) -> list[workflows.OidcJob]:
    jobs = []
    for spec in specs or []:
        repo, sep, directory = spec.partition("=")
        if not sep or repo.count("/") != 1:
            raise sources.InputError(f"--workflows expects OWNER/REPO=DIR, got {spec!r}")
        if not Path(directory).is_dir():
            raise sources.InputError(f"--workflows: {directory} is not a directory")
        jobs += workflows.scan(repo, directory)
    return jobs


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.snapshot and not args.terraform_plan:
        print("trustmint scan: give at least one --snapshot or --terraform-plan", file=sys.stderr)
        return EXIT_USAGE
    loaded = sources.load(args.snapshot or [], args.terraform_plan or [])
    context = _context(args, loaded)
    report = analyzer.analyze(
        loaded.trusts, context, _jobs(args.workflows), loaded.inputs, loaded.skipped
    )
    if args.format == "text":
        color = args.output is None and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        text = render_text(report, color=color)
    else:
        text = RENDERERS[args.format](report)
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if args.fail_on != "never":
        limit = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) <= limit for f in report.findings):
            return EXIT_FINDINGS
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    loaded = sources.load(args.snapshot or [], args.terraform_plan or [])
    context = _context(args, loaded)
    matches = [t for t in loaded.trusts if args.identity in t.identity or args.identity == t.id]
    if not matches:
        print(f"no trust whose identity contains {args.identity!r}", file=sys.stderr)
        return EXIT_USAGE
    for trust in matches:
        platform = platforms.resolve(trust.issuer, context)
        print(f"{trust.identity}  [{trust.id}]")
        print(f"  issuer    {trust.issuer}  ->  {platform.label} (scope: {platform.scope})")
        print(f"  condition {trust.condition.describe()}")
        if trust.audience is not None:
            print(f"  audience  {trust.audience.describe()}")
        print(
            f"  privilege {trust.privilege.level.name.lower()} "
            f"({'; '.join(trust.privilege.evidence)})"
        )
        literals = analyzer._literals(trust)
        candidates = platform.candidates(trust, literals)
        if not candidates:
            print("  no token model for this issuer; see TM007\n")
            continue
        audiences = platform.audience_options(literals) if platform.controls_audience else [None]
        tiers: dict[Reach, list] = defaultdict(list)
        for candidate in candidates:
            verdict, claims = analyzer.check(trust, platform, candidate, audiences)
            tiers[candidate.reach].append((verdict, candidate, claims))
        print("  ladder (broadest first):")
        for reach in sorted(tiers, reverse=True):
            rows = tiers[reach]
            hits = [r for r in rows if r[0] is True]
            unknown = sum(1 for r in rows if r[0] is None)
            if hits:
                best = max(hits, key=lambda r: analyzer._rank(r[1]))
                print(
                    f"    {reach.name:<10} MATCH  {len(hits)}/{len(rows)} tokens, e.g. "
                    f"sub={best[2].get('sub')!r}"
                )
                print(f"               minted by {best[1].actor}")
            else:
                note = f", {unknown} undecided" if unknown else ""
                sample = rows[0][1].claims.get("sub")
                print(
                    f"    {reach.name:<10} no     0/{len(rows)} tokens{note}, e.g. rejected "
                    f"sub={sample!r}"
                )
        print()
    return 0


def cmd_selfcheck(args: argparse.Namespace) -> int:
    passed, failed, lines = selfcheck.run()
    for line in lines:
        if args.verbose or line.startswith("FAIL"):
            print(line)
    print(f"selfcheck: {passed} passed, {failed} failed")
    return 1 if failed else 0


def cmd_rules(args: argparse.Namespace) -> int:
    for rule_id, title in analyzer.RULES.items():
        print(f"{rule_id}  {title}")
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    try:
        import boto3
    except ImportError:
        print("collecting from AWS needs boto3: pip install 'trustmint[aws]'", file=sys.stderr)
        return EXIT_USAGE
    from trustmint.collect_aws import collect

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    snapshot = collect(session)
    Path(args.output).write_text(json.dumps(snapshot, indent=2, default=str) + "\n")
    print(
        f"wrote {len(snapshot['aws']['roles'])} roles with web identity trust to {args.output}",
        file=sys.stderr,
    )
    return 0


def _load_list(path: str) -> list:
    data = json.loads(Path(path).read_text())
    return data if isinstance(data, list) else [data]


def cmd_assemble(args: argparse.Namespace) -> int:
    snapshot: dict = {"schema": sources.SCHEMA}
    if args.context:
        data = json.loads(Path(args.context).read_text())
        snapshot["context"] = data.get("context", data)
    gcp: dict = {"providers": [], "service_accounts": []}
    for path in args.gcp_providers or []:
        gcp["providers"] += _load_list(path)
    for spec in args.gcp_sa_policy or []:
        email, _, path = spec.partition("=")
        gcp["service_accounts"].append(
            {"email": email, "iam_policy": json.loads(Path(path).read_text())}
        )
    if gcp["providers"] or gcp["service_accounts"]:
        snapshot["gcp"] = gcp
    identities = []
    for kind, specs in (("app", args.azure_app), ("managed_identity", args.azure_mi)):
        for spec in specs or []:
            name, _, path = spec.partition("=")
            identities.append(
                {"name": name, "kind": kind, "federated_credentials": _load_list(path)}
            )
    if identities:
        snapshot["azure"] = {"identities": identities}
    Path(args.output).write_text(json.dumps(snapshot, indent=2) + "\n")
    print(f"wrote snapshot to {args.output}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustmint",
        description="Find out who can mint a token your cloud trusts.",
    )
    parser.add_argument("--version", action="version", version=f"trustmint {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def inputs(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--snapshot",
            "-s",
            action="append",
            metavar="FILE",
            help="TrustMint snapshot JSON (repeatable)",
        )
        p.add_argument(
            "--terraform-plan",
            "-p",
            action="append",
            metavar="FILE",
            help="output of `terraform show -json plan.out` (repeatable)",
        )
        p.add_argument(
            "--context",
            "-c",
            metavar="FILE",
            help="context JSON: owners, repos, protected_refs, issuers",
        )
        p.add_argument(
            "--owner",
            action="append",
            metavar="NAME",
            help="an organization/group you own (repeatable)",
        )

    scan = sub.add_parser("scan", help="analyse trusts and report who can reach them")
    inputs(scan)
    scan.add_argument(
        "--workflows",
        "-w",
        action="append",
        metavar="OWNER/REPO=DIR",
        help="GitHub workflows to check for untrusted triggers (repeatable)",
    )
    scan.add_argument(
        "--format", "-f", choices=["text", "json", "markdown", "sarif"], default="text"
    )
    scan.add_argument("--output", "-o", metavar="FILE")
    scan.add_argument(
        "--fail-on",
        choices=[*SEVERITY_ORDER, "never"],
        default="high",
        help="exit 1 if a finding at or above this severity exists (default: high)",
    )
    scan.set_defaults(func=cmd_scan)

    explain = sub.add_parser("explain", help="show the reach ladder for one identity")
    inputs(explain)
    explain.add_argument("identity", help="identity name, ARN, email or substring")
    explain.set_defaults(func=cmd_explain)

    check = sub.add_parser("selfcheck", help="run the built-in scenarios with known answers")
    check.add_argument("--verbose", "-v", action="store_true")
    check.set_defaults(func=cmd_selfcheck)

    rules = sub.add_parser("rules", help="list rule IDs")
    rules.set_defaults(func=cmd_rules)

    collect = sub.add_parser("collect", help="read-only collection from a live account")
    collect.add_argument("cloud", choices=["aws"])
    collect.add_argument("--profile")
    collect.add_argument("--output", "-o", required=True)
    collect.set_defaults(func=cmd_collect)

    assemble = sub.add_parser("assemble", help="build a snapshot from gcloud / az CLI exports")
    assemble.add_argument(
        "--gcp-providers",
        action="append",
        metavar="FILE",
        help="gcloud iam workload-identity-pools providers describe/list JSON",
    )
    assemble.add_argument(
        "--gcp-sa-policy",
        action="append",
        metavar="EMAIL=FILE",
        help="gcloud iam service-accounts get-iam-policy JSON",
    )
    assemble.add_argument(
        "--azure-app",
        action="append",
        metavar="NAME=FILE",
        help="az ad app federated-credential list JSON",
    )
    assemble.add_argument(
        "--azure-mi",
        action="append",
        metavar="NAME=FILE",
        help="az identity federated-credential list JSON",
    )
    assemble.add_argument("--context", metavar="FILE")
    assemble.add_argument("--output", "-o", required=True)
    assemble.set_defaults(func=cmd_assemble)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except sources.InputError as exc:
        print(f"trustmint: {exc}", file=sys.stderr)
        return EXIT_USAGE
