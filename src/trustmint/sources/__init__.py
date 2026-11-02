"""Load trusts from snapshots and Terraform plans."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from trustmint.context import Context
from trustmint.model import Trust
from trustmint.sources import aws, azure, gcp, terraform_plan

SCHEMA = "trustmint/snapshot@1"


class InputError(Exception):
    pass


@dataclass
class Loaded:
    trusts: list[Trust] = field(default_factory=list)
    context: Context = field(default_factory=Context)
    skipped: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise InputError(f"{path}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: not valid JSON ({exc})") from exc


def from_snapshot(data: dict, label: str) -> Loaded:
    schema = data.get("schema", SCHEMA)
    if schema != SCHEMA:
        raise InputError(f"{label}: unsupported schema {schema!r} (expected {SCHEMA})")
    loaded = Loaded(context=Context.from_dict(data.get("context")), inputs=[label])
    loaded.trusts += aws.load(data.get("aws", {}), label)
    loaded.trusts += gcp.load(data.get("gcp", {}), label)
    loaded.trusts += azure.load(data.get("azure", {}), label)
    return loaded


def load(snapshots: list[str], plans: list[str]) -> Loaded:
    result = Loaded()
    for path in snapshots:
        part = from_snapshot(_read_json(Path(path)), path)
        result.trusts += part.trusts
        result.context = result.context.merge(part.context)
        result.inputs += part.inputs
    for path in plans:
        data = _read_json(Path(path))
        if "planned_values" not in data:
            raise InputError(f"{path}: not a `terraform show -json` plan (no planned_values)")
        snapshot, skipped = terraform_plan.to_snapshot(data)
        part = from_snapshot(snapshot, path)
        result.trusts += part.trusts
        result.skipped += [f"{path}: {s}" for s in skipped]
        result.inputs.append(path)
    return result
