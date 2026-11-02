from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


@pytest.fixture
def acme_snapshot() -> str:
    return str(EXAMPLES / "acme" / "snapshot.json")


@pytest.fixture
def acme_workflows() -> str:
    return f"acme/payments-api={EXAMPLES / 'acme' / 'workflows' / 'payments-api'}"
