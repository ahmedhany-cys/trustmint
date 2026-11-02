from trustmint import workflows


def write(tmp_path, name, text):
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text)
    return str(tmp_path)


def test_detects_pull_request_target_with_head_checkout(tmp_path):
    root = write(
        tmp_path,
        "a.yml",
        """
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
      - uses: google-github-actions/auth@v2
        with: {workload_identity_provider: projects/1/locations/global/workloadIdentityPools/p/providers/gh}
""",
    )
    jobs = workflows.scan("acme/app", root)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.untrusted_triggers == ["pull_request_target"]
    assert job.runs_untrusted_code
    assert job.cloud_refs == ["projects/1/locations/global/workloadIdentityPools/p/providers/gh"]


def test_job_permissions_override_workflow_and_default_has_no_id_token(tmp_path):
    root = write(
        tmp_path,
        "b.yml",
        """
on: [push, workflow_run]
permissions: {id-token: write}
jobs:
  narrowed:
    permissions: {contents: read}
    runs-on: ubuntu-latest
    steps: [{run: echo}]
  inherited:
    runs-on: ubuntu-latest
    environment: {name: prod}
    steps: [{run: echo}]
""",
    )
    jobs = workflows.scan("acme/app", root)
    assert [j.job for j in jobs] == ["inherited"]
    assert jobs[0].environment == "prod"
    assert jobs[0].untrusted_triggers == ["workflow_run"]
    assert not jobs[0].runs_untrusted_code


def test_invalid_yaml_is_skipped(tmp_path):
    root = write(tmp_path, "c.yml", "on: [push\n")
    assert workflows.scan("acme/app", root) == []
