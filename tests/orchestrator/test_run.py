"""End-to-end coverage of start_run() driving the whole graph, including a
regression test for the recon_node async / graph.invoke() sync mismatch:
start_run() must actually be able to drive the graph without LangGraph
raising "No synchronous function provided"."""

import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import yaml

from orchestrator.run import start_run

_EMPTY_NMAP_XML = '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'

_OPEN_PORT_NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http"/>
</port>
</host></nmaprun>"""

_CURL_RESPONSE = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><head><title>Home</title></head></html>"


def _write_config(tmp_path, allowed_categories: list[str]):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scan_profiles.yaml").write_text(
        yaml.safe_dump(
            {
                "recon_only": {
                    "description": "test profile",
                    "allowed_categories": allowed_categories,
                    "max_concurrent_branches": 2,
                    "rate_limit_per_target_rps": 0,
                }
            }
        )
    )

    now = datetime.now(timezone.utc)
    scope_record_path = tmp_path / "scope.yaml"
    scope_record_path.write_text(
        yaml.safe_dump(
            {
                "run_id": "run-test",
                "targets": [{"value": "10.0.0.5"}],
                "authorization": {"kind": "self_attestation", "reference_id": "t"},
                "time_window": {
                    "starts_at": (now - timedelta(hours=1)).isoformat(),
                    "ends_at": (now + timedelta(hours=1)).isoformat(),
                },
                "allowed_categories": allowed_categories,
            }
        )
    )
    return scope_record_path


async def test_start_run_drives_the_graph_without_async_sync_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda command, **kw: SimpleNamespace(returncode=0, stdout=_EMPTY_NMAP_XML, stderr=""))
    monkeypatch.chdir(tmp_path)

    scope_record_path = _write_config(tmp_path, ["port_scan"])

    # nmap finds nothing open, so the graph short-circuits at recon with an
    # empty fan-out -- this is enough to prove ainvoke() drives async nodes
    # correctly without exercising test_service/report as well.
    run_id = await start_run(str(scope_record_path))

    assert run_id
    assert (tmp_path / "audit_logs" / f"{run_id}.jsonl").exists()
    assert (tmp_path / "reports" / f"{run_id}.md").exists()


async def test_start_run_full_happy_path_produces_findings_and_report(monkeypatch, tmp_path):
    def fake_subprocess_run(command, **kwargs):
        if command[0] == "nmap":
            if "-sV" in command:
                return SimpleNamespace(returncode=0, stdout=_OPEN_PORT_NMAP_XML, stderr="")
            if "-sC" in command:
                return SimpleNamespace(returncode=0, stdout="PORT 80/tcp open http", stderr="")
            if "vuln" in command:
                return SimpleNamespace(returncode=0, stdout="(no vulns found)", stderr="")
        if command[0] == "curl":
            return SimpleNamespace(returncode=0, stdout=_CURL_RESPONSE, stderr="")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    monkeypatch.chdir(tmp_path)

    scope_record_path = _write_config(tmp_path, ["port_scan", "service_enum", "vuln_scan", "webapp_test"])

    run_id = await start_run(str(scope_record_path))

    report_text = (tmp_path / "reports" / f"{run_id}.md").read_text(encoding="utf-8")
    assert "Service enumeration for port 80" in report_text
    assert "HTTP service on port 80" in report_text
    assert "nginx" in report_text
