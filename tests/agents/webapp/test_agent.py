from agents.webapp.agent import WebAppAgent
from tools.curl import HttpProbeResult


class _FakeExecutor:
    pass


async def test_run_wraps_http_probe_as_info_finding(monkeypatch):
    async def fake_probe(executor, target, port, scheme="http"):
        assert scheme == "http"
        return HttpProbeResult(
            url="http://10.0.0.5:80/",
            status_line="HTTP/1.1 200 OK",
            server_header="nginx",
            title="Welcome",
            raw_headers="HTTP/1.1 200 OK\r\nServer: nginx",
        )

    monkeypatch.setattr("agents.webapp.agent.curl.probe", fake_probe)

    agent = WebAppAgent(agent_name="webapp")
    findings = await agent.run(_FakeExecutor(), "10.0.0.5", 80)

    assert len(findings) == 1
    assert "nginx" in findings[0].description
    assert "Welcome" in findings[0].description


async def test_run_uses_https_scheme_for_port_443(monkeypatch):
    async def fake_probe(executor, target, port, scheme="http"):
        assert scheme == "https"
        return HttpProbeResult(url="https://10.0.0.5:443/", status_line=None, server_header=None, title=None, raw_headers="")

    monkeypatch.setattr("agents.webapp.agent.curl.probe", fake_probe)

    agent = WebAppAgent(agent_name="webapp")
    await agent.run(_FakeExecutor(), "10.0.0.5", 443)
