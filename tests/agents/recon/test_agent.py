from agents.recon.agent import ReconAgent
from tools.nmap import OpenPort


class _FakeExecutor:
    """ReconAgent only threads this through to tools.nmap.scan_target, which
    is monkeypatched below -- no real ToolExecutor/subprocess needed."""


async def test_run_maps_open_ports_to_service_targets(monkeypatch):
    async def fake_scan_target(executor, target):
        return [
            OpenPort(port=22, protocol="tcp", service="ssh", product="OpenSSH", version="8.9"),
            OpenPort(port=443, protocol="tcp", service="https", product=None, version=None),
        ]

    monkeypatch.setattr("agents.recon.agent.nmap.scan_target", fake_scan_target)

    agent = ReconAgent(agent_name="recon")
    result = await agent.run(_FakeExecutor(), "10.0.0.5")

    assert result == [
        {"target": "10.0.0.5", "port": 22, "service": "ssh"},
        {"target": "10.0.0.5", "port": 443, "service": "https"},
    ]


async def test_run_returns_empty_list_when_no_ports_open(monkeypatch):
    async def fake_scan_target(executor, target):
        return []

    monkeypatch.setattr("agents.recon.agent.nmap.scan_target", fake_scan_target)

    agent = ReconAgent(agent_name="recon")
    result = await agent.run(_FakeExecutor(), "10.0.0.9")

    assert result == []
