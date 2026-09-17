from agents.service_enum.agent import ServiceEnumAgent


class _FakeExecutor:
    pass


async def test_run_wraps_nmap_output_as_info_finding(monkeypatch):
    async def fake_enumerate_service(executor, target, port):
        return "PORT   STATE SERVICE\n22/tcp open  ssh"

    monkeypatch.setattr("agents.service_enum.agent.nmap.enumerate_service", fake_enumerate_service)

    agent = ServiceEnumAgent(agent_name="service_enum")
    findings = await agent.run(_FakeExecutor(), "10.0.0.5", 22, "ssh")

    assert len(findings) == 1
    assert findings[0].severity.value == "info"
    assert "22" in findings[0].title
    assert "ssh" in findings[0].evidence
