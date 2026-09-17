from agents.vuln_scan.agent import VulnScanAgent


class _FakeExecutor:
    pass


async def test_run_returns_finding_when_a_cve_is_flagged(monkeypatch):
    async def fake_scan_vulnerabilities(executor, target, port):
        return (
            "PORT   STATE SERVICE\n443/tcp open  https\n"
            "| vulners:\n"
            "|   cpe:/a:openssl:openssl:1.0.1:\n"
            "|     CVE-2014-0160  10.0  https://vulners.com/cve/CVE-2014-0160\n"
        )

    monkeypatch.setattr("agents.vuln_scan.agent.nmap.scan_vulnerabilities", fake_scan_vulnerabilities)

    agent = VulnScanAgent(agent_name="vuln_scan")
    findings = await agent.run(_FakeExecutor(), "10.0.0.5", 443, "https")

    assert len(findings) == 1
    assert findings[0].cve_ids == ["CVE-2014-0160"]
    assert findings[0].severity.value == "medium"


async def test_run_returns_nothing_when_no_vuln_indicator_present(monkeypatch):
    async def fake_scan_vulnerabilities(executor, target, port):
        return "PORT    STATE SERVICE\n443/tcp open  https\n(no vulns found)"

    monkeypatch.setattr("agents.vuln_scan.agent.nmap.scan_vulnerabilities", fake_scan_vulnerabilities)

    agent = VulnScanAgent(agent_name="vuln_scan")
    findings = await agent.run(_FakeExecutor(), "10.0.0.5", 443, "https")

    assert findings == []
