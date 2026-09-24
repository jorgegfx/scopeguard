"""TLS configuration assessment via sslscan.

Reports weak protocol versions, weak/anonymous/null ciphers, and certificate
problems (expired / self-signed). This is passive inspection of what the
server offers -- no exploitation. Runs under the VULN_SCAN category.

sslscan output varies between versions; we parse its XML (`--xml=-`) and are
deliberately lenient about missing elements.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from scope.models import TestCategory
from tools.base import ToolExecutor

TLS_TIMEOUT_SECONDS = 300.0

# Protocol versions considered outdated. TLS 1.2+ is the modern baseline.
_WEAK_PROTOCOLS = {("ssl", "2.0"), ("ssl", "3.0"), ("tls", "1.0"), ("tls", "1.1")}
_WEAK_CIPHER_STRENGTHS = {"null", "weak", "anonymous"}


@dataclass
class TlsResult:
    host: str
    port: int
    weak_protocols: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    certificate_issues: list[str] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.weak_protocols or self.weak_ciphers or self.certificate_issues)


async def scan(executor: ToolExecutor, target: str, port: int = 443) -> TlsResult:
    result = await executor.run(
        target=target,
        category=TestCategory.VULN_SCAN,
        command=["sslscan", "--no-colour", "--xml=-", f"{target}:{port}"],
        timeout=TLS_TIMEOUT_SECONDS,
    )
    return _parse_sslscan_xml(result.stdout, target, port)


def _parse_sslscan_xml(xml_text: str, host: str, port: int) -> TlsResult:
    res = TlsResult(host=host, port=port)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return res

    for proto in root.iter("protocol"):
        if proto.get("enabled") != "1":
            continue
        ptype = (proto.get("type") or "").lower()
        version = proto.get("version") or ""
        if (ptype, version) in _WEAK_PROTOCOLS:
            res.weak_protocols.append(f"{ptype.upper()} {version}")

    for cipher in root.iter("cipher"):
        strength = (cipher.get("strength") or "").lower()
        if strength in _WEAK_CIPHER_STRENGTHS:
            name = cipher.get("cipher") or "?"
            sslversion = cipher.get("sslversion") or ""
            res.weak_ciphers.append(f"{name} ({sslversion}, {strength})")

    for cert in root.iter("certificate"):
        self_signed = cert.findtext("self-signed")
        if self_signed and self_signed.lower() == "true":
            res.certificate_issues.append("certificate is self-signed")
        expired = cert.findtext("expired")
        if expired and expired.lower() == "true":
            res.certificate_issues.append("certificate is expired")

    return res
