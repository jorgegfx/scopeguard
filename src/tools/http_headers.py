"""HTTP security-header and cookie analysis.

Pure analysis over headers already fetched by tools.curl.probe -- it issues
no request of its own, so there is nothing here to gate through
scope.checker: the fetch that produced these headers was already authorized
(WEBAPP_TEST) when curl ran. This just interprets the response.

Checks for missing hardening headers, insecure cookie flags, and version
disclosure. Everything reported here is INFO/LOW-severity hygiene, not an
exploitable finding.
"""

from __future__ import annotations

from dataclasses import dataclass

from orchestrator.state import Severity

# header name (lowercased) -> what its absence means
_EXPECTED_HEADERS = {
    "strict-transport-security": "HSTS not set (no enforced-HTTPS policy)",
    "content-security-policy": "no Content-Security-Policy (weaker XSS/injection defence)",
    "x-frame-options": "no X-Frame-Options / frame-ancestors (clickjacking exposure)",
    "x-content-type-options": "no X-Content-Type-Options: nosniff (MIME-sniffing risk)",
    "referrer-policy": "no Referrer-Policy set",
}

# headers whose mere presence leaks stack/version detail
_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


@dataclass
class HeaderIssue:
    summary: str
    severity: Severity


def _parse_headers(raw_headers: str) -> list[tuple[str, str]]:
    """Return (lowercased-name, value) pairs, skipping the status line."""
    pairs: list[tuple[str, str]] = []
    for line in raw_headers.splitlines():
        if ":" not in line:
            continue  # status line or blank
        name, _, value = line.partition(":")
        pairs.append((name.strip().lower(), value.strip()))
    return pairs


def analyze(raw_headers: str, *, is_https: bool) -> list[HeaderIssue]:
    pairs = _parse_headers(raw_headers)
    present = {name for name, _ in pairs}
    issues: list[HeaderIssue] = []

    for header, message in _EXPECTED_HEADERS.items():
        # HSTS is only meaningful over TLS; don't flag it on plain HTTP.
        if header == "strict-transport-security" and not is_https:
            continue
        if header not in present:
            issues.append(HeaderIssue(summary=message, severity=Severity.LOW))

    for name, value in pairs:
        if name == "set-cookie":
            lowered = value.lower()
            flags = []
            if "secure" not in lowered:
                flags.append("Secure")
            if "httponly" not in lowered:
                flags.append("HttpOnly")
            if flags:
                cookie_name = value.split("=", 1)[0].strip()
                issues.append(
                    HeaderIssue(
                        summary=f"cookie {cookie_name!r} missing {', '.join(flags)} flag(s)",
                        severity=Severity.LOW,
                    )
                )

    for name, value in pairs:
        if name in _DISCLOSURE_HEADERS and value:
            issues.append(
                HeaderIssue(summary=f"version disclosure via {name}: {value!r}", severity=Severity.INFO)
            )

    return issues
