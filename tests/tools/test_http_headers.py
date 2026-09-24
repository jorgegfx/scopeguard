from orchestrator.state import Severity
from tools.http_headers import analyze

_HARDENED = (
    "HTTP/1.1 200 OK\r\n"
    "Strict-Transport-Security: max-age=63072000\r\n"
    "Content-Security-Policy: default-src 'self'\r\n"
    "X-Frame-Options: DENY\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Referrer-Policy: no-referrer\r\n"
)

_WEAK = (
    "HTTP/1.1 200 OK\r\n"
    "Server: Apache/2.4.29\r\n"
    "Set-Cookie: session=abc123; Path=/\r\n"
)


def test_hardened_https_response_has_no_issues():
    assert analyze(_HARDENED, is_https=True) == []


def test_weak_response_flags_missing_headers_cookie_and_disclosure():
    issues = analyze(_WEAK, is_https=True)
    summaries = [i.summary for i in issues]

    assert any("HSTS" in s for s in summaries)
    assert any("Content-Security-Policy" in s for s in summaries)
    assert any("session" in s and "Secure" in s for s in summaries)
    assert any("version disclosure via server" in s for s in summaries)
    assert all(isinstance(i.severity, Severity) for i in issues)


def test_hsts_not_flagged_on_plain_http():
    issues = analyze("HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n", is_https=False)
    assert not any("HSTS" in i.summary for i in issues)
