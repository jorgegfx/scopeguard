import httpx

from tools import passive_recon
from tools.passive_recon import _parse_crt_sh, _parse_nslookup

_NSLOOKUP_OUTPUT = """Server:  dns.example.net
Address:  192.0.2.53

Name:    scan-target.example.com
Addresses:  2001:db8::1
          198.51.100.10
"""


def test_parse_nslookup_skips_server_and_keeps_answers():
    result = _parse_nslookup("scan-target.example.com", _NSLOOKUP_OUTPUT)

    assert result.addresses == ["2001:db8::1", "198.51.100.10"]


def test_parse_crt_sh_dedupes_and_filters_to_subdomains():
    data = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "example.com"},          # the apex itself is filtered out
        {"name_value": "other.org"},            # unrelated domain filtered out
    ]

    assert _parse_crt_sh(data, "example.com") == ["api.example.com", "www.example.com"]


async def test_crt_sh_subdomains_returns_empty_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        assert await passive_recon.crt_sh_subdomains("example.com", client=client) == []
