import httpx

from tools import cve_lookup
from tools.cve_lookup import _parse_nvd_response

_SAMPLE_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2018-15473",
                "descriptions": [
                    {"lang": "es", "value": "ignorado"},
                    {"lang": "en", "value": "OpenSSH user enumeration"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}
                    ]
                },
            }
        },
        {"cve": {"id": "CVE-0000-0000", "descriptions": [], "metrics": {}}},
    ]
}


def test_parse_extracts_english_description_and_cvss():
    matches = _parse_nvd_response(_SAMPLE_NVD)

    assert matches[0].cve_id == "CVE-2018-15473"
    assert matches[0].description == "OpenSSH user enumeration"
    assert matches[0].cvss_score == 5.3
    assert matches[0].severity == "MEDIUM"
    assert matches[1].cvss_score is None


async def test_lookup_returns_empty_without_product_or_version():
    assert await cve_lookup.lookup(None, "8.9") == []
    assert await cve_lookup.lookup("OpenSSH", None) == []


async def test_lookup_uses_injected_client_and_parses_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["keywordSearch"] == "OpenSSH 8.9"
        return httpx.Response(200, json=_SAMPLE_NVD)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        matches = await cve_lookup.lookup("OpenSSH", "8.9", client=client)

    assert matches[0].cve_id == "CVE-2018-15473"
