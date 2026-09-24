from tools.nuclei import _parse_nuclei_jsonl

_SAMPLE_JSONL = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical",'
    '"description":"log4shell","classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0}},'
    '"matched-at":"http://10.0.0.5:8080/"}\n'
    '{"template-id":"tech-detect","info":{"name":"nginx","severity":"info"},"host":"10.0.0.5"}\n'
    "not-json-noise\n"
)


def test_parse_extracts_findings_with_cve_and_cvss():
    results = _parse_nuclei_jsonl(_SAMPLE_JSONL)

    assert len(results) == 2
    first = results[0]
    assert first.template_id == "CVE-2021-44228"
    assert first.severity == "critical"
    assert first.cve_ids == ["CVE-2021-44228"]
    assert first.cvss_score == 10.0
    assert first.matched_at == "http://10.0.0.5:8080/"


def test_parse_tolerates_missing_classification_and_bad_lines():
    results = _parse_nuclei_jsonl(_SAMPLE_JSONL)

    second = results[1]
    assert second.name == "nginx"
    assert second.cve_ids == []
    assert second.cvss_score is None
    assert second.matched_at == "10.0.0.5"


def test_parse_empty_returns_empty():
    assert _parse_nuclei_jsonl("") == []
