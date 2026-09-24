from tools.content_discovery import _parse_ffuf_json

_SAMPLE_JSON = """
{
  "results": [
    {"input": {"FUZZ": "admin"}, "url": "http://10.0.0.5/admin", "status": 401, "length": 12},
    {"input": {"FUZZ": ".env"}, "url": "http://10.0.0.5/.env", "status": 200, "length": 340}
  ]
}
"""


def test_parse_extracts_discovered_paths():
    found = _parse_ffuf_json(_SAMPLE_JSON)

    assert len(found) == 2
    assert found[0].path == "admin"
    assert found[0].status == 401
    assert found[1].path == ".env"
    assert found[1].length == 340


def test_parse_empty_or_no_results():
    assert _parse_ffuf_json("") == []
    assert _parse_ffuf_json('{"results": []}') == []
    assert _parse_ffuf_json("not json") == []
