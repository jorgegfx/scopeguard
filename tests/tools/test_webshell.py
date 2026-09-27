from tools.webshell import Confidence, _match_signatures, _parse_ffuf_json

_SAMPLE_FFUF_JSON = """
{
  "results": [
    {"input": {"FUZZ": "c99.php"}, "url": "http://10.0.0.5/c99.php", "status": 200, "length": 5120},
    {"input": {"FUZZ": "uploads/shell.php"}, "url": "http://10.0.0.5/uploads/shell.php", "status": 403, "length": 12}
  ]
}
"""

# A stripped-down snippet of what a c99 shell's landing page looks like.
_C99_BODY = """
<html><head><title>!C99Shell v. 1.0 pre-release build</title></head>
<body>Safe-mode: OFF (not secure)
<form method=post>Execute command: <input name="cmd" type=text></form>
</body></html>
"""

_BENIGN_BODY = "<html><head><title>Welcome</title></head><body>Under construction</body></html>"


def test_parse_ffuf_json_extracts_candidate_paths():
    candidates = _parse_ffuf_json(_SAMPLE_FFUF_JSON)

    assert len(candidates) == 2
    assert candidates[0].path == "c99.php"
    assert candidates[0].status == 200
    assert candidates[1].path == "uploads/shell.php"
    assert candidates[1].status == 403


def test_parse_ffuf_json_empty_or_bad_input():
    assert _parse_ffuf_json("") == []
    assert _parse_ffuf_json('{"results": []}') == []
    assert _parse_ffuf_json("not json") == []


def test_match_signatures_flags_a_known_shell_body():
    matched = _match_signatures(_C99_BODY)

    # Should catch the c99 banner, the safe-mode line and the cmd form field.
    assert "c99shell" in matched
    assert "safe-mode bypass banner" in matched
    assert "command-execution form field" in matched


def test_match_signatures_ignores_a_benign_page():
    assert _match_signatures(_BENIGN_BODY) == []


def test_match_signatures_empty_body():
    assert _match_signatures("") == []


def test_confidence_values():
    # Guard the string values the report/graph layer renders.
    assert Confidence.HIGH.value == "high"
    assert Confidence.MEDIUM.value == "medium"
