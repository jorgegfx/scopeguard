from tools.curl import _parse_curl_output

_SAMPLE_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.25.0\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<html><head><title>Welcome</title></head><body></body></html>"
)


def test_parse_curl_output_extracts_status_server_and_title():
    result = _parse_curl_output("http://10.0.0.5:80/", _SAMPLE_RESPONSE)

    assert result.status_line == "HTTP/1.1 200 OK"
    assert result.server_header == "nginx/1.25.0"
    assert result.title == "Welcome"


def test_parse_curl_output_handles_missing_title_and_server():
    raw = "HTTP/1.1 404 Not Found\r\n\r\nnot found"
    result = _parse_curl_output("http://10.0.0.5:80/missing", raw)

    assert result.status_line == "HTTP/1.1 404 Not Found"
    assert result.server_header is None
    assert result.title is None
