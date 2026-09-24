from tools.tls import _parse_sslscan_xml

_SAMPLE_XML = """<?xml version="1.0"?>
<document>
 <ssltest host="10.0.0.5" port="443">
  <protocol type="ssl" version="3.0" enabled="1"/>
  <protocol type="tls" version="1.0" enabled="1"/>
  <protocol type="tls" version="1.2" enabled="1"/>
  <protocol type="tls" version="1.3" enabled="0"/>
  <cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="DES-CBC3-SHA" strength="weak"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="AES256-GCM-SHA384" strength="strong"/>
  <certificate>
    <self-signed>true</self-signed>
    <expired>false</expired>
  </certificate>
 </ssltest>
</document>
"""


def test_parse_flags_weak_protocols_ciphers_and_cert():
    result = _parse_sslscan_xml(_SAMPLE_XML, "10.0.0.5", 443)

    assert result.weak_protocols == ["SSL 3.0", "TLS 1.0"]
    assert result.weak_ciphers == ["DES-CBC3-SHA (TLSv1.0, weak)"]
    assert result.certificate_issues == ["certificate is self-signed"]
    assert result.has_issues


def test_parse_clean_config_has_no_issues():
    clean = '<document><ssltest host="h" port="443">' \
            '<protocol type="tls" version="1.2" enabled="1"/></ssltest></document>'
    result = _parse_sslscan_xml(clean, "h", 443)

    assert not result.has_issues


def test_parse_bad_xml_returns_empty_result():
    result = _parse_sslscan_xml("not xml", "h", 443)
    assert not result.has_issues
