from tools.nmap import _parse_nmap_xml

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<port protocol="tcp" portid="22">
  <state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.9"/>
</port>
<port protocol="tcp" portid="80">
  <state state="open"/>
  <service name="http"/>
</port>
<port protocol="tcp" portid="139">
  <state state="closed"/>
  <service name="netbios-ssn"/>
</port>
</host>
</nmaprun>
"""


def test_parse_nmap_xml_extracts_only_open_ports():
    ports = _parse_nmap_xml(_SAMPLE_XML)

    assert len(ports) == 2
    assert ports[0].port == 22
    assert ports[0].service == "ssh"
    assert ports[0].product == "OpenSSH"
    assert ports[0].version == "8.9"
    assert ports[1].port == 80
    assert ports[1].product is None


def test_parse_nmap_xml_with_no_ports_returns_empty_list():
    assert _parse_nmap_xml("<?xml version='1.0'?><nmaprun><host></host></nmaprun>") == []
