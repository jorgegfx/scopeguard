from tools.nikto import _parse_nikto_xml

_SAMPLE_XML = """<?xml version="1.0"?>
<niktoscan>
 <scandetails targetip="10.0.0.5" targetport="80">
  <item id="999955" osvdbid="3092">
    <description>/admin/: Admin login page/section found.</description>
    <uri>/admin/</uri>
  </item>
  <item id="999957">
    <description>Server leaks inodes via ETags.</description>
    <uri></uri>
  </item>
  <item id="000000"><description></description></item>
 </scandetails>
</niktoscan>
"""


def test_parse_extracts_items_with_uri_and_osvdb():
    items = _parse_nikto_xml(_SAMPLE_XML)

    assert len(items) == 2
    assert items[0].description.startswith("/admin/")
    assert items[0].uri == "/admin/"
    assert items[0].osvdb_id == "3092"
    assert items[1].uri is None


def test_parse_bad_xml_returns_empty():
    assert _parse_nikto_xml("<broken") == []
