import pytest

from orchestrator.profiles import load_scan_profile


def test_load_scan_profile_reads_the_real_config():
    profile = load_scan_profile("recon_only", path="config/scan_profiles.yaml")

    assert profile.name == "recon_only"
    assert profile.max_concurrent_branches > 0
    assert "port_scan" in profile.allowed_categories


def test_load_scan_profile_raises_on_unknown_name():
    with pytest.raises(KeyError):
        load_scan_profile("not_a_real_profile", path="config/scan_profiles.yaml")
