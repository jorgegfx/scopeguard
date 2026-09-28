"""Metasploit Framework wrapper -- parameterized, scope-gated module runner.

The agent chooses *what* to do (which module, which options); it does NOT get
to hand us a free-form command string. That distinction is deliberate and is
the whole reason this tool can exist in ScopeGuard at all (see CLAUDE.md's
"authorization-first" principle):

  * The target flows through as an explicit argument, so `RHOSTS` is set by us
    from the scope-validated `target` -- never lifted out of an agent-authored
    string. `executor.run()` validates that same target against the scope
    record before msfconsole is ever spawned.
  * The required TestCategory is *derived from the module's family prefix*
    (`auxiliary/` -> AUX_SCAN, `exploit/` -> EXPLOIT), not passed in by the
    caller, so an agent cannot run an exploit module while only AUX_SCAN was
    authorized. This is the "don't let an agent escalate itself into a more
    invasive category than what was authorized" rule, enforced in code.
  * Metasploit is active exploitation -- the most invasive thing in this repo.
    Both categories are opt-in: no default scan profile enables them (see
    config/scan_profiles.yaml `active_exploit`). Clearly-destructive module
    families (payloads on their own, post-exploitation, DoS) are refused
    outright regardless of authorization.

Two entry points:

  * run_module(): parameterized -- category derived from the module family,
    destructive families refused. The tightest option.
  * run_command(): open-ended -- the agent authors the full msfconsole
    directive sequence, gated by the profile via the EXPLOIT category. Still
    target-bound: RHOSTS is injected from the scope-validated target and the
    agent cannot re-target or select a DoS module. Turned on only by a scan
    profile that enables `exploit` (config/scan_profiles.yaml `active_exploit`).
"""

from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from scope.models import TestCategory
from tools.base import ToolExecutor, ToolResult

# msfconsole startup + a single module run is slow relative to curl; give it a
# real budget. Overridable via config/tools.yaml key "msfconsole".
MSFCONSOLE_TIMEOUT_SECONDS = 900.0

# Module names msfconsole accepts are lowercase paths; keep the charset tight
# so a module string can't smuggle shell/resource-script metacharacters.
_MODULE_RE = re.compile(r"^[a-z0-9][a-z0-9_./-]*$")

# Only discovery/verification-shaped families are runnable, and each maps to
# the category that authorize() must have granted for it.
_FAMILY_CATEGORY = {
    "auxiliary/": TestCategory.AUX_SCAN,
    "exploit/": TestCategory.EXPLOIT,
}

# Families refused outright -- destructive or out-of-remit regardless of what
# the scope record says. Delivering a standalone payload, post-exploitation,
# encoders/nops/evasion (only useful to weaponize delivery) and anything under
# a /dos/ path are all off the table for the default toolset (CLAUDE.md).
_DENIED_PREFIXES = ("payload/", "post/", "encoder/", "nop/", "evasion/")
_DENIED_SUBSTRINGS = ("/dos/",)

# Option keys are msf datastore names; values must not contain newlines (which
# would let an agent append extra resource-script commands after the `set`).
_OPTION_KEY_RE = re.compile(r"^[A-Za-z0-9_]+$")

# We own RHOSTS -- it is derived from the scope-validated target and any
# caller-supplied value for it is dropped rather than trusted.
_RESERVED_OPTIONS = {"RHOSTS", "RHOST"}

# msfconsole `check` (safe verification) vs `run` (actually fire the module).
_ACTIONS = ("run", "check")

# In the open-ended runner (run_command), the agent authors the msfconsole
# directives freely EXCEPT the target: RHOSTS/RHOST is set by us from the
# scope-validated target, so a `set rhosts ...` line is refused rather than
# allowed to re-point the run past the scope gate.
_SET_RHOST_RE = re.compile(r"^\s*set(g)?\s+rhosts?\b", re.IGNORECASE)

# `use <module>` lines are inspected only to keep DoS modules out -- flooding a
# host is a denial-of-service, refused regardless of profile/authorization.
_USE_MODULE_RE = re.compile(r"^\s*use\s+(\S+)", re.IGNORECASE)


@dataclass
class ModuleResult:
    module: str
    action: str
    target: str
    returncode: int
    session_opened: bool
    signals: list[str] = field(default_factory=list)
    raw_output: str = ""


def category_for_module(module: str) -> TestCategory:
    """Resolve the TestCategory a module requires, or raise ValueError if the
    module is malformed or belongs to a denied/unknown family.

    Kept public and side-effect-free so callers (and tests) can check a
    module's category without running anything.
    """
    module = module.strip()
    if not _MODULE_RE.match(module):
        raise ValueError(f"invalid module name: {module!r}")
    if any(module.startswith(p) for p in _DENIED_PREFIXES) or any(
        s in module for s in _DENIED_SUBSTRINGS
    ):
        raise ValueError(f"module family is not permitted: {module!r}")
    for prefix, category in _FAMILY_CATEGORY.items():
        if module.startswith(prefix):
            return category
    raise ValueError(
        f"module family is not runnable via this tool: {module!r} "
        f"(allowed: {', '.join(sorted(_FAMILY_CATEGORY))})"
    )


def _validate_options(options: dict[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in options.items():
        if key.upper() in _RESERVED_OPTIONS:
            # Silently ignoring would hide intent; refuse so the caller learns
            # RHOSTS is not theirs to set.
            raise ValueError(f"option {key!r} is set from the scope target, not the caller")
        if not _OPTION_KEY_RE.match(key):
            raise ValueError(f"invalid option name: {key!r}")
        svalue = str(value)
        if "\n" in svalue or "\r" in svalue:
            raise ValueError(f"option {key!r} value must not contain newlines")
        clean[key] = svalue
    return clean


def build_resource_script(
    module: str,
    target: str,
    options: dict[str, str],
    action: str,
    port: int | None,
) -> str:
    """Assemble the msfconsole resource (-r) script.

    RHOSTS is always our scope-validated target; RPORT is set from `port` when
    given. The caller's options are appended after, minus the reserved ones.
    """
    lines = [f"use {module}", f"set RHOSTS {target}"]
    if port is not None:
        lines.append(f"set RPORT {int(port)}")
    for key, value in options.items():
        lines.append(f"set {key} {value}")
    lines.append(action)
    lines.append("exit")
    return "\n".join(lines) + "\n"


async def run_module(
    executor: ToolExecutor,
    target: str,
    module: str,
    options: dict[str, str] | None = None,
    port: int | None = None,
    action: str = "run",
) -> ModuleResult:
    """Run a single Metasploit module against a scope-validated target.

    The agent picks `module` and `options`; the category is derived from the
    module and enforced by executor.run() -> scope.checker.authorize(). Raises
    ValueError for a disallowed module/option before any subprocess is spawned
    (fail closed), and ScopeViolation if the target/category isn't authorized.
    """
    if action not in _ACTIONS:
        raise ValueError(f"action must be one of {_ACTIONS}, got {action!r}")

    category = category_for_module(module)
    clean_options = _validate_options(options or {})
    script = build_resource_script(module, target, clean_options, action, port)

    if shutil.which("msfconsole") is None:
        # Fail loudly rather than reporting a module as "not vulnerable" when
        # the framework simply isn't installed.
        raise RuntimeError("msfconsole not found on PATH; Metasploit is required for this tool")

    # msfconsole reads the module/options from a resource script rather than a
    # long -x string: keeps the datastore assignments off the process argv
    # (and out of `ps`) and avoids any quoting ambiguity.
    tmp = Path(tempfile.mkdtemp(prefix="scopeguard-msf-")) / "run.rc"
    tmp.write_text(script, encoding="utf-8")
    try:
        result = await executor.run(
            target=target,
            category=category,
            command=["msfconsole", "-q", "-n", "-r", str(tmp)],
            timeout=executor.timeout_for("msfconsole"),
        )
    finally:
        try:
            tmp.unlink()
            tmp.parent.rmdir()
        except OSError:
            pass

    return _parse_result(module, action, target, result)


def validate_setup_lines(setup: list[str]) -> list[str]:
    """Validate agent-authored msfconsole directives for the open-ended runner.

    The agent may write any msfconsole commands it wants (use/set/setg/run
    options, payload/LHOST for exploit modules, etc.) with two exceptions,
    both enforced here so the run stays bound to the scope:

      * No line may set RHOSTS/RHOST -- the target is ours, injected from the
        scope-validated target by run_command().
      * No `use` may select a DoS module -- flooding is refused outright.

    Also rejects embedded newlines (which would smuggle extra directives past
    these checks). Returns the cleaned lines; raises ValueError on any refusal.
    """
    clean: list[str] = []
    for raw in setup:
        line = str(raw)
        if "\n" in line or "\r" in line:
            raise ValueError("setup directives must be one command per list item (no newlines)")
        if _SET_RHOST_RE.match(line):
            raise ValueError("RHOSTS is set from the scope target, not the caller")
        m = _USE_MODULE_RE.match(line)
        if m:
            module = m.group(1)
            if any(module.startswith(p) for p in ("auxiliary/dos/",)) or "/dos/" in module:
                raise ValueError(f"DoS modules are not permitted: {module!r}")
        clean.append(line.rstrip())
    return clean


async def run_command(
    executor: ToolExecutor,
    target: str,
    setup: list[str],
    action: str = "run",
    port: int | None = None,
) -> ModuleResult:
    """Open-ended Metasploit runner: the agent authors the full msfconsole
    directive sequence in `setup` (its own `use`, `set`, payload/LHOST, etc.).

    Gated by profile, but still target-bound: this runs under the EXPLOIT
    category (so it only executes when the active scan profile enables it --
    see config/scan_profiles.yaml `active_exploit`), and RHOSTS is forced from
    `target`, which executor.run() validates against the scope record. The
    agent cannot re-target (see validate_setup_lines). Fails closed on any
    disallowed directive before a subprocess is spawned.
    """
    if action not in _ACTIONS:
        raise ValueError(f"action must be one of {_ACTIONS}, got {action!r}")

    clean_setup = validate_setup_lines(setup)
    # Whole runner is treated as EXPLOIT (the most invasive category) since the
    # module isn't constrained -- the profile is what turns this on, but the
    # per-target scope check still runs via executor.run() below.
    category = TestCategory.EXPLOIT

    # Agent directives first (their `use` must precede our `set`), then the
    # target we own, then the action.
    lines = list(clean_setup)
    lines.append(f"set RHOSTS {target}")
    if port is not None:
        lines.append(f"set RPORT {int(port)}")
    lines.append(action)
    lines.append("exit")
    script = "\n".join(lines) + "\n"

    if shutil.which("msfconsole") is None:
        raise RuntimeError("msfconsole not found on PATH; Metasploit is required for this tool")

    tmp = Path(tempfile.mkdtemp(prefix="scopeguard-msf-")) / "run.rc"
    tmp.write_text(script, encoding="utf-8")
    try:
        result = await executor.run(
            target=target,
            category=category,
            command=["msfconsole", "-q", "-n", "-r", str(tmp)],
            timeout=executor.timeout_for("msfconsole"),
        )
    finally:
        try:
            tmp.unlink()
            tmp.parent.rmdir()
        except OSError:
            pass

    module = _first_module(clean_setup)
    return _parse_result(module, action, target, result)


def _first_module(setup: list[str]) -> str:
    for line in setup:
        m = _USE_MODULE_RE.match(line)
        if m:
            return m.group(1)
    return "<none>"


def _parse_result(module: str, action: str, target: str, result: ToolResult) -> ModuleResult:
    signals, session_opened = _parse_msf_output(result.stdout)
    return ModuleResult(
        module=module,
        action=action,
        target=target,
        returncode=result.returncode,
        session_opened=session_opened,
        signals=signals,
        raw_output=result.stdout,
    )


_SESSION_RE = re.compile(r"session\s+\d+\s+opened", re.IGNORECASE)


def _parse_msf_output(raw: str) -> tuple[list[str], bool]:
    """Pull the human-meaningful signal lines out of msfconsole's chatter.

    msfconsole has no stable machine-readable output mode, so we surface the
    status-marked lines ([+]/[-]/[*]/[!]) as evidence and flag whether a
    session was opened -- downstream this becomes a structured finding rather
    than raw text handed between agents.
    """
    signals: list[str] = []
    session_opened = False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith(("[+]", "[-]", "[*]", "[!]")):
            signals.append(stripped)
        if _SESSION_RE.search(stripped):
            session_opened = True
    return signals, session_opened
