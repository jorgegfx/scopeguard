# ScopeGuard

A multi-agent penetration-testing orchestrator. A top-level coordinator
fans out to specialized sub-agents (recon, service enumeration,
vulnerability scanning, web-app testing, reporting) that run OS-level tools
against a **user-declared, explicitly authorized target scope** and roll
results up into a report.

LLM inference is served locally via [LM Studio](https://lmstudio.ai)
(OpenAI-compatible `/v1/chat/completions` endpoint). Sub-agent fan-out uses
[LangGraph](https://langchain-ai.github.io/langgraph/)'s `Send` API.

> **Status:** the full pipeline runs end to end — recon → parallel
> per-service testing (service enum / vuln scan / web-app probe) → report
> (Markdown + PDF) — gated by a scan profile's concurrency cap and rate
> limit. Every agent so far is deterministic (nmap/curl output parsing, no
> LLM call yet); the LLM client exists but nothing uses it. See
> [Status](#status) below.

## Non-negotiable principle: authorization-first

No sub-agent touches a target without going through the scope-checker
first. A run requires a **scope record**: target(s), an authorization
artifact, a time window, and an explicit list of allowed test categories.
Every tool invocation is re-validated against that record, and every
decision — allow or deny — is written to an append-only audit log. See
[`CLAUDE.md`](./CLAUDE.md) for the full rationale and constraints this
project is built around.

## Requirements

- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/) for environment/dependency management
- [LM Studio](https://lmstudio.ai) running locally, for future LLM-backed
  sub-agents (nothing in the current pipeline calls it yet)
- Scanner binaries on `PATH` — every scan/probe tool wrapper shells out to
  one of these, gated through `scope.checker`. `nmap`, `curl` and `nslookup`
  are required; `nuclei`, `nikto`, `sslscan` and `ffuf` are optional and
  only needed for the tools that use them (a run whose scope record doesn't
  enable those categories, or a service tester that never selects them,
  won't invoke a missing binary). `ffuf` backs both content discovery and
  the webshell/backdoor sweep (`tools.webshell`), which also uses `curl` to
  fetch and fingerprint candidate shell pages. Version→CVE lookup
  (`tools.cve_lookup`) and certificate-transparency subdomain discovery
  (`tools.passive_recon`) call public web APIs (NVD, crt.sh) rather than a
  local binary.

## Installing the requirements (step by step)

The commands below are Windows-first (this is where the project is
developed); Linux/macOS equivalents follow each step. Nothing here needs to
run as administrator except the package-manager installs.

**1. Install `uv`** (Python environment + dependency manager — the only one
this project uses):

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
```

`uv` bootstraps a compatible Python (3.11+) itself, so a separate Python
install is optional. Verify with `uv --version`.

**2. Sync the Python dependencies** (creates `.venv/` and installs
everything from `pyproject.toml` / `uv.lock`):

```bash
uv sync
```

**3. Install the scanner binaries** so the tool wrappers can shell out to
them. On Windows, [Chocolatey](https://chocolatey.org/install) covers most:

```powershell
# Windows (PowerShell, admin) — via Chocolatey
choco install nmap curl -y          # nmap + curl (nslookup ships with Windows)
choco install ffuf nuclei -y        # content discovery + webshell sweep + templates
# nikto and sslscan have no maintained choco package — see the notes below
```

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y nmap curl dnsutils nikto sslscan   # dnsutils provides nslookup
# ffuf + nuclei are Go tools — install via Go (step 4) or download a release binary
```

```bash
# macOS (Homebrew)
brew install nmap curl bind nikto sslscan ffuf nuclei  # bind provides nslookup
```

**4. Install the Go-based scanners (`ffuf`, `nuclei`) if your package
manager doesn't carry them.** Install [Go](https://go.dev/dl/), then:

```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Make sure `%USERPROFILE%\go\bin` (Windows) or `$HOME/go/bin` (Linux/macOS)
is on your `PATH`. After installing `nuclei`, run `nuclei -update-templates`
once to pull its detection templates (including the webshell/backdoor ones).

> **Windows notes for `nikto` and `sslscan`:** both are easiest under WSL
> (`wsl --install`, then use the Debian/Ubuntu commands above) or Git Bash
> with Perl for `nikto`. They're optional — a scan only invokes them when
> the scope record enables `vuln_scan` and the service tester selects them.

**5. Install [LM Studio](https://lmstudio.ai)** and start its local server
(the OpenAI-compatible endpoint on `http://localhost:1234/v1` by default),
then load a model. Point `config/llm.yaml` at it (base URL + model name).
Only the LLM-driven service tester needs this; the deterministic tool
wrappers run without it.

**6. Verify everything resolves:**

```bash
uv run pytest                                   # the suite should pass
nmap --version && curl --version                # required binaries
ffuf -V && nuclei -version                       # optional (content/webshell/templates)
nikto -Version && sslscan --version              # optional (vuln_scan)
```

Any optional binary you skip simply means the tools that use it are
unavailable; the rest of the pipeline still runs.

## Getting started

```bash
uv sync
uv run pytest
```

Point `config/llm.yaml` at your LM Studio instance (base URL + model name)
before running anything that uses the LLM client.

## Running a scan

Copy `examples/scope_record.example.yaml` and fill in your own target(s),
authorization artifact, time window, and allowed categories:

```bash
uv run scopeguard run --scope my_scope_record.yaml --profile recon_only
```

`--profile` selects an entry from `config/scan_profiles.yaml` (default
`recon_only`), which sets the run's concurrency cap and per-target rate
limit. Recon discovers open ports via nmap, then every discovered service
is tested in parallel (bounded by the profile) for whichever categories
the scope record authorizes, and a Markdown + PDF report is written to
`reports/<run_id>.{md,pdf}`.

`--log-level` (default `INFO`) controls console verbosity: every tool
invocation is logged with its target/category/duration, every
authorization refusal is logged as a warning (not just written to the
audit JSONL), and `DEBUG` also shows successful authorization checks and
rate-limit delays. This is operational logging for watching a run live --
separate from `audit.log`'s append-only per-run JSONL, which is the
compliance record.

## Project layout

```
scopeguard/
├── config/
│   ├── llm.yaml             # LM Studio endpoint + per-agent temperature/context
│   └── scan_profiles.yaml   # passive / recon_only / active profiles + concurrency caps
├── examples/
│   └── scope_record.example.yaml
├── src/
│   ├── scope/                # scope record schema + the authorize() gate
│   ├── audit/                 # append-only, concurrency-safe run/command log
│   ├── tools/                 # subprocess wrappers (nmap, curl) -- every call goes through scope.checker,
│   │                          # plus rate_limit.RateLimiter (per-target throttling)
│   ├── llm/                   # LM Studio client (semaphore-bounded concurrency) -- not yet used by any agent
│   ├── agents/                # recon, service_enum, vuln_scan, webapp, report
│   └── orchestrator/          # LangGraph fan-out/fan-in graph + profiles + run lifecycle + CLI
└── tests/
```

## Status

| Module | State |
| --- | --- |
| `scope.checker` / `scope.models` | Implemented, tested |
| `audit.log` | Implemented |
| `tools.base` | Implemented, tested — async, semaphore-bounded, rate-limited `ToolExecutor` |
| `tools.nmap` / `tools.curl` | Implemented, tested |
| `tools.nuclei` | Implemented, tested — templated CVE/misconfig detection, JSONL parsed (`vuln_scan`) |
| `tools.tls` | Implemented, tested — sslscan weak-protocol/cipher/cert checks (`vuln_scan`) |
| `tools.nikto` | Implemented, tested — web-server issue scan, XML parsed (`vuln_scan`) |
| `tools.cve_lookup` | Implemented, tested — nmap version string → NVD CVEs (external API, advisory) |
| `tools.http_headers` | Implemented, tested — security-header/cookie/disclosure analysis (`webapp_test`) |
| `tools.content_discovery` | Implemented, tested — ffuf path brute-force (`content_discovery` category) |
| `tools.webshell` | Implemented, tested — remote PHP/Apache backdoor detection: ffuf sweep of known shell paths + curl body-signature validation (`webshell_scan` category) |
| `tools.passive_recon` | Implemented, tested — nslookup (`passive_recon`) + crt.sh subdomains (external API) |
| `orchestrator.profiles` | Implemented, tested — loads `config/scan_profiles.yaml` |
| `agents.recon` | Implemented, tested — nmap port/service discovery |
| `agents.service_enum` | Implemented, tested — nmap `-sC` default scripts |
| `agents.vuln_scan` | Implemented, tested — nmap `vuln` NSE scripts, only surfaces a finding when one actually flags something |
| `agents.webapp` | Implemented, tested — passive curl HTTP probe |
| `agents.report` | Implemented, tested — renders Markdown + PDF from structured findings |
| `orchestrator.graph` | All three nodes (`recon` → `test_service` → `report`) wired and tested, including per-category failure isolation |
| `orchestrator.run` / `cli` | Implemented, tested — async end-to-end, `--profile` flag |

None of the agents call the LLM yet — every one so far is deterministic
tool-output parsing. The LLM client (`llm.client`) exists but is unused by
the pipeline and has no tests of its own.

## Testing

```bash
uv run pytest
```

No secondary test runner — `uv run pytest` is the only supported way to run
the suite.

## Design decisions still open

- Authorization artifact verification (self-attestation is a placeholder;
  a commercial product testing third-party infrastructure needs something
  more rigorous).
- No LLM-driven reasoning anywhere yet -- every agent is a fixed
  tool-output parser. The LLM's intended role (deciding what to probe next,
  writing an executive summary, etc.) hasn't been built.
- `vuln_scan` now spans nmap `vuln` NSE scripts, nuclei templates, Nikto,
  sslscan (TLS) and an NVD version→CVE lookup. The NVD lookup is a keyword
  match on the nmap version string, so it's advisory (back-ported/distro
  patches can make it a false positive) rather than a confirmed CPE match --
  a proper CPE-based query is still worth doing.
- Webshell/backdoor detection (`webshell_scan`) is black-box only: it probes
  a curated wordlist of known shell paths and fingerprints response bodies.
  The wordlist and signature set are intentionally small/precise; broadening
  either (or adding host-side scanning like YARA/ClamAV, which would need
  file-system access to the target and so a different authorization model)
  is a deliberate next step, not an accident of the current scope.
- Per-run concurrency tuning against real LM Studio throughput (moot until
  an agent actually calls the LLM).

See `CLAUDE.md`'s "Open questions" section for the full list.
