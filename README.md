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
  won't invoke a missing binary). Version→CVE lookup (`tools.cve_lookup`)
  and certificate-transparency subdomain discovery (`tools.passive_recon`)
  call public web APIs (NVD, crt.sh) rather than a local binary.

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
- Per-run concurrency tuning against real LM Studio throughput (moot until
  an agent actually calls the LLM).

See `CLAUDE.md`'s "Open questions" section for the full list.
