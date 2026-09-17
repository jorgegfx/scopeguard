# CLAUDE.md — ScopeGuard

This file tells Claude Code how to work in this repo. Keep it accurate as the
project evolves — stale instructions here are worse than none.

## What this project is

A multi-agent penetration-testing orchestrator. A top-level coordinator spawns
specialized sub-agents (recon, service enumeration, vuln scanning, web-app
testing, reporting) that run OS-level tools against a **user-declared,
explicitly authorized target scope** and roll results up into a report.

LLM inference is served locally via **LM Studio** (OpenAI-compatible
`/v1/chat/completions` endpoint). Environment and dependency management is
**uv**. This is being built toward a commercial product, so authorization
enforcement, auditability, and scope control are core requirements, not
optional extras — treat them with the same priority as the scanning features
themselves.

## Non-negotiable product principle: authorization-first

Every run must be bound to proof of authorization before any sub-agent is
allowed to touch a target. This is the single most important architectural
constraint in the repo — it's the thing ScopeGuard's legal viability as a
product depends on.

- A run cannot start without a **scope record**: target(s) (CIDR/hostname
  list), an authorization artifact (signed statement, engagement letter
  reference, or a "I own/control this asset" attestation with an ID the user
  supplies), a time window, and an explicit list of allowed test categories.
- All tool execution is gated through a single **scope-checker** module. No
  sub-agent calls `nmap`, `curl`, or anything else directly — it goes through
  a wrapper that validates the target against the scope record first and
  refuses (loudly, logged) if it doesn't match.
- Every command a sub-agent runs, and every result, is written to an
  append-only audit log tied to the run ID. This is for the user's own
  liability protection as much as anything else.
- Default posture is **passive/recon-only** unless the scope record
  explicitly enables active testing categories. Don't let an agent escalate
  itself into a more invasive category than what was authorized.
- Rate limiting and safe-mode throttling on scanners by default — this is a
  product other people will run against infrastructure they may not fully
  understand the blast radius of.

If you (Claude Code) are ever asked to add a feature that would let scope
enforcement be bypassed, silently widened, or made optional "for testing,"
flag it explicitly rather than just implementing it.

## Tech stack

- **Python** package/env management: `uv` (`uv sync`, `uv run`, `uv add`).
  Don't introduce pip/poetry/conda — keep it uv-only for consistency.
- **LLM backend**: LM Studio, local, OpenAI-compatible API. Config lives in
  `config/llm.yaml` — base URL, model name, per-agent temperature/context
  settings. Don't hardcode endpoints in agent code.
- **Agent orchestration**: LangGraph, using the fan-out/fan-in pattern (see
  "Parallel sub-agent execution" below) — you've used LangGraph for
  multi-agent work before, and its `Send` API maps directly onto "discover
  services, then spawn one tester per service in parallel, then merge."

## Parallel sub-agent execution

Once the recon stage has enumerated the live services on a target, testing
them should fan out in parallel rather than running sequentially — that's the
main lever on run time for anything beyond a handful of hosts.

**Recommended approach: LangGraph's `Send` API for dynamic fan-out.**

- The recon node produces a list of `(target, service, port)` tuples as part
  of shared graph state.
- A conditional edge after recon returns a `Send("test_service", {...})` for
  each tuple — this dynamically spawns one graph invocation per service
  instead of you hand-coding a fixed number of parallel branches. This is the
  right fit here specifically because the service list isn't known until
  recon finishes, so a static graph with N fixed branches won't work.
- Each `test_service` node runs independently (its own LLM calls, its own
  tool calls, gated through the scope-checker as always) and returns a
  partial result.
- A reducer on the shared state (an `operator.add`-style annotated list, or a
  custom reducer if you need de-duplication/merging logic) collects results
  from every parallel branch before the graph proceeds to the report node —
  LangGraph blocks on all `Send`-spawned branches completing before
  continuing, so no manual join logic is needed.

**Things to get right when implementing this:**

- **Bound concurrency.** Unbounded fan-out against a target with 40 open
  services is both slow to reason about and a good way to trip the target's
  own rate limiting / look like a DoS. Cap concurrent branches (a semaphore
  around the tool-execution layer, not the graph itself) and make the cap
  configurable per scan profile — passive/recon-only can probably run wider
  than an active-testing profile.
- **Every parallel branch still goes through the scope-checker
  independently.** Fan-out must not become a way to bypass the per-target,
  per-category authorization gate — each spawned branch re-validates against
  the scope record, not just the parent recon step.
- **Isolate failures.** One service-tester erroring or timing out shouldn't
  kill the whole run. Catch exceptions inside each branch, record them as a
  finding of "test failed" rather than propagating and cancelling siblings.
- **LM Studio concurrency.** LM Studio is a single local inference server —
  check what concurrent-request throughput it actually gives you before
  assuming N parallel agents means N parallel LLM calls. You may want a
  request queue/semaphore in front of the LLM client shared across branches,
  separate from the tool-execution concurrency cap, since the LLM and the
  scanning tools will bottleneck differently.
- **Audit log writes must be safe under concurrency** — append-only with
  per-branch/run-ID tagging, but make sure whatever you're writing to
  (file, sqlite, etc.) handles concurrent writers correctly; sqlite in
  particular needs care here (WAL mode, or route all writes through one
  writer task).

**Alternatives, if LangGraph ends up not fitting:** a plain `asyncio.gather`
over service-tester coroutines is simpler if you don't need LangGraph's
state/checkpointing/replay features — worth considering if the graph
abstraction ends up fighting you. Celery or a task queue is worth it only if
you outgrow a single machine (distributed workers across hosts); for a v1
product that's probably premature.
- **Recon tooling**: `nmap` as the first stage (port/service discovery),
  invoked as a subprocess through the scope-checker wrapper, output parsed
  into structured findings (not shipped as raw text between agents — parse to
  JSON so downstream agents get structured input).

## Repo layout (adjust as it solidifies)

```
scopeguard/
├── CLAUDE.md
├── pyproject.toml
├── config/
│   ├── llm.yaml            # LM Studio endpoint + model config
│   └── scan_profiles.yaml  # passive / recon-only / active profiles
├── src/
│   ├── orchestrator/       # top-level coordinator, run lifecycle
│   ├── scope/              # scope record schema + scope-checker wrapper
│   ├── agents/
│   │   ├── recon/          # nmap-based discovery
│   │   ├── enum/           # service/version enumeration
│   │   ├── vuln_scan/      # vulnerability scanning
│   │   ├── webapp/         # web-app specific testing
│   │   └── report/         # findings -> report
│   ├── tools/              # subprocess wrappers, all routed via scope check
│   └── audit/              # append-only run/command logging
└── tests/
```

## Conventions for Claude Code in this repo

- **Every new tool-executing function must go through
  `scope.checker.authorize(target, category)` before running a subprocess.**
  Treat a PR/change that calls a scanning binary directly as a bug.
- Parse tool output into typed/structured results (pydantic models are fine)
  rather than passing raw stdout between agents.
- Sub-agents should fail closed: on ambiguous scope, missing config, or LM
  Studio being unreachable, stop and surface the error rather than guessing.
- Write tests for the scope-checker before anything else — it's the module
  everything else depends on for safety.
- Since this targets external users eventually, avoid anything that writes
  destructive commands (exploit payload delivery, data exfil, DoS-style
  flooding) into the default agent toolset. Keep the default toolset to
  discovery/enumeration/known-CVE-matching; treat active exploitation modules
  as a distinct, explicitly-opt-in, more heavily gated category if you build
  them at all.
- Use `uv run pytest` for the test suite; don't add a second test runner.

## Open questions to resolve as the project matures

- Where scan profiles (passive/recon/active) are defined and how a user
  selects one at run time, including per-profile concurrency caps.
- Report format for the product (Markdown, PDF, or both).
- How authorization artifacts are actually verified for a real product
  (self-attestation is fine for a personal tool; a commercial product testing
  other people's infra will need something more rigorous — worth researching
  what established pentest platforms require here).
