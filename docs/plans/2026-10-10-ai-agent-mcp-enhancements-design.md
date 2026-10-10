# AI-Agent MCP Enhancements — Design

Date: 2026-10-10
Status: Proposed
Scope: features chosen for the fork/PR —
1. Asynchronous runs + completion observation
2. MCP prompts for agent workflows
3. Structured findings tool
4. **MCP server control UI (Burp Suite tab + settings panel)**
5. **Broader Montoya API integration**

The UI + hardening design draws on well-established patterns for AI-agent Burp
extensions — EDT confinement for Swing work, bind-host/token access controls, a
status/health surface, and audit logging. We borrow *patterns* only, not code.

This document is a design, not an implementation. Implementation follows
`superpowers:test-driven-development` (per CLAUDE.md): a failing test precedes
each behavioural change.

---

## 0. Context: what already exists

This repo already ships a mature MCP integration (merged from `d0ge/mcp-server`,
commits `73618c2`, `55762f1`). Before designing anything, the relevant current
state is:

- **Server:** `mcp.TurboMcpServer` on the official Java SDK
  `io.modelcontextprotocol.sdk:mcp:0.17.0`, served over embedded Jetty with
  `HttpServletStatelessServerTransport` (the **stateless** transport), bound to
  `127.0.0.1:31337` (Burp) / `31338` (standalone). Off by default behind the
  `enable unsafe MCP server` setting (`McpServerGate`).
- **Tools:** `start_run`, `stop_run`, `delete_run`, `save_to_organizer`,
  `generate_collaborator_payload`, `get_collaborator_interactions`,
  `search_responses`. An unused `start_run_async` builder exists, gated off by
  the `ENABLE_ASYNC_RUN = false` constant in `TurboMcpServer.kt`.
- **Resources:** declarative DSL (`mcp/resource/`) — `turbo://runs`,
  `runs/{id}`, `runs/{id}/script`, `runs/{id}/summary`, `runs/{id}/{n}`,
  `turbo://organizer`, `turbo://docs/*`, `turbo://examples/*`. `current`
  aliases the latest run. `turbo://runs/{id}?wait=true` long-polls while a run
  is still `running` (`McpResourceHandlers.getRunStatus(waitMs)`).
- **Montoya:** Collaborator + Organizer providers, context menus, hotkey.
- **Run lifecycle:** `RunManager` → `ActiveRun` (`id`, `handler: RunHandler`,
  `store: ResultStore`). `RunHandler.status()` returns `running` /
  `completed` / `failed`; `markScriptCompleted()` flips the terminal state.

### Transport constraint that shapes this plan (verified against SDK 0.17.0)

The stateless transport has **no sessions**, therefore **no server-initiated
notifications**: no `notifications/resources/updated`, no `resources/subscribe`,
no server-pushed logging. Confirmed from the SDK source:
`McpStatelessSyncServer` exposes only `addTool/removeTool`,
`addResource/removeResource`, `addResourceTemplate`, `addPrompt/removePrompt`,
`close` — there is no subscribe/notify surface.

Two consequences:

1. **"Subscriptions" in the feature list cannot be true server-push** on this
   transport. We implement completion *observation* via long-poll (already the
   codebase's pattern) rather than push. Real push would require switching to
   the session-based Streamable HTTP transport — a larger, riskier change the
   server was explicitly built to avoid (`TurboMcpServer.kt:129` comment:
   "no sessions, simpler client compatibility"). Out of scope here; noted as a
   future option in §4.
2. **Prompts DO work on stateless** — `StatelessSyncSpecification.prompts(...)`
   and `McpStatelessServerFeatures.SyncPromptSpecification` both exist. Feature
   #2 needs no transport change.

### Pre-existing capability over-promise (fix within Feature #1)

`TurboMcpServer.startInternal()` declares:

```kotlin
.capabilities(McpSchema.ServerCapabilities.builder()
    .tools(true)
    .resources(true, true)   // subscribe=true, listChanged=true
    .logging()
    .build())
```

On the stateless transport neither `subscribe` nor `listChanged` can be
honoured, and `logging()` cannot push either. This advertises behaviour the
server cannot deliver, which a strict client may rely on. Corrected in §1.

---

## 1. Feature: Asynchronous runs + completion observation

### Goal

Let an agent start a run and return immediately, then observe progress and
completion without blocking a tool call for up to 55 s. This removes the
`timeout_ms` guesswork in `start_run` for long runs (billion-request fuzzing,
multi-day timing studies).

### Non-goal

Server-push notifications (see transport constraint above). Observation is
client-driven long-poll.

### Design

1. **Enable the existing async tool.** Remove the `ENABLE_ASYNC_RUN` gate (or
   default it true) so `start_run_async` is registered. It already delegates to
   `McpToolHandlers.startRunAsync(...)`, returning `{status: "started",
   run_id}`. No new handler logic needed for the start path.

2. **Completion observation uses the existing long-poll resource.** Agents read
   `turbo://runs/{run_id}?wait=true` (already implemented,
   `getRunStatus(waitMs)`), which blocks up to the handler's wait window and
   returns the terminal status + top-20 summary. Document this as the canonical
   async pattern; add the `wait` semantics to the tool's result `message`
   (already partly present in `startRun`'s timeout branch).

3. **Bound the long-poll.** `getRunStatus` currently honours an unbounded
   `waitMs` from the query string. Clamp it server-side (e.g. max 55 s) so a
   client cannot hold a Jetty thread indefinitely. New behaviour → new test.

4. **Correct the advertised capabilities** to match the stateless transport:
   `resources(false, false)`, drop `logging()` unless/until a session transport
   is adopted. (If we keep `listChanged` aspirationally we must actually emit
   it; we can't, so we remove it.)

### Files

- `src/mcp/TurboMcpServer.kt` — remove `ENABLE_ASYNC_RUN`; fix capabilities.
- `src/mcp/McpResourceHandlers.kt` — clamp `waitMs`.
- `docs/MCP-SERVER.md`, `docs/plans/.../mcp-server-design.md` — document the
  async pattern.

### Tests (TDD)

- `startRunAsync` returns `started` + a `run_id` that resolves in `RunManager`.
- `getRunStatus(waitMs > cap)` never blocks longer than the cap.
- `getRunStatus` returns terminal status + summary once `markScriptCompleted()`.
- Capability object reports `subscribe=false`.

---

## 2. Feature: MCP prompts for agent workflows

### Goal

Give agents ready-made, parameterised workflows instead of hand-writing a
Jython script every time. A prompt returns a filled-in `start_run` script +
base request skeleton the agent can review and submit.

### Why prompts (not more tools)

MCP prompts are user/agent-selectable templates that expand to messages. They
are the right primitive for "here is a vetted recipe, fill the blanks" and keep
the raw scripting power behind a reviewed template. Confirmed available on the
stateless transport (§0).

### Proposed prompts (v1)

Each takes a small argument set and returns a `PromptMessage` whose text is a
complete, copy-ready `start_run` invocation (script + base_request guidance).
Scripts are sourced from the existing vetted `resources/examples/` so prompts
stay in lockstep with tested code.

| Prompt name            | Arguments                               | Expands to (based on) |
|------------------------|-----------------------------------------|-----------------------|
| `fuzz_parameter`       | `endpoint`, `param`, `wordlist_hint?`   | `default.py` wordlist fuzz |
| `race_condition_test`  | `endpoint`, `requests` (int)            | `race-single-packet-attack.py` |
| `timing_probe`         | `endpoint`, `param`                     | `timing.py` statistical timing |
| `recursive_discovery`  | `endpoint`                              | `recursive.py` |

Scope note: start with `fuzz_parameter` and `race_condition_test`; the other
two are additive and share the same mechanism.

### Design

1. **Prompt registry, mirroring the resource DSL.** Add `mcp/prompt/` with a
   small builder (`prompt("name") { argument(...); handle { args -> ... } }`)
   producing `SyncPromptSpecification`s, and a `PromptRegistry` with
   `buildStatelessSpecs()`. This matches the existing `ResourceRegistry`
   structure for review familiarity.
2. **Template bodies reuse `McpResourceHandlers.getExample(name)`** so a prompt
   and `turbo://examples/{name}` never drift. The prompt substitutes the
   endpoint/param into the returned script text (or appends an instruction
   block the agent applies).
3. **Wire into the builder:** `.prompts(promptRegistry.buildStatelessSpecs())`
   and `.capabilities(... .prompts(true) ...)`.
4. **Respect `disabledTools` philosophy:** add a `disabledPrompts` set so a
   deployment can narrow the surface.

### Files

- `src/mcp/prompt/PromptRegistry.kt`, `PromptDsl.kt`, `PromptDefinitions.kt` (new).
- `src/mcp/TurboMcpServer.kt` — register prompts; add `prompts(true)` capability.
- `docs/MCP-SERVER.md` — "Available Prompts" section.

### Tests (TDD)

- Each prompt definition lists its declared arguments.
- `fuzz_parameter` expansion contains the endpoint and param, and references a
  real example script name present in `discoveredExamples`.
- Disabled prompts are absent from `buildStatelessSpecs()`.
- Prompt template script names stay a subset of `resources/examples/`.

---

## 3. Feature: Structured findings tool

### Goal

Let an agent record a vulnerability in machine-readable form, not just prose
notes, and persist it to Burp's Organizer so a human sees it in-context.

### Current gap

`save_to_organizer` takes free-text `notes` only. There is no typed finding
(severity, confidence, type, evidence request id). Agents and humans can't
filter or triage programmatically.

### Design

1. **New tool `report_finding`.** Arguments:
   - `run_id` (string), `request_id` (int) — the evidencing request in the run.
   - `title` (string, required)
   - `severity` enum: `info|low|medium|high|critical`
   - `confidence` enum: `tentative|firm|certain`
   - `finding_type` (string, e.g. `sqli`, `ssrf`, `race-condition`)
   - `detail` (string) — free-form explanation.
   - `collaborator_payload?` (string) — link an OOB payload if relevant.
2. **Structured output.** Return a typed JSON object
   (`{finding_id, status, organizer_item?}`) using the SDK's structured-output
   path so a client gets a schema, not a blob. The human-readable note written
   to Organizer is rendered from the structured fields (stable format:
   `[SEVERITY/CONFIDENCE] title — type\n\ndetail\n\nRun/Request/Payload refs`).
3. **Persistence.** Reuse `OrganizerProvider.sendToOrganizer(request, notes)`.
   The request is fetched from the run's `ResultStore.getRequest(request_id)`,
   exactly as `saveToOrganizer` already does, so Montoya wiring is unchanged.
4. **Validation.** Reject unknown enum values with a clear error (not a stack
   trace). Reject a missing run/request with the existing
   `runNotFoundMessage` / `request_not_found` conventions.

### Interop with other features

- Pairs with Feature #2: a prompt-driven workflow ends with the agent calling
  `report_finding`.
- Pairs with Collaborator tools: `collaborator_payload` ties an OOB hit to the
  finding.

### Files

- `src/mcp/McpToolHandlers.kt` — `reportFinding(...)` + a `Finding` data class
  and note renderer.
- `src/mcp/TurboMcpServer.kt` — `buildStatelessReportFindingTool()` + register.
- `docs/MCP-SERVER.md` — tool row + payload example.

### Tests (TDD)

- Valid finding → writes one Organizer item; returned `finding_id` is stable.
- Invalid severity/confidence → typed error, no Organizer write.
- Missing run / request id → `not_found` / `request_not_found`, no write.
- Note renderer output contains title, severity, type, run id, request id.
- Organizer persistence verified through a fake `OrganizerProvider` (the tests
  already inject one), so no Burp runtime needed.

---

## 3b. Feature: MCP server control UI (Burp Suite tab + settings panel)

### Problem

Today the server is controlled **only** by a hidden boolean setting
(`enable unsafe MCP server`) surfaced through the albinowaxUtils
`ConfigMenu` in Burp's menu bar (`BurpExtender.kt:54`). There is no dedicated
Burp **Suite tab**, no Montoya **settings panel**, no status readout, and no way
to see whether the server is actually listening or what it is doing. A user
cannot tell running from stopped, cannot see the port/address, and cannot
inspect MCP activity. This is the gap the user called out.

### Goal

A first-class **"Turbo MCP"** Suite tab plus a Montoya settings panel that make
the server observable and controllable from the GUI, while keeping
`McpServerGate` as the single lifecycle authority (the UI drives the gate; it
never starts/stops the server directly).

### Montoya surfaces used

Verified available in the Montoya API already on the classpath
(`montoya-api-examples.md`): `userInterface().registerSuiteTab(title, component)`,
`userInterface().registerSettingsPanel(SettingsPanelBuilder…)`,
`logging().logToOutput/logToError`, `persistence()`. EDT rules follow the
reference project's confinement contract (23-UI-SPEC): **all Swing work on the
EDT via `SwingUtilities.invokeLater`; the blocking start/stop runs off-EDT on a
daemon thread** (the gate already serialises lifecycle under a lock, so the UI
only needs to call `settingChanged(...)` off the EDT and then refresh status).

### Tab layout (Swing; no new heavy UI framework)

```
┌─ Turbo MCP ───────────────────────────────────────────────┐
│  Status:  ● Running   http://127.0.0.1:31337               │
│           [ Start ] [ Stop ]        (disabled per state)   │
│                                                            │
│  ┌ Configuration ─────────────────────────────────────┐   │
│  │ Bind host   [127.0.0.1    ]  (loopback enforced)    │   │
│  │ Port        [31337        ]                         │   │
│  │ Desync mode [x]  (strips Connection headers)        │   │
│  │ Enabled tools:   [x]start_run [x]report_finding ... │   │
│  │ Enabled prompts: [x]fuzz_parameter [x]race_... ...  │   │
│  └────────────────────────────────────────────────────┘   │
│                                                            │
│  ┌ Activity log ──────────────────────────────────────┐   │
│  │ 13:40:01  server started on 127.0.0.1:31337         │   │
│  │ 13:40:12  start_run  run=… status=completed         │   │
│  │ 13:40:30  report_finding  high  sqli  → organizer 7 │   │
│  └────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
```

The security banner on the "unsafe" nature of the server (loopback,
unauthenticated) stays prominent — reuse `McpServerGate.DESCRIPTION` text.

### Design

1. **`McpControlPanel` (new, `src/mcp/ui/`).** A `JPanel` built on EDT. The
   Start/Stop buttons call `gate.settingChanged("true"/"false")` on a daemon
   thread, then marshal a status refresh back to the EDT. Status is derived
   from a new `McpServerGate.isRunning()` accessor (the gate already tracks
   `running` internally — expose it read-only) plus the bound host/port.
2. **Status model is observable.** Add a light listener hook to `McpServerGate`
   (`onStateChange: (running: Boolean) -> Unit`) so the panel updates when the
   server starts/stops for *any* reason (menu toggle, takeover, failure), not
   only button clicks. Keeps a single source of truth.
3. **Tool/prompt enablement.** The server already supports `disabledTools`
   (and §2 adds `disabledPrompts`). The panel reads/writes these via
   `Utilities.globalSettings` (one boolean per tool/prompt, lazily registered)
   so choices persist across restarts, and `startMcpServer()` reads them when
   constructing `TurboMcpServer`. Changing enablement while running prompts a
   restart (or applies on next start) — simplest correct behaviour.
4. **Activity log.** Introduce an `McpActivityLog` ring buffer (bounded, e.g.
   500 entries) that `McpToolHandlers` and the resource handlers append to on
   each call (tool name, run id, outcome). The panel renders it (append on EDT)
   and also mirrors to `logging().logToOutput(...)` for the audit trail the
   hardening runbook recommends. Bounded to avoid the memory issues the run
   manager already guards against.
5. **Settings panel (secondary).** A `registerSettingsPanel` with the same
   bind/port/enable fields, so the config is reachable from Burp's unified
   Settings search too. The Suite tab remains the primary surface because it
   also shows live status + log, which a settings panel cannot.
6. **Wiring in `BurpExtender`.** After `initialize(montoyaApi)`, build the panel
   on the EDT and `registerSuiteTab("Turbo MCP", panel)`; register the settings
   panel. Keep the existing menu checkbox working (it drives the same gate) for
   backward compatibility — the tab's toggle and the menu stay in sync via the
   gate's state-change listener.

### EDT / threading contract (from 23-UI-SPEC, applied)

- Build/update all Swing components on the EDT (`SwingUtilities.invokeLater`).
- Never call `gate.settingChanged` / `start()` / `stop()` on the EDT — they do
  Jetty socket I/O and can block; run on a named daemon thread.
- The activity-log append marshals to the EDT; the ring buffer itself is
  thread-safe so handler threads can write without touching Swing.

### Files

- `src/mcp/ui/McpControlPanel.kt` (new), `src/mcp/ui/McpActivityLog.kt` (new).
- `src/McpServerGate.kt` — add `isRunning()` + `onStateChange` hook.
- `src/mcp/McpToolHandlers.kt`, `src/mcp/McpResourceHandlers.kt` — append to the
  activity log (constructor-injected, nullable so tests pass none).
- `src/BurpExtender.kt` — register suite tab + settings panel; read per-tool /
  per-prompt enablement settings when constructing the server.
- `docs/MCP-SERVER.md` — document the tab and controls.

### Tests (TDD)

- `McpServerGate.isRunning()` reflects start/stop transitions; `onStateChange`
  fires with the right boolean. (Gate is already Burp-free and unit-tested.)
- `McpActivityLog` is bounded (drops oldest past capacity) and thread-safe
  (concurrent appends don't lose the count invariant).
- Per-tool enablement setting → absent from `getEnabledToolNames()`.
- Swing classes themselves are not unit-tested (no Burp runtime); logic is
  extracted into non-Swing collaborators (gate, log, enablement resolver) that
  are.

---

## 3c. Feature: Broader Montoya API integration

"Use the entire Montoya API" is open-ended; a single PR cannot wrap all of it
responsibly. This section defines a **bounded, high-value** set that directly
serves AI-agent workflows, plus a clearly-marked backlog. Each item is additive
and independently shippable.

### In this scope (v1)

1. **`logging()` everywhere.** Replace ad-hoc `System.err.println`
   (e.g. `McpToolHandlers.launchRun` catch block) and `Utils.out` with
   `montoyaApi.logging()` so output lands in Burp's Output/Errors tabs and feeds
   the activity log — the auditability the hardening runbook asks for.
2. **`persistence()` for MCP settings.** Persist port / enabled tools / enabled
   prompts via Montoya persistence (project or user prefs), so an agent setup
   survives Burp restarts without relying solely on albinowaxUtils settings.
3. **`siteMap()` read resource.** Add `turbo://sitemap?host=…&limit=…` resource
   exposing Burp's site map entries (request/response summaries) so an agent can
   *discover* endpoints to fuzz, not just fuzz ones it was handed. Read-only,
   respects the same body-truncation + desync-filter paths as existing
   resources. (This is the single biggest agent-capability unlock.)
4. **`scope()` guard.** Before a run or when listing site-map entries, expose
   whether a host `isInScope(url)` and optionally refuse out-of-scope targets
   when a new `enforce_scope` setting is on. Turns Burp's scope into a safety
   rail for autonomous agents — aligns with the reference project's scope-first
   safety guidance.

### Backlog (named, not built here)

- `ai()` service (Burp's built-in AI) for in-extension assistance — only when
  `montoyaApi.ai().isEnabled()`; gated behind `EnhancedCapability.AI_FEATURES`.
- `proxy().history()` as a resource (large, attacker-controlled — must be a
  confirmed/gated read, treating returned traffic as untrusted model input).
- `scanner()` issue export / `sendToScanner`.
- Bearer-token + TLS for non-loopback exposure (external mode). Only if someone
  actually needs remote agents; loopback stays default.

### Why bounded

Hardening these surfaces responsibly (access control, redaction, trust
boundaries, EDT confinement) is substantial work. We deliberately ship the
loopback-safe subset first and treat remote exposure, bulk attacker-controlled
reads, and the AI service as separate, individually reviewed additions rather
than one unreviewable mega-PR.

### Tests (TDD)

- Site-map resource maps entries to the existing summary shape and honours
  `limit`/`host`; empty when Montoya absent (tests inject a fake provider, as
  Organizer already does).
- `enforce_scope` on → out-of-scope endpoint rejected before any request.
- Persistence round-trips port + enablement.

---

## 4. Explicitly out of scope (and why)

- **True server-push subscriptions / progress notifications.** Requires the
  session-based Streamable HTTP transport, replacing
  `HttpServletStatelessServerTransport`, reworking `HostValidationFilter`
  session handling, and re-testing client compatibility. Large and orthogonal;
  propose as a separate design if the long-poll pattern proves insufficient.
- **Resource templates / completions.** The SDK supports them on stateless and
  they could replace `QueryParamAwareUriTemplateManager`, but that is a
  refactor, not a feature; not needed for the three goals.

---

## 5. Build / environment note for contributors

The build requires a JDK that Gradle 8.10 supports (Java 21 recommended;
`sourceCompatibility = 21`). The default JDK on this machine is 24, which
Gradle 8.10 rejects ("Unsupported class file major version 68"). Build with:

```bash
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ./gradlew jar
```

Worth adding to `CLAUDE.md` / `readme.md` so the fork's CI and contributors
pin the right JDK. (Optional: a `toolchain { languageVersion = 21 }` block in
`build.gradle` would make Gradle select it automatically.)

---

## 6. Suggested PR sequencing

Each is independently mergeable and testable:

0. **PR 0 — JDK toolchain / build note** (§5). Tiny; makes the fork buildable
   in CI without the JDK-24 surprise.
1. **PR A — async + capability correctness** (§1). Unblocks long runs, fixes the
   capability over-promise.
2. **PR B — structured findings** (§3). Self-contained; high agent value.
3. **PR C — MCP prompts** (§2). Builds on A + B.
4. **PR D — MCP control UI** (§3b). The user-facing gap: Suite tab + settings
   panel + status + activity log. Depends on the gate `isRunning()`/listener
   hook; the activity log it renders is fed by B and C, so it lands after them.
5. **PR E — broader Montoya (loopback subset)** (§3c): `logging()`,
   `persistence()`, `turbo://sitemap`, `enforce_scope`. Each commit is one
   surface so review stays tractable.

Remote exposure (bearer token / TLS), bulk proxy-history reads, and the `ai()`
service are **separate future PRs**, not part of this plan.
