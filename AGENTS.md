# TURBO INTRUDER — PROJECT KNOWLEDGE BASE

**Generated:** 2026-02-24  
**Commit:** 0923fef  
**Branch:** master  
**Version:** 1.62

## OVERVIEW

Burp Suite extension for high-speed HTTP fuzzing. Custom hand-coded HTTP/1.1 and HTTP/2 stacks via raw sockets, controlled via Python attack scripts (Jython 2.7 or external Python 3). Complements Burp Intruder for bulk/billion-request attacks, race conditions, and timing-based vulnerabilities.

## STRUCTURE

```
turbo-intruder/
├── src/                    # Kotlin + Java source (compiled together)
│   ├── fast-http.kt        # UI (TurboIntruderFrame), Jython eval, CLI entry point
│   ├── BurpExtender.kt     # Extension registration (legacy + Montoya API)
│   ├── RequestEngine.kt    # Abstract base — queue, gate, diff, retry logic
│   ├── BurpRequestEngine.kt  # Engine using Burp's native HTTP stack
│   ├── ThreadedRequestEngine.kt  # Raw socket HTTP/1.1 engine (main workhorse)
│   ├── HTTP2RequestEngine.kt # Custom H2 multiplexed engine
│   ├── SpikeEngine.kt      # Single-packet attack engine (race conditions)
│   ├── Python3Runner.kt    # External Python 3 subprocess via JSON-RPC
│   ├── H2Connection.kt     # HTTP/2 connection + stream management
│   ├── HeaderEncoder.kt    # HPACK header compression
│   ├── Frame.kt / Stream.kt # HTTP/2 framing primitives
│   └── burp/               # Java utilities (TurboLib, Floodgate, Bruteforce, Utils)
├── resources/
│   ├── ScriptEnvironment.py  # Python environment injected before user scripts
│   └── examples/           # 29 Python attack scripts (canonical usage references)
├── build.gradle            # Gradle build — produces turbo-intruder-all.jar (fat jar)
├── decorators.md           # Python decorator API reference
└── README.md
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Extension registration / hotkey / menus | `src/BurpExtender.kt` |
| UI, script editor, attack toggle | `src/fast-http.kt` → `TurboIntruderFrame` |
| Jython script execution | `src/fast-http.kt` → `evalJython()` |
| Python 3 subprocess bridge | `src/Python3Runner.kt` |
| Queue/gate/diff/retry base logic | `src/RequestEngine.kt` |
| Raw socket HTTP/1.1 implementation | `src/ThreadedRequestEngine.kt` |
| Burp-native HTTP engine | `src/BurpRequestEngine.kt` |
| HTTP/2 multiplexed engine | `src/HTTP2RequestEngine.kt` |
| Single-packet race attack | `src/SpikeEngine.kt` + `src/SpikeConnection.kt` |
| Python script patterns / examples | `resources/examples/*.py` |
| Python API decorators | `decorators.md` |
| Build configuration | `build.gradle` |
| Burp API interfaces (legacy) | `src/burp/*.java` |

## ENGINE TYPES

Three request engines — chosen in Python scripts via engine parameter:

| Constant | Class | Transport |
|----------|-------|-----------|
| `Engine.BURP` (1) | `BurpRequestEngine` | Burp's native HTTP stack |
| `Engine.THREADED` (2) | `ThreadedRequestEngine` | Raw sockets, HTTP/1.1 |
| `Engine.BURP2` (4) | `BurpRequestEngine` | Burp HTTP/2 batch (race) |
| `Engine.HTTP2` (3) | `HTTP2RequestEngine` | Custom H2 multiplexed |
| `Engine.SPIKE` | `SpikeEngine` | Single-packet via Burp HTTP/2 |

Default engine when unspecified: `Engine.THREADED`.

## PYTHON SCRIPT CONTRACT

Every attack script must implement exactly two functions:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           callback=handleResponse)
    # Inject payloads via %s in request template:
    engine.queue(target.req, payload)
    engine.openGate('name')   # for race attacks

def handleResponse(req, interesting):
    # req.status, req.wordcount, req.length, req.response, req.label
    if interesting:
        table.add(req)
```

- **Injection marker**: `%s` in raw HTTP template (NOT `{placeholder}`)
- **`$randomplz`**: auto-replaced with random alphanumeric string before queuing
- `target.req` = base request bytes; `target.endpoint` = `host:port` or `host:port:https`

## CODE MAP

| Symbol | Type | File | Role |
|--------|------|------|------|
| `TurboIntruderFrame` | class | `fast-http.kt` | Main Swing UI |
| `evalJython()` | fun | `fast-http.kt` | Runs Python 2/Jython attack |
| `main()` | fun | `fast-http.kt` | CLI entrypoint |
| `RequestEngine` | abstract class | `RequestEngine.kt` | Base attack engine |
| `RequestEngine.queue()` | fun | `RequestEngine.kt` | Enqueue a request |
| `RequestEngine.openGate()` | fun | `RequestEngine.kt` | Release gated requests |
| `BurpExtender` | class | `BurpExtender.kt` | Burp extension bootstrap |
| `Python3Runner` | class | `Python3Runner.kt` | Python 3 subprocess IPC |
| `Scripts` | object | `fast-http.kt` | Loads ScriptEnvironment.py + default.py |

## BUILD

```bash
# Build fat jar (Linux/macOS)
./gradlew build fatjar

# Build fat jar (Windows)
gradlew.bat build fatjar

# Output
build/libs/turbo-intruder-all.jar

# CLI mode
java -jar turbo-intruder-all.jar scriptFile baseRequestFile endpoint [baseInput]
```

- Java 21 required
- Kotlin 2.1.10
- Jython 2.7.0 bundled (Python 2 syntax in scripts)
- Python 3 via external subprocess (configure path in Burp settings → `python3Path`)
- `hpack-1.0.2.jar` and `albinowaxUtils-all.jar` are local JARs in `libs/`
- `rsyntaxtextarea` + `rstaui` for script editor UI

## ANTI-PATTERNS (THIS PROJECT)

- **Do NOT use `{placeholder}` or `{{var}}` injection** — only `%s` is the injection marker
- **Do NOT use Python 3 f-strings or type hints in Jython scripts** — Jython is Python 2.7
- **Do NOT modify `ScriptEnvironment.py` for per-attack logic** — put attack logic in `resources/examples/` scripts or user scripts
- **Do NOT write tests** — project has no test suite; validate via manual Burp loading
- **Do NOT use `engine.queue()` after attack start without gates** — use `openGate()` for synchronized race attacks
- **Do NOT import external Python packages in Jython scripts** — only stdlib + Jython builtins available

## CONVENTIONS

- Dual API registration: supports both legacy `IBurpExtender` (pre-2023 Burp) and Montoya API — both must remain functional
- UI runs on Swing Event Dispatch Thread via `SwingUtilities.invokeLater`
- Python 3 scripts communicate via JSON-RPC with 4-byte big-endian length-prefixed frames
- Response diffing uses Burp's `IResponseVariations` API via thread-safe `SafeResponseVariations` wrapper
- Race attack gate sync: withhold last 1 byte of each request, release simultaneously via `Floodgate`

## NOTES

- `decorators.md` documents the Python decorator API (e.g., `@MatchStatus`, `@FilterWords`) — check before adding new response filtering logic
- Burp's `rankingUtils()` (auto-sort by anomaly) requires Burp ≥ 2025.10; gracefully degrades otherwise
- `ThreadedRequestEngine` trusts all SSL certs (`TrustingTrustManager`) — intentional for pentest use
- No CI pipeline, no linter config, no formatter config
- Burp App Store metadata: `BappManifest.bmf`, `BappDescription.html`

## API SYNC RULE

**`RequestEngine.__init__` exists in TWO files and must always be identical:**

| File | Runtime | Role |
|------|---------|------|
| `resources/ScriptEnvironment.py` | Jython 2.7 (inside JVM) | Injected before every user attack script in Burp; calls Kotlin/Java directly via Jython interop |
| `resources/turbo_intruder.py` | CPython 3.x (subprocess) | Extracted from JAR and executed as a standalone Python 3 process; sends JSON-RPC to Kotlin instead of calling Java |

Both `RequestEngine.__init__` signatures must stay **byte-for-byte identical** (same parameter names, same order, same defaults).

### When a Kotlin engine parameter changes (add / remove / rename):

1. Update `RequestEngine.__init__` in **`resources/ScriptEnvironment.py`**
2. Update `RequestEngine.__init__` in **`resources/turbo_intruder.py`** — same change, same position
3. Update the engine constructor call body in `ScriptEnvironment.py` (the `burp.*` Java dispatch)
4. Update the `createEngine` RPC params in `turbo_intruder.py`
5. Update `handleCreateEngine()` in `src/Python3Runner.kt` to handle the new param over RPC
6. Rebuild: `JAVA_HOME=... ./gradlew fatjar`

Both files contain a `# !! SYNC:` comment above `__init__` as a reminder. Do not remove those comments.

