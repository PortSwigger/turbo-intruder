# Settings Reference

Complete parameter reference for RequestEngine and queue().

## RequestEngine Constructor

```python
engine = RequestEngine(
    endpoint,                    # Required: "protocol://host:port"
    callback=None,               # Response callback (default: handleResponse)
    engine=Engine.THREADED,      # Engine type
    concurrentConnections=50,    # Parallel connections
    requestsPerConnection=100,   # Requests per TCP connection
    pipeline=False,              # Enable HTTP/1.1 pipelining
    maxQueueSize=100,            # Max queued requests
    timeout=10,                  # Response timeout (seconds)
    maxRetriesPerRequest=3,      # Retry failed requests
    idleTimeout=0,               # Total attack timeout (ms, 0=none)
    readCallback=None,           # Partial response callback
    readSize=1024,               # Read buffer size
    resumeSSL=True,              # Resume SSL sessions
    autoStart=True,              # Start engine immediately
)
```

### Parameter Details

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `endpoint` | str | Required | Target URL: `"https://example.com:443"` |
| `engine` | Engine | THREADED | `Engine.THREADED`, `Engine.BURP`, `Engine.BURP2` |
| `concurrentConnections` | int | 50 | Parallel TCP connections |
| `requestsPerConnection` | int | 100 | Requests before reconnecting |
| `pipeline` | bool/int | False | Pipeline requests (THREADED only) |
| `maxQueueSize` | int | 100 | Queue limit (blocks when full) |
| `timeout` | int | 10 | Response timeout in seconds |
| `maxRetriesPerRequest` | int | 3 | Retries for failed requests |
| `idleTimeout` | int | 0 | Attack timeout in ms (0=disabled) |
| `autoStart` | bool | True | Start immediately vs manual `engine.start()` |

### Engine-Specific Notes

**THREADED:**
- All parameters supported
- `pipeline=True` sends all requests before reading responses
- `pipeline=N` reads after every N requests

**BURP/BURP2:**
- `requestsPerConnection` forced to 1
- `pipeline` not supported
- `readCallback` not supported

## engine.queue() Parameters

```python
engine.queue(
    template,              # Request with %s injection points
    payloads=None,         # Payload(s) to inject
    learn=0,               # Learn boring responses (1-N)
    callback=None,         # Per-request callback
    gate=None,             # Gate name for synchronization
    label="",              # Custom label
    pauseBefore=0,         # Pause N times during send
    pauseTime=1000,        # Pause duration (ms)
    pauseMarker=[],        # Pause after these strings
    delay=0,               # Delay completion (ms)
    endpoint=None,         # Override target endpoint
    fixContentLength=True  # Auto-fix Content-Length header
)
```

### Parameter Details

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `template` | str | Required | Request with `%s` markers |
| `payloads` | any | None | Single value, list, or None |
| `learn` | int | 0 | Learn response as baseline (1, 2, etc.) |
| `callback` | func | None | Override default callback |
| `gate` | str | None | Gate name for race conditions |
| `label` | str | "" | Custom label for grouping |
| `delay` | int | 0 | Delay response processing (ms) |
| `endpoint` | str | None | Override target for this request |
| `fixContentLength` | bool | True | Update existing Content-Length header (does not add if missing) |

### Special Payload Values

- `$randomplz` - Replaced with random 10-char alphanumeric string

```python
engine.queue(target.req, "$randomplz")  # Cache-busting
```

## Table Output

```python
table.add(req)  # Add request to results table
```

The results table displays:
- Status code
- Response length
- Word count
- Response time
- Payload
- Label
- Anomaly rank (Burp 2025.10+)

### Custom Sort Order

```python
table.setSortOrder(column, descending)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `column` | int | Column index (0-based) |
| `descending` | bool | `True` for descending, `False` for ascending |

Setting a custom sort order also disables the automatic sort-by-anomaly-rank on attack completion.

```python
# Sort by first column (status) in ascending order
table.setSortOrder(0, False)
```

## Handler Methods

```python
handler.setMessage("Status text")  # Update status bar
handler.abort()                     # Cancel attack
```

## Engine Methods

```python
engine.start(timeout=5)     # Manual start (if autoStart=False)
engine.complete(timeout=-1) # Wait for completion
engine.cancel()             # Cancel attack
engine.openGate('name')     # Open a gate
engine.userState            # Dict for custom state
engine.applySetting(name, value)  # Internal settings
```

### Internal Settings

```python
engine.applySetting("calculateAnomalyRank", False)  # Disable anomaly ranking
engine.applySetting("ignoreLength", True)           # Ignore Content-Length (THREADED only)
```

| Setting | Default | Engine | Description |
|---------|---------|--------|-------------|
| `calculateAnomalyRank` | True | All | Calculate anomaly rankings on completion |
| `ignoreLength` | False | THREADED | Ignore Content-Length and chunked encoding when parsing responses. Useful for HTTP research with malformed responses. |
