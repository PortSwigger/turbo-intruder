# Engine Types

Turbo Intruder provides multiple HTTP engines for different scenarios.

## Quick Comparison

| Engine | Protocol | Speed | Reliability | Pipelining | Use Case |
|--------|----------|-------|-------------|------------|----------|
| `Engine.THREADED` | HTTP/1.1 | Extremely fast | Toggleable | Yes | Default, most attacks |
| `Engine.BURP` | HTTP/1.1 | Fast | Excellent | No | Proxy, auth, upstream |
| `Engine.BURP2` | HTTP/2 | Extremely fast | Excellent | Automatic | HTTP/2, race conditions |

> **Note:** `Engine.HTTP2` is deprecated. Use `Engine.BURP2` for HTTP/2.

> **Note:** `Engine.SPIKE` is non-functional and should not be used.

> **THREADED vs BURP:** The THREADED engine is significantly faster due to its custom HTTP stack with pipelining support, but Burp's HTTP stack (used by BURP/BURP2) is more mature and stable. If you encounter connection errors or malformed responses with THREADED, try switching to BURP for better compatibility.

## Engine.THREADED

Custom hand-coded HTTP stack optimized for speed and control.

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.THREADED,
                       concurrentConnections=50,
                       requestsPerConnection=100,
                       pipeline=True,
                       timeout=10,
                       readCallback=myCallback,
                       readSize=1024,
                       resumeSSL=True)
```

**Unique Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `pipeline` | False | `True` = send all requests before reading; `N` = read after every N requests |
| `timeout` | 10 | Socket timeout in seconds |
| `readCallback` | None | Callback receiving partial response data as it arrives (see below) |
| `readSize` | 1024 | Socket receive buffer size in bytes |
| `resumeSSL` | True | Reuse SSL sessions (auto-disables on SSL errors) |
| `requestsPerConnection` | 100 | Requests before reconnecting |

**readCallback Signature:**

```python
def handleRead(data):
    # data contains the latest chunk of response data (string)
    # Note: data is only the last socket read, not the full response
    # Tokens or patterns may be split across multiple reads
    if 'token' in data:
        engine.queue('follow-up-request')
    # Return value is ignored
```

**Unique queue() Parameters:**

| Parameter | Description |
|-----------|-------------|
| `pauseBefore` | Pause after sending N bytes (negative = from end) |
| `pauseTime` | Pause duration in ms (default 1000) |
| `pauseMarker` | List of strings - pause after sending each marker |

These enable request smuggling research and timing attacks by splitting request transmission.

**Features:**
- Fastest option with HTTP/1.1 pipelining
- Automatic decompression (gzip, deflate, brotli)
- Handles chunked transfer encoding
- Trusts all SSL certificates
- TCP optimizations (TCP_NODELAY, keep-alive)
- Auto-converts HTTP/2 requests to HTTP/1.1
- Auto-converts `Connection: close` to `Connection: keep-alive`

**Limitations:**
- Doesn't use Burp's proxy settings
- No automatic authentication

**Best for:** High-volume fuzzing, request smuggling research, timing attacks, maximum speed.

## Engine.BURP

Uses Burp Suite's native HTTP/1.1 stack.

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.BURP,
                       concurrentConnections=20)
```

**Features:**
- Uses Burp's upstream proxy settings
- Automatic authentication handling
- Session handling and cookie jar
- Battle-tested reliability

**Limitations:**
- `requestsPerConnection` forced to 1 (no keep-alive)
- `pipeline` not supported
- `timeout` not supported (uses Burp's settings)
- `readCallback` not supported
- `readSize` not supported
- `resumeSSL` not supported
- `pauseBefore`/`pauseTime`/`pauseMarker` not supported
- Slower than THREADED

**Best for:** When you need Burp's proxy/auth features, or maximum compatibility.

## Engine.BURP2

Uses Burp Suite's HTTP/2 stack. Required for single-packet attacks.

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.BURP2,
                       concurrentConnections=1)
```

**Features:**
- HTTP/2 multiplexing over single connection
- Single-packet attacks: all gated requests sent in one TCP packet
- Uses Burp's upstream proxy settings
- Automatic authentication handling

**HTTP/2 Character Escapes:**

When using HTTP/2 engines, you can use these escape sequences in requests:

| Escape | Character | Description |
|--------|-----------|-------------|
| `^` | `\r` | Carriage return |
| `~` | `\n` | Line feed |
| `` ` `` | `:` | Colon |

**Overriding Pseudo-Headers:**

You can override HTTP/2 pseudo-headers by specifying them as regular headers:

```python
req = '''GET / HTTP/2
Host: example.com
:path: /custom-path
:method: POST

'''
```

**Limitations:**
- `requestsPerConnection` forced to 1
- `pipeline` not supported (HTTP/2 handles multiplexing)
- `timeout` not supported (uses Burp's settings)
- `readCallback` not supported
- `readSize` not supported
- `resumeSSL` not supported
- `pauseBefore`/`pauseTime`/`pauseMarker` not supported

**Best for:** HTTP/2 targets, race condition testing, single-packet attacks.

See [race-conditions.md](race-conditions.md) for single-packet attack examples.


## Example Scripts

- [default.py](../resources/examples/default.py) - Basic THREADED usage
- [burpIntegration.py](../resources/examples/burpIntegration.py) - BURP engine with Collaborator
- [race-single-packet-attack.py](../resources/examples/race-single-packet-attack.py) - BURP2 for races
