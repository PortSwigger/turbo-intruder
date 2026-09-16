# Engine Types

Turbo Intruder provides multiple HTTP engines for different scenarios.

## Quick Comparison

| Engine | Protocol | Speed | Reliability | Pipelining | Use Case |
|--------|----------|-------|-------------|------------|----------|
| `Engine.AUTO` | Highest available | Adaptive | Adaptive | No | Professional default, ease of use |
| `Engine.THREADED` | HTTP/1.1 | Extremely fast | Toggleable | Yes | Community default, tuned HTTP/1.1 use cases |
| `Engine.BURP` | HTTP/1.1 | Fast | Excellent | No | Proxy, auth, upstream |
| `Engine.BURP2` | HTTP/2 | Extremely fast | Excellent | Automatic | HTTP/2, race conditions |
| `Engine.HTTP3` | HTTP/3 over QUIC | Extremely fast | Good | Automatic | HTTP/3 targets, race conditions |

> **Note:** `Engine.HTTP2` is deprecated. Use `Engine.BURP2` for HTTP/2.

> **Note:** `Engine.SPIKE` is non-functional and should not be used.

> **THREADED vs BURP:** The THREADED engine is significantly faster due to its custom HTTP stack with pipelining support, but Burp's HTTP stack (used by BURP/BURP2) is more mature and stable. If you encounter connection errors or malformed responses with THREADED, try switching to BURP for better compatibility.

## Engine.AUTO

`Engine.AUTO` requires Burp Suite Professional. It handles engine configuration for you by selecting
the highest available HTTP version, then configuring the relevant settings dynamically as the attack
runs. It is selected by default in Professional when `engine` is omitted. Other editions default to
`Engine.THREADED`, while desync-agent mode defaults to `Engine.BURP`.

```python
engine = RequestEngine(endpoint=target.endpoint)
```

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

These enable request smuggling research and timing tests by splitting request transmission.

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

**Best for:** High-volume fuzzing, request smuggling research, timing tests, maximum speed.

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

Uses Burp Suite's HTTP/2 stack. Required for single-packet attack.

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.BURP2,
                       concurrentConnections=1)
```

**Features:**
- HTTP/2 multiplexing over single connection
- Single-packet attack: all gated requests sent in one TCP packet
- Uses Burp's upstream proxy settings
- Automatic authentication handling

See [Kettled Requests](#kettled-requests-burp2-and-http3) for pseudo-header overrides and CRLF
injection through Burp's native HTTP/2 API.

**Limitations:**
- `requestsPerConnection` forced to 1
- `pipeline` not supported (HTTP/2 handles multiplexing)
- `timeout` not supported (uses Burp's settings)
- `readCallback` not supported
- `readSize` not supported
- `resumeSSL` not supported
- `pauseBefore`/`pauseTime`/`pauseMarker` not supported

**Best for:** HTTP/2 targets, race condition testing, single-packet attack.

See [race-conditions.md](race-conditions.md) for single-packet attack examples.

## Engine.HTTP3

Uses Turbo Intruder's own HTTP/3 stack over QUIC. This engine requires Burp Suite Professional.
The target has to support HTTP/3; there is no fallback to HTTP/2 or HTTP/1.1.

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.HTTP3,
                       concurrentConnections=32)
```

**Going fast:**
- Raise `concurrentConnections` until the `Fails` column stops reading zero, then back off. Each connection runs up to 256 requests at once
- `requestsPerConnection` defaults to a million. Only raise it if one connection will carry more requests than that

**Features:**
- HTTP/3 multiplexing over QUIC
- Two race condition techniques

See [Kettled Requests](#kettled-requests-burp2-and-http3) for pseudo-header overrides and malformed
field values. HTTP3 uses the same per-request API and escape syntax as BURP2.

**Race Gates**

Requests sharing a `gate` get their own connection and are released together. `gateMode` picks how
that connection is held.

| `gateMode` | Behaviour |
|------------|-----------|
| `auto` (default) | Whichever gate the server supports |
| `sda` | Single Datagram Attack. The whole batch released in one UDP packet |
| `qpack` | Blocks the batch on one withheld QPACK insertion. Takes bigger batches, up to the server's `SETTINGS_QPACK_BLOCKED_STREAMS` |

Settings:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `gateMode` | `'auto'` | Which gate to use |

**Limitations:**
- Doesn't use Burp's proxy settings, authentication, or cookie handling

**Best for:** HTTP/3 targets, and races that need the smallest possible gap between requests.

See [race-conditions.md](race-conditions.md) for gate examples.

## Kettled Requests (BURP2 and HTTP3)

Pass `kettled=True` to encode deliberately malformed HTTP/2 or HTTP/3 field names and values. This is supported by `Engine.BURP2`, `Engine.HTTP3`, and `Engine.AUTO` when AUTO selects either of those protocols.

```python
req = '''GET /ignored HTTP/1.1
Host: example.com
:method: POST
:path: /actual
X-Test: one^~transfer-encoding:^schunked

body'''

engine.queue(req, kettled=True)
```
The HTTP/1 style request line is required and implies the `:method` and `:path` pseudo headers. If they are then provided, you are **replacing** the values that were implied. You can then include duplicates if you so wish with an additional pseudo header.

You can also add the binary representation of characters that cannot be expressed in HTTP/1.1 using the following escape sequences.

| Escape | Value |
|--------|-------|
| `^~` | CRLF |
| `^r` | CR |
| `^n` | LF |
| `^0` | NUL |
| `^s` | Space |
| `^xNN` | Byte `0xNN` |
| `^^` | Literal `^` |

## Example Scripts

- [default.py](../resources/examples/default.py) - Basic edition-dependent default usage
- [burpIntegration.py](../resources/examples/burpIntegration.py) - BURP engine with Collaborator
- [race-single-packet-attack.py](../resources/examples/race-single-packet-attack.py) - BURP2 for races
- [race-http3.py](../resources/examples/race-http3.py) - Single Datagram Attack
