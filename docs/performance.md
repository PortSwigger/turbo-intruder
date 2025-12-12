# Performance Tuning

How to maximize requests per second (RPS) for high-volume attacks.

## Quick Checklist

1. Minimize request size (remove unnecessary headers/cookies)
2. Minimize response size (HEAD method, Range header)
3. Choose the right engine
4. Tune engine parameters
5. Filter responses before adding to table
6. Stream wordlists instead of buffering

## Engine Selection

Typical speed ranking (fastest to slowest):

1. **Engine.THREADED** (well-tuned) - fastest for HTTP/1.1
2. **Engine.BURP2** - fast for HTTP/2
3. **Engine.BURP** - most compatible, slowest

> **Tip:** A well-tuned THREADED engine can achieve 30,000+ RPS to remote servers.

## Tuning Engine.THREADED

Tune these parameters in priority order:

### 1. Pipeline

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.THREADED,
                       pipeline=True)  # Send all requests before reading
```

| Value | Behavior |
|-------|----------|
| `False` | Send one request, wait for response (safest) |
| `True` | Send all requests before reading any responses (fastest) |
| `N` (int) | Read after every N requests (balanced) |

Start with `pipeline=True`. If you get errors, try `pipeline=10` or lower.

### 2. requestsPerConnection

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.THREADED,
                       requestsPerConnection=1000)
```

Higher values reduce connection overhead. Start high (1000) and reduce if the server closes connections.

### 3. concurrentConnections

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.THREADED,
                       concurrentConnections=50)
```

More connections = more parallelism, but diminishing returns. Watch for:
- Server rate limiting
- Connection errors
- Retries increasing

**Tuning approach:** Increase until RPS stops improving or Retries increases.

### Example: Maximum Speed

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.THREADED,
                       concurrentConnections=100,
                       requestsPerConnection=1000,
                       pipeline=True)
```

## Tuning Engine.BURP / BURP2

Only `concurrentConnections` is tunable:

```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.BURP,
                       concurrentConnections=50)
```

Start with 20-50 and increase until RPS plateaus.

## Reducing Request Size

Remove unnecessary headers to minimize bandwidth:

```
GET /path HTTP/1.1
Host: target.com

```

vs bloated:

```
GET /path HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Accept: text/html,application/xhtml+xml,...
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Cookie: session=abc123; tracking=xyz789; preferences=...
```

## Reducing Response Size

### HEAD Method

If you only need status codes:

```python
req = target.req.replace('GET ', 'HEAD ')
engine.queue(req, payload)
```

### Range Header

Request only first N bytes:

```python
req = target.req.replace('\r\n\r\n', '\r\nRange: bytes=0-500\r\n\r\n')
```

## Memory Management

For million+ request attacks, memory management is critical.

### Filter Before Adding to Table

Bad (stores everything):
```python
def handleResponse(req, interesting):
    table.add(req)  # Every response consumes RAM
```

Good (filter first):
```python
def handleResponse(req, interesting):
    if req.status != 404:
        table.add(req)
```

Better (use decorators):
```python
@FilterStatus(404)
def handleResponse(req, interesting):
    table.add(req)
```

### Stream Wordlists

Bad (loads entire file into memory):
```python
words = open('/path/to/huge-wordlist.txt').read().splitlines()
for word in words:
    engine.queue(target.req, word)
```

Good (streams line by line):
```python
for word in open('/path/to/huge-wordlist.txt'):
    engine.queue(target.req, word.rstrip())
```

## Callback Performance

Avoid expensive operations in `handleResponse`:

```python
# Bad - regex on every response
def handleResponse(req, interesting):
    if re.search(r'complex.*pattern', req.response):
        table.add(req)

# Good - simple string check
def handleResponse(req, interesting):
    if 'target-string' in req.response:
        table.add(req)
```

## Monitoring Performance

Watch the status bar for:
- **RPS** - requests per second (maximize this)
- **Retries** - should stay near zero
- **Fails** - connection failures

If Retries climbs:
1. Reduce `concurrentConnections`
2. Reduce `pipeline` value
3. Reduce `requestsPerConnection`
4. Try `Engine.BURP` for better stability

## Server Proximity

For maximum speed, minimize network latency:

```bash
# Run Turbo Intruder headless on a VPS near the target
java -jar turbo-intruder.jar script.py
```

## Server-Side Bottlenecks

Your attack speed is limited by the slowest component:
- **Network latency** - use closer server
- **Server processing** - nothing you can do
- **Rate limiting** - reduce concurrency or add delays

If a server executes slow database queries per request, no amount of tuning will help.

## Example: High-Speed Fuzzing

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           engine=Engine.THREADED,
                           concurrentConnections=100,
                           requestsPerConnection=1000,
                           pipeline=True)

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())

@FilterStatus(404, 400)
@FilterSize(0)
def handleResponse(req, interesting):
    table.add(req)
```

## References

- [Turbo Intruder: Embracing the billion-request attack](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
