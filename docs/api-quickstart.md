# Turbo Intruder API Quickstart

Quick reference for scripting. See linked docs for full details.

## Basic Script Structure

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           engine=Engine.THREADED)

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    table.add(req)
```

## RequestEngine Constructor (Essential)

```python
engine = RequestEngine(
    endpoint=target.endpoint,     # Required: "protocol://host:port"
    concurrentConnections=5,      # Parallel connections
    requestsPerConnection=100,    # Requests per connection
    engine=Engine.THREADED        # Engine type (see engines.md)
)
```

See [settings.md](settings.md) for all parameters.

## engine.queue() (Essential)

```python
engine.queue(target.req, "payload")              # Single payload
engine.queue(target.req, ["p1", "p2"])           # Multiple payloads
engine.queue(target.req, payload, gate='race1')  # Gated request (see race-conditions.md)
engine.queue(target.req, payload, label='test')  # Labeled for analysis
```

Use `%s` as injection point in request template. See [settings.md](settings.md) for all parameters.

## Request Object Properties

In `handleResponse(req, interesting)`:

| Property | Type | Description |
|----------|------|-------------|
| `req.response` | str | Full HTTP response |
| `req.request` | str | Full HTTP request (with payloads injected) |
| `req.status` | int | HTTP status code |
| `req.code` | int | HTTP status code (alias for `status`) |
| `req.length` | int | Response body length |
| `req.wordcount` | int | Word count in response |
| `req.time` | long | Response time (μs) |
| `req.words` | list | Injected payloads |
| `req.label` | str | Custom label (writable) |
| `req.template` | str | Original request template |
| `req.engine` | obj | Engine instance (for recursive queueing) |
| `req.order` | int | Response order within gate (0 = first) |
| `req.id` | int | Unique request ID |

## Engine Types

| Engine | Protocol | Use Case |
|--------|----------|----------|
| `Engine.THREADED` | HTTP/1.1 | Fast custom stack, most attacks |
| `Engine.BURP` | HTTP/1.1 | Needs Burp's proxy/auth |
| `Engine.BURP2` | HTTP/2 | HTTP/2, single-packet attacks |

See [engines.md](engines.md) for details.

## Global Variables

| Variable | Description |
|----------|-------------|
| `target` | Target with `.endpoint`, `.req` |
| `table` | Results table (`table.add(req)`) |
| `wordlists` | Access `.clipboard`, `.observedWords`, `.bruteforce` |
| `handler` | Attack handler (`.setMessage()`, `.abort()`) |
| `api` | Montoya API (Burp integration) |
| `callbacks` | Legacy Burp callbacks |

## Quick Links

- [Engine Types](engines.md) - THREADED vs BURP vs BURP2
- [Performance Tuning](performance.md) - Maximize requests per second
- [Race Conditions](race-conditions.md) - Gated requests, synchronization
- [All Settings](settings.md) - Full parameter reference
- [Response Processing](response-processing.md) - Callbacks, filtering
- [Decorators](decorators.md) - @MatchStatus, @FilterRegex, etc.
- [Wordlists & Misc](misc.md) - Bruteforce, clipboard, utilities
