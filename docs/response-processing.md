# Response Processing

How to handle and filter responses in Turbo Intruder.

## Basic handleResponse

```python
def handleResponse(req, interesting):
    table.add(req)
```

- `req` - Request object with response data
- `interesting` - Boolean from automatic analysis (if `learn=` was used)

## Request Object Properties

```python
def handleResponse(req, interesting):
    # Response data
    req.response    # Full HTTP response (str)
    req.status      # HTTP status code (int)
    req.code        # HTTP status code (alias for status)
    req.length      # Response body length (int)
    req.wordcount   # Word count in response (int)
    req.time        # Response time in μs (long)

    # Request data
    req.request     # Full HTTP request with payloads injected (str)
    req.template    # Original request template (str)
    req.words       # List of injected payloads
    req.label       # Custom label (writable)

    # Metadata
    req.order       # Response order within gate (0 = first)
    req.id          # Unique request ID
    req.engine      # Engine instance
```

## Filtering Responses

### Manual Filtering

```python
def handleResponse(req, interesting):
    if req.status == 200:
        table.add(req)
```

```python
def handleResponse(req, interesting):
    if '404 Not Found' not in req.response:
        table.add(req)
```

### Using Decorators

See [decorators.md](decorators.md) for full decorator reference.

```python
@MatchStatus(200, 204)
def handleResponse(req, interesting):
    table.add(req)
```

```python
@FilterStatus(404, 500)
@MatchSizeRange(100, 1000)
def handleResponse(req, interesting):
    table.add(req)
```

## Automatic Interesting Detection

Use `learn=` to automatically detect interesting responses:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint)

    # First 5 requests train the baseline
    for i in range(5):
        engine.queue(target.req, randstr(i), learn=1)

    # Subsequent requests compared to baseline
    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if interesting:
        table.add(req)
```

The `interesting` parameter is `True` when the response differs from the learned baseline.

## Custom Per-Request Callbacks

```python
def myCallback(req, interesting):
    print("Custom handling for: " + req.words[0])
    table.add(req)
    return True

engine.queue(target.req, payload, callback=myCallback)
```

## Recursive Scanning

Queue new requests from within handleResponse:

```python
def handleResponse(req, interesting):
    if '404 Not Found' not in req.response:
        table.add(req)
        # Queue deeper scans
        for word in open('/usr/share/dict/words'):
            req.engine.queue(req.template, req.words[0] + '/' + word.rstrip())
```

## Completed Callback

Process all results after the attack:

```python
def completed(reqsFromTable):
    for req in reqsFromTable:
        print(req.status, req.time, req.words)
```

## Burp Integration

```python
def handleResponse(req, interesting):
    if interesting:
        table.add(req)
        # Add to Burp's site map
        callbacks.addToSiteMap(req.getBurpRequest())
```

Available Burp objects:
- `callbacks` - IBurpExtenderCallbacks
- `api` - Montoya API
- `helpers` - IExtensionHelpers

## Example Scripts

- [recursive.py](../resources/examples/recursive.py) - Recursive directory scanning
- [burpIntegration.py](../resources/examples/burpIntegration.py) - Burp API integration
- [timing.py](../resources/examples/timing.py) - Timing analysis with completed()
