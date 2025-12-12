# Wordlists & Utilities

Additional features for scripting.

## Wordlists

### File Wordlists

```python
for word in open('/usr/share/dict/words'):
    engine.queue(target.req, word.rstrip())
```

### Clipboard

Lines from your clipboard:

```python
for word in wordlists.clipboard:
    engine.queue(target.req, word)
```

### Observed Words

Words collected during Burp passive scanning:

```python
for word in wordlists.observedWords:
    engine.queue(target.req, word)
```

### Bruteforce Generator

Infinite incremental bruteforce (a, b, ... aa, ab, ...):

```python
seed = 0
while True:
    batch = []
    seed = wordlists.bruteforce.generate(seed, 5000, batch)
    for word in batch:
        engine.queue(target.req, word)
```

## Utility Functions

### Random Strings

```python
from ScriptEnvironment import randstr

randstr()           # 12 char alphanumeric
randstr(8)          # 8 char alphanumeric
randstr(8, False)   # 8 char letters only
```

### Cache Busting

Use `$randomplz` in requests or payloads:

```python
engine.queue(target.req, "$randomplz")
```

Replaced with random 10-character alphanumeric string.

### Statistical Functions

```python
from ScriptEnvironment import mean, stddev

times = [req.time for req in results]
avg = mean(times)
std = stddev(times)
```

## Global Variables

| Variable | Type | Description |
|----------|------|-------------|
| `target` | obj | `.endpoint`, `.req`, `.baseInput` |
| `wordlists` | obj | `.clipboard`, `.observedWords`, `.bruteforce` |
| `table` | OutputHandler | Results table |
| `handler` | AttackHandler | Attack control |
| `callbacks` | IBurpExtenderCallbacks | Burp callbacks |
| `helpers` | IExtensionHelpers | Burp helpers |
| `api` | MontoyaApi | Montoya API |
| `host` | str | Target hostname |

## Target Object

```python
target.endpoint  # "https://example.com:443"
target.req       # Full HTTP request with %s markers
target.baseInput # Original request before markers
```

## Handler Object

```python
handler.setMessage("Processing...")  # Update status bar
handler.abort()                       # Cancel attack
```

## Engine User State

Store custom state across callbacks:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint)
    engine.userState['counter'] = 0
    ...

def handleResponse(req, interesting):
    req.engine.userState['counter'] += 1
```

## Multi-Host Attacks

Override endpoint per-request:

```python
hosts = ['host1.com', 'host2.com', 'host3.com']

for host in hosts:
    endpoint = 'https://' + host + ':443'
    engine.queue(target.req, payload, endpoint=endpoint)
```

## Output to File

```python
def handleResponse(req, interesting):
    with open('output.txt', 'a') as f:
        f.write(req.words[0] + '\n')
    table.add(req)
```

## Example Scripts

- [specialWordlists.py](../resources/examples/specialWordlists.py) - Wordlist sources
- [multiHost.py](../resources/examples/multiHost.py) - Multi-host scanning
- [outputToFile.py](../resources/examples/outputToFile.py) - File output
