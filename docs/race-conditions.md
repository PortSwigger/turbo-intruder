# Race Condition Testing

Turbo Intruder supports gated requests for precise timing in race condition attacks.

## Basic Gated Requests

The `gate` parameter withholds requests until `openGate()` is called:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Queue requests - they won't send yet
    for i in range(20):
        engine.queue(target.req, gate='race1')

    # Send all queued requests simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

## Single-Packet Attack (HTTP/2)

For HTTP/2 targets, use `Engine.BURP2` with `concurrentConnections=1` to trigger single-packet attacks:

```python
engine = RequestEngine(endpoint=target.endpoint,
                       concurrentConnections=1,
                       engine=Engine.BURP2)

for i in range(20):
    engine.queue(target.req, gate='race1')

engine.openGate('race1')
```

All gated requests are sent in a single TCP packet, arriving at the server simultaneously.

> **Tip:** A negative timestamp in results indicates the server responded before the request was fully sent - a sign of server-side processing overlap.

See: https://portswigger.net/research/smashing-the-state-machine

## HTTP/1.1 Race Conditions

For HTTP/1.1, use `Engine.THREADED` or `Engine.BURP`:

```python
engine = RequestEngine(endpoint=target.endpoint,
                       concurrentConnections=20,
                       engine=Engine.THREADED)

for i in range(20):
    engine.queue(target.req, gate='race1')

engine.openGate('race1')
```

Uses multiple connections to send requests as simultaneously as possible.

## Multiple Gates

Use separate gates for different request groups:

```python
# First race
for i in range(10):
    engine.queue(req1, gate='gate1')

# Second race
for i in range(10):
    engine.queue(req2, gate='gate2')

engine.openGate('gate1')
time.sleep(0.1)
engine.openGate('gate2')
```

## Timing Attack Pattern

For comparing response times between two payloads:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=2,
                           engine=Engine.BURP,
                           maxQueueSize=2)

    REPEATS = 100

    for i in range(REPEATS):
        gate_id = str(i)

        # Alternate order to prevent false positives
        if i % 2 == 1:
            engine.queue(attack.replace('%s', 'payload1'), gate=gate_id, label='left')
            engine.queue(attack.replace('%s', 'payload2'), gate=gate_id, label='right')
        else:
            engine.queue(attack.replace('%s', 'payload2'), gate=gate_id, label='right')
            engine.queue(attack.replace('%s', 'payload1'), gate=gate_id, label='left')

        engine.openGate(gate_id)
        time.sleep(0.2)  # Avoid rate limiting
```

## Response Order

Use `req.order` to see which request in a gate got a response first (0 = first):

```python
def handleResponse(req, interesting):
    if req.order == 0:
        print("This request won the race")
    table.add(req)
```

## Example Scripts

- [race-single-packet-attack.py](../resources/examples/race-single-packet-attack.py) - Basic race
- [timing.py](../resources/examples/timing.py) - Statistical timing analysis
- [race-multi-endpoint.py](../resources/examples/race-multi-endpoint.py) - Multi-endpoint races
