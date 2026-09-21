# Infinite queuing example - uses while True so items are queued on-demand.
# engine.queue() blocks when the queue is full, providing natural backpressure.
# WARNING: never use 'for i in range(large_number)' - use xrange() instead to avoid a memory leak.
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           engine=Engine.THREADED,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    i = 0
    while True:
        engine.queue(target.req, str(i))
        i += 1


def handleResponse(req, interesting):
    if interesting:
        table.add(req)
