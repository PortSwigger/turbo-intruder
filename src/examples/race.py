
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False,
                           maxQueueSize=-1
                           )
    # queue up attacks before launching engine.start
    for i in range(30):
        engine.queue(target.req, target.baseInput)

    engine.start(timeout=5)
    engine.complete(timeout=60)


def handleResponse(req, interesting):
    table.add(req)
