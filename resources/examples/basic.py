def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())


def handleResponse(req, interesting):
    # available: req.status, req.length, req.wordcount, req.response, req.time, req.request, req.label, etc
    if req.status != 404:
        table.add(req)
