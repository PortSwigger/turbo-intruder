def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, # this is just a protocol:domain:port string like https://example.com:443
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False,
                           maxQueueSize=10,
                           timeout=5,
                           maxRetriesPerRequest=3
                           )
    engine.start()

    # You can queue arbitrary requests - you don't have to use the insertion point
    oddRequest = """GET /static/style.css HTTP/1.1
Host: hackxor.net

"""
    engine.queue(oddRequest)

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())


def handleResponse(req, interesting):
    if '404 Not Found' not in req.response:
        table.add(req)
