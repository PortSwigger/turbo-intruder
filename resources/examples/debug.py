def queueRequests(target, wordlists):
    # change Engine.THREADED to Engine.BURP to use Burp's stack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=1,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED
                           )
    engine.start()

    engine.queue(target.req)
    engine.queue(target.req)
    engine.queue(target.req)


def handleResponse(req, interesting):
    table.add(req)

