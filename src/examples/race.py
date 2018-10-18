
def queueRequests():
    engine = RequestEngine(target=target,
                           callback=handleResponse,
                           engine=Engine.THREADED,  # {BURP, THREADED, ASYNC, HTTP2}
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False,
                           queueSize=-1
                           )


    req = helpers.bytesToString(baseRequest)

    # queue up attacks before launching engine.start
    for i in range(30):
        engine.queue(req, baseInput)

    engine.start(timeout=5)
    engine.complete(timeout=60)


def handleResponse(req, interesting):
    table.add(req)
