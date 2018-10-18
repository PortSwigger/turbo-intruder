
def queueRequests():
    engine = RequestEngine(target=target,
                           callback=handleResponse,
                           engine=Engine.THREADED,  # {BURP, THREADED, ASYNC, HTTP2}
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False,
                           queueSize=10
                           )

    engine.start(timeout=5)
    req = helpers.bytesToString(baseRequest)

    for line in open('/Users/james/Dropbox/lists/favourites/disc_words.txt'):
        engine.queue(req, line.rstrip())

    engine.complete(timeout=6000)


def handleResponse(req, interesting):
    if interesting:
        table.add(req)
