# Find more advanced sample attacks at skeletonscribe.net/turbo
def queueRequests():
    engine = RequestEngine(target=target,
                           callback=handleResponse,
                           engine=Engine.THREADED,  # {BURP, THREADED}
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False,
                           queueSize=10
                           )

    engine.start(timeout=5)
    req = helpers.bytesToString(baseRequest)

    for word in open('/Users/james/Dropbox/lists/favourites/disc_words.txt'):
        engine.queue(req, word.rstrip())



def handleResponse(req, interesting):
    table.add(req)
