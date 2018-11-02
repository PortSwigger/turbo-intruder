# Find more advanced sample attacks at skeletonscribe.net/turbo
def queueRequests():
    engine = RequestEngine(target=target,
                           engine=Engine.THREADED,  # {BURP, THREADED}
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False,
                           queueSize=10
                           )

    engine.start(timeout=5)
    req = helpers.bytesToString(baseRequest)

    for word in open('wordlist.txt'):
        engine.queue(req, word.rstrip())

def handleResponse(req, interesting):
    if '200 OK' in req.response:
        table.add(req)
