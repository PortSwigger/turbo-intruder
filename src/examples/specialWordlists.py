
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

    # regular wordlist
    for line in open('/Users/james/Dropbox/lists/favourites/disc_words.txt'):
        engine.queue(req, line.rstrip())

    # list of all words observed in traffic
    for word in observedWords:
        engine.queue(req, word)

    # infinitely-running bruteforce (a, b ... aaa, aab etc)
    seed = 0
    while True:
        batch = []
        seed = bruteforce.generate(seed, 5000, batch)
        for word in batch:
            engine.queue(req, word)


def handleResponse(req, interesting):
    table.add(req)
