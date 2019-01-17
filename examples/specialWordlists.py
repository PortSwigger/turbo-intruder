
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False,
                           maxQueueSize=10,
                           timeout=5,
                           maxRetriesPerRequest=3
                           )

    engine.start()

    # regular wordlist
    for line in open('/Users/james/Dropbox/lists/favourites/disc_words.txt'):
        engine.queue(req, line.rstrip())

    # list of all words observed in traffic
    for word in wordlists.observedWords:
        engine.queue(req, word)

    # infinitely-running bruteforce (a, b ... aaa, aab etc)
    seed = 0
    while True:
        batch = []
        seed = wordlists.bruteforce.generate(seed, 5000, batch)
        for word in batch:
            engine.queue(target.req, word)


def handleResponse(req, interesting):
    table.add(req)
