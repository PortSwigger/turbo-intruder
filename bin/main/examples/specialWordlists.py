def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    # regular wordlist
    for line in open('disc_words.txt'):
        engine.queue(target.req, line.rstrip())

    # clipboard, split on lines
    for word in wordlists.clipboard:
        engine.queue(target.req, word)

    # list of all words observed during passive scans
    for word in wordlists.observedWords:
        engine.queue(target.req, word)

    # infinitely-running bruteforce (a, b ... aaa, aab etc)
    seed = 0
    while True:
        batch = []
        seed = wordlists.bruteforce.generate(seed, 5000, batch)
        for word in batch:
            engine.queue(target.req, word)


def handleResponse(req, interesting):
    table.add(req)
