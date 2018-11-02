import time

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           maxQueueSize=10,
                           )
    engine.start()

    for i in range(5):
        engine.queue(req, randstr(i), learn=1)
        engine.queue(req, target.baseInput, learn=2)

    for word in open('wordlist.txt'):
        engine.queue(req, word.rstrip())


def handleResponse(req, interesting):
    if interesting:
        table.add(req)
