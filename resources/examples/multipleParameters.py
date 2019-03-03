def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    engine.start()

    for firstWord in open('/usr/share/dict/words'):
      for secondWord in open('/usr/share/dict/american-english'):
        engine.queue(target.req, [firstWord.rstrip(), secondWord.rstrip()])


def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    if req.status != 404:
        table.add(req)
