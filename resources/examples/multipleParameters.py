def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for firstWord in open('/usr/share/dict/words'):
      for secondWord in open('/usr/share/dict/american-english'):
        engine.queue(target.req, [firstWord.rstrip(), secondWord.rstrip()])


def handleResponse(req, interesting):
    # available: req.status, req.length, req.wordcount, req.response, req.time, req.request, req.label, etc
    if req.status != 404:
        table.add(req)
