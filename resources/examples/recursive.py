def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint)
    engine.start()
    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())


def handleResponse(req, interesting):
    if '404 Not Found' not in req.response:
        table.add(req)
        for word in open('/usr/share/dict/words'):
            req.engine.queue(req.template, req.word+'/'+word.rstrip())
