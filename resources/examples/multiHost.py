# Please note the stats panel won't reflect reality on multi-host attacks
def queueRequests(target, wordlists):
    req = '''GET / HTTP/1.1
Host: %s
Connection: keep-alive

'''
    engines = {}
    for domain in open('/tmp/domains'):
        domain = domain.rstrip()
        engine = RequestEngine(endpoint='https://'+domain+':443')
        engine.start()
        engines[domain] = engine

    for i in range(3, 8):
        for (domain, engine) in engines.items():
            engine.queue(req, randstr(i)+'.'+domain, learn=1)

    for word in open('/tmp/words'):
        word = word.rstrip()
        for (domain, engine) in engines.items():
            engine.queue(req, word+'.'+domain)


def handleResponse(req, interesting):
    if interesting:
        table.add(req)