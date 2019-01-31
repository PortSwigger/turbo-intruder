# Please note the stats panel won't reflect reality on multi-host attacks, and this example script isn't optimised for scale
def queueRequests(target, wordlists):
    base_req = '''GET / HTTP/1.1
Host: %s.hostname
Connection: keep-alive

'''
    for domain in open('your domain list here'):
        engine = RequestEngine(endpoint='https://'+domain+':443')
        engine.start()

        req = base_req.replace('hostname', domain)

        for i in range(3, 8):
            engine.queue(req, randstr(i), learn=1)

        for word in open('/usr/share/dict/words'):
            engine.queue(req, word.rstrip())


def handleResponse(req, interesting):
    if interesting:
        table.add(req)