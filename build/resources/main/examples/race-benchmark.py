from decimal import *

def queueRequests(target, wordlists):
    req = '''GET /time.php HTTP/1.1
Host: portswigger-labs.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:67.0) Gecko/20100101 Firefox/67.0
Connection: keep-alive

'''

    window = []
    samples = 30
    for i in range(samples):

        engine = RequestEngine(endpoint='https://portswigger-labs.net:443',
                               concurrentConnections=5,
                               requestsPerConnection=1,
                               pipeline=False
                               )
        engine.userState['results'] = []
        engine.userState['window'] = window

        for k in range(5):
            engine.queue(req, gate='race1')

        engine.openGate('race1')

        engine.complete(timeout=60)

    window.sort()
    print max(window)
    print min(window)
    print window[(samples/2)-1]


def handleResponse(req, interesting):
    table.add(req)
    timestamp = req.response.splitlines()[-1].rstrip('\x00')
    req.engine.userState['results'].append(Decimal(timestamp))
    if len(req.engine.userState['results']) == 5:
        sorted = req.engine.userState['results']
        sorted.sort()
        req.engine.userState['window'].append(sorted[1] - sorted[0])
