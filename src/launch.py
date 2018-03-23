import req.RequestEngine
from urlparse import urlparse

def handleResponse(req, resp):
    code = resp.split(' ', 2)[1]
    if code != '404':
        print(code + ': '+req.split('\r', 1)[0])

def queueRequests(target, urlfile, threads, readFreq, requestsPerConnection):
    engine = req.AsyncRequestEngine(target, threads, readFreq, requestsPerConnection, handleResponse)
    engine.start()
    requests = 0
    with open(urlfile) as file:
        for line in file:
            requests+=1
            url = urlparse(line.rstrip())
            engine.queue('GET %s?%s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n' % (url.path, url.query, url.netloc))

    engine.getResult(requests)
