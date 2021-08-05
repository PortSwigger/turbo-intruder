def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           engine=Engine.HTTP2 # To use Burp's HTTP/2 stack instead, use Engine.BURP2
                           )

     # When using either HTTP/2 engine, the following rewrites are performed:
     # ^ -> \r
     # ~ -> \n
     # ` -> :
     # You can override pseudo-headers by specifying them like normal headers
     # eg ':path: /robots.txt'

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())


def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    if req.status != 404:
        table.add(req)
