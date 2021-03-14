def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    payload1 = []
    payload2 = []
    for eachWord in open('/usr/share/dict/numbers.txt'):
        payload1.append(eachWord)
    for eachWord in open('/usr/share/dict/posspass.txt'):
        payload2.append(eachWord)
    for i in range(0,len(payload2) if(len(payload2)<=len(payload1)) else len(payload1)):
        # execute till the length of smaller payload.
        engine.queue(target.req, [payload1[i], payload2[i]])


def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    if req.status != 404:
        table.add(req)
