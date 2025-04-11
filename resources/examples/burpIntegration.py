def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           engine=Engine.BURP # Use Burp's HTTP/1 network stack, including upstream proxies etc. You can also use Engine.BURP2 for HTTP/2.
                           )


    # generate a collaborator domain - interactions will appear in the Collaborator tab
    collabDomain = api.collaborator().defaultPayloadGenerator().generatePayload()

    for i in range(3, 8):
        engine.queue(target.req, randstr(i), learn=1)

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if interesting:
        table.add(req)
        callbacks.addToSiteMap(req.getBurpRequest())
        # You can also trigger scans, report issues, send to spider, etc:
        # https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html
