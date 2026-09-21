def queueRequests(target, wordlists):

    # 'auto' uses the QPACK blocked-stream gate where the server advertises support for it, and
    # the single-datagram gate otherwise
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP3, #Requires Burp Suite Professional
                           gateMode='auto' #Force with 'sda' or 'qpack'
                           )

    for i in xrange(20):
        engine.queue(target.req, gate='race1')

    # once every 'race1' tagged request has been queued
    # invoke engine.openGate() to send them in sync
    engine.openGate('race1')


def handleResponse(req, interesting):
    table.add(req)
