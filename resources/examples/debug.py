# Use this to debug issues with Turbo Intruder connecting to sites
# If this script as-is fails, try changing Engine.THREADED to Engine.BURP
# If that makes it work, file a report on http://github.com/PortSwigger/turbo-intruder/issues
# Please include the target request/domain, and your OS and Java version from Help->Diagnostics
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=1,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED
                           )
    engine.start()

    engine.queue(target.req)
    engine.queue(target.req)
    engine.queue(target.req)


def handleResponse(req, interesting):
    table.add(req)

