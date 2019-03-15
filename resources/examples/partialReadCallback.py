def queueRequests(target, wordlists):
    global engine
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=2,
                           readCallback=handleRead,
                           readSize=256, # TCP socket buffer size - the server may choose to send less
                           )
    engine.start()

    engine.queue(target.req)

# data is *just* the last socket read contents
# so if you're really unlucky your token might get split over two reads
def handleRead(data):
    if 'token' in data:
        engine.queue('something-using-the-token')
        time.sleep(1) # this will delay the remaining reads on this response

def handleResponse(req, interesting):
    table.add(req)
