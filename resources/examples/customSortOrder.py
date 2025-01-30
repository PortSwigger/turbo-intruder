def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint)

    # sort by the first column in descending order
    table.setSortOrder(0, False)

    while True:
        engine.queue(target.req)
        time.sleep(0.1)

def handleResponse(req, interesting):
    table.add(req)
