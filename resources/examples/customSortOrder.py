def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint)

    # sort by the first column in descending order
    # note this also disables the auto-sort by anomaly rank on attack completion
    table.setSortOrder(0, False)

    while True:
        engine.queue(target.req)
        time.sleep(0.1)

def handleResponse(req, interesting):
    table.add(req)
