# Content-Length Brute Force
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1,
                           pipeline=False)

    base = target.req
    parts = base.split("\r\n\r\n", 1)
    headers = parts[0].split("\r\n")
    body = parts[1] if len(parts) > 1 else ""

    # replace existing Content-Length line with an injection marker, or add it
    found = False
    for i in range(len(headers)):
        if headers[i].lower().startswith("content-length:"):
            headers[i] = "Content-Length: %s"
            found = True
            break
    if not found:
        headers.append("Content-Length: %s")

    template = "\r\n".join(headers) + "\r\n\r\n" + body

    # queue requests: Turbo Intruder will replace %s with each payload value
    for n in range(1746, 1801):
        engine.queue(template, str(n),fixContentLength=False)


def handleResponse(req, interesting):
    table.add(req)