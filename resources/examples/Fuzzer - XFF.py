# It first splits the request headers. If it finds X-Forwarded-For,
    # it replaces its value with %s; otherwise it adds the X-Forwarded-For: %s header.
# Then it queues the template for every IP from 127.0.0.1 to 127.0.0.255.

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10, requestsPerConnection=1, pipeline=False)
    base = target.req
    parts = base.split("\r\n\r\n", 1)
    headers = parts[0].split("\r\n")
    body = parts[1] if len(parts) > 1 else ""

    found = False
    for i in range(len(headers)):
        if headers[i].lower().startswith("x-forwarded-for:"):
            headers[i] = "X-Forwarded-For: %s"
            found = True
            break
    if not found:
        headers.append("X-Forwarded-For: %s")

    template = "\r\n".join(headers) + "\r\n\r\n" + body
    for n in range(1, 256):
        engine.queue(template, "127.0.0.%d" % n)


def handleResponse(req, _):
    table.add(req)
