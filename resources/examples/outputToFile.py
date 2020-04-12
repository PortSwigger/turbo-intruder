# Find more example scripts at https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for i in range(3, 8):
        engine.queue(target.req, randstr(i), learn=1)
        engine.queue(target.req, target.baseInput, learn=2)

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())


def handleResponse(req, interesting):
    if interesting:
        table.add(req)
        
        data = req.response.encode('utf8')
        
        # Extract header and body
        header, _, body = data.partition('\r\n\r\n')
        
        # Save body to file /tmp/output-turbo.txt
        output_file = open("/tmp/output-turbo.txt","a+")
        output_file.write(body + "\n")
        output_file.close()
