# This is just for making sure the engine works during development
# Launch with java -jar build/libs/turbo-intruder-all.jar resources/examples/test.py /dev/null z z
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint='https://hackxor.net:443',
                           concurrentConnections=1,
                           requestsPerConnection=10,
                           pipeline=False
                           )
    engine.start()

    noPayload = '''GET /static/404 HTTP/1.1
Host: hackxor.net
Connection: close

'''
    engine.queue(noPayload)

    onePayload = '''GET /static/404?q=%s HTTP/1.1
Host: hackxor.net
Connection: close

'''
    engine.queue(onePayload, 'one payload')

    twoPayloads = '''GET /static/404?q=%s HTTP/1.1
Host: hackxor.net
Connection: close

'''

    engine.queue(twoPayloads, ['first payload', 'second payload'])



def handleResponse(req, interesting):
    table.add(req)
