def queueRequests(target, wordlists):

    global BATCH_SIZE
    BATCH_SIZE = 20


    engine = RequestEngine(endpoint='https://x.psres.net:443',
                           concurrentConnections=1,
                           requestsPerConnection=1000,
                           engine=Engine.BURP2,
                           pipeline=False,
                           maxQueueSize=BATCH_SIZE
                           )


    req = '''GET /wtf/?nottime=%s HTTP/2
Host: x.psres.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Cache-Control: max-age=0

'''

    for i in range(10):
        gate_id = str(i)

        for x in range(BATCH_SIZE):
            engine.queue(req, '0.000', gate=gate_id)

        engine.openGate(gate_id)
        time.sleep(0.5)


def handleResponse(req, interesting):
    xtime= req.response.split('\r\n\r\n')[1]
    req.label = xtime
    table.add(req)


def completed(reqsFromTable):
    diffs = []
    time.sleep(1)
    print len(reqsFromTable)
    for i in range(len(reqsFromTable)):
        if i % BATCH_SIZE != 0:
            continue

        entries = []
        for x in range(BATCH_SIZE):
            entries.append(float(reqsFromTable[i+x].label))

        entries.sort()
        diffs.append(entries[-1] - entries[0])

    diffs.sort()
    print('Best: '+str(min(diffs)))
    print('Mean: '+str(mean(diffs)))
    print('Stddev: '+str(stddev(diffs)))
    print('Median: '+str(diffs[len(diffs)/2]))
    print('Range: '+str(max(diffs)-min(diffs)))
    handler.setMessage(str(sum(diffs)/len(diffs)))