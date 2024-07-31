import math

def queueRequests(target, wordlists):

    LEFT_PAYLOAD = 'changeme' # you can use $randomplz to bypass caching
    RIGHT_PAYLOAD = 'changeme2' # you can use $randomplz to bypass caching

    REPEATS = 100 # more repeats takes longer, but reduces chance of incorrect results
    DELAY  = 0.2 # timing attacks don't work if you trigger a server rate-limit.

    engineType = Engine.BURP
    connections = 2
    if target.req.split('\r\n', 1)[0].endswith('HTTP/2'):
        engineType = Engine.BURP2
        connections = 1


    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=connections,
                           requestsPerConnection=100,
                           engine=engineType,
                           maxQueueSize=2,
                           timeout=3
                           )

    attack = target.req


    left_attack =  attack.replace('%s', LEFT_PAYLOAD)
    right_attack = attack.replace('%s', RIGHT_PAYLOAD)

    # alternate order to prevent order-FPs - see 'sticky ordering problem'
    for i in range(REPEATS):
        gate_id = str(i)
        if (i % 2 == 1):
            engine.queue(left_attack, gate=gate_id, label='left-first')
            engine.queue(right_attack, gate=gate_id, label='right-second')
        else:
            engine.queue(right_attack, gate=gate_id, label='right-first')
            engine.queue(left_attack, gate=gate_id, label='left-second')

        engine.openGate(gate_id)
        time.sleep(DELAY*2)


def handleResponse(req, interesting):
    table.add(req)

def completed(reqsFromTable):
    left_times = []
    left_first = 0
    right_times = []
    right_first = 0
    diffs = []
    first_won = 0
    second_won = 0
    for req in reqsFromTable:
        if req.order == 0:
            if req.label.endswith('first'):
                first_won += 1
            else:
                second_won += 1

        if req.label.startswith('left'):
            left_times.append(req.time)
            if req.order == 0:
                left_first += 1
        else:
            right_times.append(req.time)
            if req.order == 0:
                right_first += 1

        if len(right_times) == len(left_times):
            diffs.append(right_times[-1]-left_times[-1])

    left_times.sort()
    right_times.sort()
    diffs.sort()
    compare = int(100 - (float(min(left_first, right_first)) / (left_first+right_first)*2)*100)
    ranges = '[{0}-{1}, {2}-{3}]'.format((left_times[0]), left_times[int(math.floor(len(left_times)/5))], right_times[0], right_times[int(math.floor(len(right_times)/5))])
    output = "Confidence: {0}%   Split: [{1}|{2}]   Bias: [{3}|{4}]   Max-jitter: {5}   Ranges: {6}".format(compare, left_first, right_first, first_won, second_won, max(max(left_times)-min(left_times), max(right_times)-min(right_times)), ranges)
    print(output)
    handler.setMessage(output)
    time.sleep(0.5)
    handler.setMessage(output)