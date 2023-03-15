# Author: https://github.com/abiwaddell
# Throttle the attack per-request, and per X requests.
# Full description at https://github.com/abiwaddell/Run-Pause-Resume
import time

# Parameters to configure
triedWords=20
timeMins=0
timeSecs=5
throttleMillisecs=200

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           pipeline=False,
                           engine=Engine.BURP
                           )

    for i in range(3, 8):
        engine.queue(target.req, randstr(i), learn=1)
        engine.queue(target.req, target.baseInput, learn=2)

    secs=timeMins*60+timeSecs
    n=0
    for word in open('words.txt'):
        time.sleep(throttleMillisecs/1000)
        engine.queue(target.req, word.rstrip())
        n+=1
        if(n==triedWords):
            time.sleep(secs)
            n=0

def handleResponse(req, interesting):
    if interesting:
        table.add(req)