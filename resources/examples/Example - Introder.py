# Turbo Intruder — Introder

WORDLIST = "D:\\Applications\\Wordlists\\SecLists-master\\Usernames\\top-usernames-shortlist.txt"   # <-- set your path (use forward slashes or double backslash)

def load_lines(p):
    return [l.rstrip() for l in open(p.replace("\\","/"), "r").readlines() if l.rstrip()]

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            autoStart=True,           # I tested it with different values, let it be autoStart
                            concurrentConnections=40, # Modify Based on your list length
                            requestsPerConnection=1,  # Modify Based on your list length
                            pipeline=False)
    words = load_lines(WORDLIST);

    for w in words:
        engine.queue(target.req, w, gate="g1")   # queue with gate name
    engine.openGate("g1")
    
def handleResponse(req, interesting):
    table.add(req)