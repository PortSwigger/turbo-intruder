# Turbo Intruder — one gate per file, safe sub-batching to avoid deadlock
import os
from time import sleep

WORDLIST_DIR = "D:\\Research\\Notes\\race conditions\\wordlist"    # <-- folder with files
CONNECTIONS = 100            # concurrentConnections (tune)
REQ_PER_CONNECTION = 40     # Request per connections (tune)
HTTP_PIPE_LINE = True # Tune
DELAY_AFTER_START = 0.1     #  (tune)
DELAY_BETWEEN_GATES = 0.1      #  (tune)

def load_lines(fp):
    out = []
    try:
        f = open(fp, "r")
        for line in f:
            v = line.rstrip()
            if v:
                out.append(v)
        f.close()
    except:
        pass
    return out

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           autoStart=False,
                           concurrentConnections=CONNECTIONS,
                           requestsPerConnection=REQ_PER_CONNECTION,
                           pipeline=HTTP_PIPE_LINE)

    base = target.req
    if "__PAYLOAD__" not in base:
        print("ERROR: put __PAYLOAD__ in request"); return
    template = base.replace("__PAYLOAD__", "%s")

    d = WORDLIST_DIR.replace("\\", "/")
    try:
        names = sorted(os.listdir(d))
    except Exception as e:
        print("ERROR reading folder:", str(e)); return

    # start engine once
    try:
        engine.start()
    except:
        pass
    sleep(DELAY_AFTER_START)

    total = 0
    file_index = 0

    for name in names:
        fp = d + "/" + name
        if not os.path.isfile(fp):
            continue
        payloads = load_lines(fp)
        if not payloads:
            continue
        file_index += 1

        # process this file in sub-batches sized <= CONCURRENCY
        start = 0
        part = 0
        while start < len(payloads):
            part += 1
            end = start + CONNECTIONS
            chunk = payloads[start:end]
            gid = "f%d_p%d" % (file_index, part)   # string gate id

            # queue this chunk under gid
            for p in chunk:
                try:
                    engine.queue(template, p, gate=str(gid))
                    total += 1
                except Exception as e:
                    print("queue error:", str(e)); return

            # open this gid immediately so we don't accumulate too many gated requests
            try:
                engine.openGate(gid)
            except Exception:
                try:
                    engine.openGate(str(gid))
                except:
                    print("openGate failed for", gid)
            sleep(DELAY_BETWEEN_GATES)

            start = end

    print("Queued and released %d payloads from %d files" % (total, file_index))
def handleResponse(req, interesting):
    table.add(req)