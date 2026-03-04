import sys
import json
import struct
import threading
import math
import random
import string
import re
import base64

rpc_futures = {}
rpc_id_counter = 1
rpc_lock = threading.Lock()
rpc_cond = threading.Condition(rpc_lock)

send_lock = threading.Lock()
original_stdout_buffer = sys.stdout.buffer

def send_rpc(method, params=None, id=None, result=None):
    msg = {"jsonrpc": "2.0"}
    if method is not None:
        msg["method"] = method
    if params is not None:
        msg["params"] = params
    if id is not None:
        msg["id"] = id
    if result is not None:
        msg["result"] = result
        
    data = json.dumps(msg).encode('utf-8')
    frame = struct.pack(">I", len(data)) + data
    with send_lock:
        original_stdout_buffer.write(frame)
        original_stdout_buffer.flush()

class BurpPrintRedirector:
    def write(self, text):
        if text.strip() != "":
            send_rpc("log", {"msg": str(text)})
    def flush(self):
        pass

sys.stdout = BurpPrintRedirector()

def call_rpc_sync(method, params):
    global rpc_id_counter
    with rpc_lock:
        req_id = str(rpc_id_counter)
        rpc_id_counter += 1
        rpc_futures[req_id] = None
    send_rpc(method, params, id=req_id)
    with rpc_lock:
        while req_id in rpc_futures and rpc_futures[req_id] is None:
            rpc_cond.wait()
        res = rpc_futures.pop(req_id, None)
    return res

# -------------------------------------------------------------
# API Parity with ScriptEnvironment.py
# -------------------------------------------------------------

def MatchRegex(regex):
    m = re.compile(str(regex), re.UNICODE|re.DOTALL|re.MULTILINE|re.IGNORECASE)
    def decorator(func):
        def handleResponse(req, interesting):
            if m.search(req.response):
                func(req, interesting)
        return handleResponse
    return decorator

def MatchStatus(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            if req.status in args:
                func(req, interesting)
        return handleResponse
    return decorator

def MatchSize(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            if req.length in args:
                func(req, interesting)
        return handleResponse
    return decorator

def MatchSizeRange(min_val, max_val):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.length >= min_val) and (req.length <= max_val)):
                func(req, interesting)
        return handleResponse
    return decorator

def MatchWordCount(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            if req.wordcount in args:
                func(req, interesting)
        return handleResponse
    return decorator

def MatchWordCountRange(min_val, max_val):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.wordcount >= min_val) and (req.wordcount <= max_val)):
                func(req, interesting)
        return handleResponse
    return decorator

def MatchLineCount(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            if req.linecount in args:
                func(req, interesting)
        return handleResponse
    return decorator

def MatchLineCountRange(min_val, max_val):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.linecount >= min_val) and (req.linecount <= max_val)):
                func(req, interesting)
        return handleResponse
    return decorator

def FilterStatus(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            if req.status in args:
                return
            func(req, interesting)
        return handleResponse
    return decorator

def FilterSize(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            if req.length in args:
                return
            func(req, interesting)
        return handleResponse
    return decorator

def FilterRegex(regex):
    m = re.compile(str(regex), re.UNICODE|re.DOTALL|re.MULTILINE|re.IGNORECASE)
    def decorator(func):
        def handleResponse(req, interesting):
            if not m.search(req.response):
                func(req, interesting)
        return handleResponse
    return decorator

def FilterSizeRange(min_val, max_val):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.length >= min_val) and (req.length <= max_val)):
                return
            func(req, interesting)
        return handleResponse
    return decorator

def FilterWordCount(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            if req.wordcount in args:
                return
            func(req, interesting)
        return handleResponse
    return decorator

def FilterWordCountRange(min_val, max_val):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.wordcount >= min_val) and (req.wordcount <= max_val)):
                return
            func(req, interesting)
        return handleResponse
    return decorator

def FilterLineCount(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            if req.linecount in args:
                return
            func(req, interesting)
        return handleResponse
    return decorator

def FilterLineCountRange(min_val, max_val):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.linecount >= min_val) and (req.linecount <= max_val)):
                return
            func(req, interesting)
        return handleResponse
    return decorator

CodeWords = {}
def UniqueWordCount(instances=1):
    def decorator(func):
        def handleResponse(req, interesting):
            global CodeWords
            codeword = str(req.status) + str(req.wordcount)
            if codeword in CodeWords:
                if CodeWords[codeword] >= instances:
                    return
                CodeWords[codeword] += 1
            else:
                CodeWords[codeword] = 1
            func(req, interesting)
        return handleResponse
    return decorator

CodeLines = {}
def UniqueLineCount(instances=1):
    def decorator(func):
        def handleResponse(req, interesting):
            global CodeLines
            codeline = str(req.status) + str(req.linecount)
            if codeline in CodeLines:
                if CodeLines[codeline] >= instances:
                    return
                CodeLines[codeline] += 1
            else:
                CodeLines[codeline] = 1
            func(req, interesting)
        return handleResponse
    return decorator

CodeLength = {}
def UniqueSize(instances=1):
    def decorator(func):
        def handleResponse(req, interesting):
            global CodeLength
            codelen = str(req.status) + str(req.length)
            if codelen in CodeLength:
                if CodeLength[codelen] >= instances:
                    return
                CodeLength[codelen] += 1
            else:
                CodeLength[codelen] = 1
            func(req, interesting)
        return handleResponse
    return decorator

def mean(data):
    return sum(data)/len(data) if len(data) > 0 else 0

def stddev(data):
    if len(data) <= 1:
        return 0
    avg = mean(data)
    base = sum((entry-avg)**2 for entry in data)
    return math.sqrt(base/(len(data)-1))

def randstr(length=12, allow_digits=True):
    candidates = string.ascii_lowercase
    if allow_digits:
        candidates += string.digits
    return ''.join(random.choice(candidates) for x in range(length))


class Engine:
    BURP = 1
    THREADED = 2
    HTTP2 = 3
    BURP2 = 4
    SPIKE = 5

class RequestEngine:
    # !! SYNC: If you change this __init__ signature (add/remove/rename parameters or change defaults),
    # !! you MUST make the identical change in RequestEngine.__init__ in resources/ScriptEnvironment.py.
    # !! See AGENTS.md § API SYNC RULE for full guidance.
    def __init__(self, endpoint, callback=None, engine=Engine.THREADED, concurrentConnections=50, requestsPerConnection=100, pipeline=False, maxQueueSize=100, timeout=10, maxRetriesPerRequest=3, idleTimeout=0, readCallback=None, readSize=1024, resumeSSL=True, autoStart=True, explodeOnEarlyRead=False, warmLocalConnection=True, fatPacket=False):
        self.endpoint = endpoint
        params = {
            "endpoint": endpoint,
            "engine": engine,
            "concurrentConnections": concurrentConnections,
            "requestsPerConnection": requestsPerConnection,
            "maxRetriesPerRequest": maxRetriesPerRequest,
            "idleTimeout": idleTimeout,
            "fixContentLength": True
        }
        call_rpc_sync("createEngine", params)

    def queue(self, template, payloads=None, learn=0, callback=None, gate=None, label="", pauseBefore=0, pauseTime=1000, pauseMarker=[], delay=0, endpoint=None, fixContentLength=True):
        if payloads is None:
            payloads = []
        elif not isinstance(payloads, list):
            payloads = [str(payloads)]
        
        params = {
            "template": template,
            "words": payloads,
            "learnBoring": learn,
            "gate": gate,
            "label": label,
            "pauseBefore": pauseBefore,
            "pauseTime": pauseTime,
            "pauseMarker": pauseMarker[0] if pauseMarker else None,
            "delay": delay,
            "endpoint": endpoint or self.endpoint
        }
        send_rpc("queue", params)

    def openGate(self, gate):
        send_rpc("openGate", {"gate": gate})

    def applySetting(self, settingName, settingValue):
        send_rpc("applySetting", {"name": settingName, "value": settingValue})

    def start(self, timeout=5):
        pass

    def complete(self, timeout=-1):
        call_rpc_sync("complete", {"timeout": timeout})

    def cancel(self):
        send_rpc("cancel", {})

class Target:
    def __init__(self, req, rawReq, endpoint, host, baseInput):
        self.req = req
        self.rawReq = rawReq
        self.endpoint = endpoint
        self.host = host
        self.baseInput = baseInput

class RequestResponse:
    def __init__(self, params):
        self.id = params.get("id")
        self.status = params.get("status", 0)
        self.length = params.get("length", 0)
        self.wordcount = params.get("wordcount", 0)
        self.linecount = params.get("linecount", 0)
        self.time = params.get("time", 0)
        self.label = params.get("label", "")
        self.interesting = params.get("interesting", False)
        self._response_body = None

    @property
    def response(self):
        if self._response_body is None:
            res_b64 = call_rpc_sync("fetchBody", {"reqId": self.id})
            if res_b64:
                try:
                    self._response_body = base64.b64decode(res_b64).decode('iso-8859-1')
                except Exception as e:
                    self._response_body = ""
            else:
                self._response_body = ""
        return self._response_body

class Table:
    def add(self, req):
        send_rpc("addResult", {"id": req.id})

class WordlistDict:
    def __getattr__(self, name):
        return []

user_script_env = {}

def do_init(params):
    global user_script_env
    script_code = params.get("script", "")
    target = Target(
        req=params.get("req"),
        rawReq=params.get("rawReq"),
        endpoint=params.get("endpoint"),
        host=params.get("host"),
        baseInput=params.get("baseInput")
    )
    
    user_script_env.update({
        "RequestEngine": RequestEngine,
        "Engine": Engine,
        "MatchRegex": MatchRegex,
        "MatchStatus": MatchStatus,
        "MatchSize": MatchSize,
        "MatchSizeRange": MatchSizeRange,
        "MatchWordCount": MatchWordCount,
        "MatchWordCountRange": MatchWordCountRange,
        "MatchLineCount": MatchLineCount,
        "MatchLineCountRange": MatchLineCountRange,
        "FilterStatus": FilterStatus,
        "FilterSize": FilterSize,
        "FilterRegex": FilterRegex,
        "FilterSizeRange": FilterSizeRange,
        "FilterWordCount": FilterWordCount,
        "FilterWordCountRange": FilterWordCountRange,
        "FilterLineCount": FilterLineCount,
        "FilterLineCountRange": FilterLineCountRange,
        "UniqueWordCount": UniqueWordCount,
        "UniqueLineCount": UniqueLineCount,
        "UniqueSize": UniqueSize,
        "mean": mean,
        "stddev": stddev,
        "randstr": randstr,
        "table": Table(),
        "wordlists": WordlistDict(),
        "target": target,
        "__builtins__": __builtins__
    })
    
    try:
        exec(script_code, user_script_env)
        if "queueRequests" in user_script_env:
            user_script_env["queueRequests"](target, user_script_env["wordlists"])
    except Exception as e:
        print("Python3 Error: " + str(e))

def do_handle_response(params):
    if "handleResponse" in user_script_env:
        req = RequestResponse(params)
        try:
            user_script_env["handleResponse"](req, params.get("interesting", False))
        except Exception as e:
            print("Python3 Error in handleResponse: " + str(e))

def handle_message(msg):
    if "result" in msg and "id" in msg:
        with rpc_lock:
            rpc_futures[msg["id"]] = msg["result"]
            rpc_cond.notify_all()
    elif "method" in msg:
        if msg["method"] == "init":
            threading.Thread(target=do_init, args=(msg["params"],), daemon=True).start()
        elif msg["method"] == "handleResponse":
            threading.Thread(target=do_handle_response, args=(msg["params"],), daemon=True).start()
        elif msg["method"] == "done":
            sys.exit(0)

def receive_loop():
    while True:
        len_buf = sys.stdin.buffer.read(4)
        if not len_buf or len(len_buf) < 4:
            break
        frame_len = struct.unpack(">I", len_buf)[0]
        data = sys.stdin.buffer.read(frame_len)
        if len(data) < frame_len:
            break
        try:
            msg = json.loads(data.decode('utf-8'))
            handle_message(msg)
        except Exception as e:
            print("Python3 RPC Error: " + str(e))

if __name__ == "__main__":
    receive_loop()
