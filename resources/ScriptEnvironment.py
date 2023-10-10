import burp.RequestEngine, burp.Args, string, random, time, math, re

def MatchRegex(regex):
    m = re.compile(unicode(regex), re.UNICODE|re.DOTALL|re.MULTILINE|re.IGNORECASE)
    def decorator(func):
        def handleResponse(req, interesting):
            if m.match(req.response):
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

def MatchSizeRange(min, max):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.length >= min) and (req.length <= max)):
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

def MatchWordCountRange(min, max):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.wordcount >= min) and (req.wordcount <= max)):
                func(req, interesting)
        return handleResponse
    return decorator

def MatchLineCount(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            linecount = len(req.response.split('\n'))
            if linecount in args:
                func(req, interesting)
        return handleResponse
    return decorator

def MatchLineCountRange(min, max):
    def decorator(func):
        def handleResponse(req, interesting):
            linecount = len(req.response.split('\n'))
            if ((linecount >= min) and (linecount <= max)):
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
    m = re.compile(unicode(regex), re.UNICODE|re.DOTALL|re.MULTILINE|re.IGNORECASE)
    def decorator(func):
        def handleResponse(req, interesting):
            if not m.match(req.response):
                func(req, interesting)
        return handleResponse
    return decorator

def FilterSizeRange(min, max):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.length >= min) and (req.length <= max)):
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

def FilterWordCountRange(min, max):
    def decorator(func):
        def handleResponse(req, interesting):
            if ((req.wordcount >= min) and (req.wordcount <= max)):
                return
            func(req, interesting)
        return handleResponse
    return decorator

def FilterLineCount(*args):
    def decorator(func):
        def handleResponse(req, interesting):
            linecount = len(req.response.split('\n'))
            if linecount in args:
                return
            func(req, interesting)
        return handleResponse
    return decorator

def FilterLineCountRange(min, max):
    def decorator(func):
        def handleResponse(req, interesting):
            linecount = len(req.response.split('\n'))
            if ((linecount >= min) and (linecount <= max)):
                return
            func(req, interesting)
        return handleResponse
    return decorator

def UniqueWordCount(instances=1):
    def decorator(func):
        def handleResponse(req, interesting):
            global CodeWords
            try:
                CodeWords
            except:
                CodeWords = {}

            if "lastreq" in CodeWords:
                currreqs = req.engine.engine.successfulRequests.intValue()
                lastreqs = CodeWords["lastreq"]
                if currreqs < lastreqs:
                    CodeWords = {}
                    CodeWords["lastreq"] = currreqs
            CodeWords["lastreq"] = req.engine.engine.successfulRequests.intValue()

            codeword = str(req.status) + str(req.wordcount)
            if codeword in CodeWords:
                if CodeWords[codeword] >= instances:
                    return
                else:
                    CodeWords[codeword] += 1
            else:
                CodeWords[codeword] = 1
            func(req, interesting)
        return handleResponse
    return decorator

def UniqueLineCount(instances=1):
    def decorator(func):
        def handleResponse(req, interesting):
            global CodeLines
            try:
                CodeLines
            except:
                CodeLines = {}

            if "lastreq" in CodeLines:
                currreqs = req.engine.engine.successfulRequests.intValue()
                lastreqs = CodeLines["lastreq"]
                if currreqs < lastreqs:
                    CodeLines = {}
                    CodeLines["lastreq"] = currreqs
            CodeLines["lastreq"] = req.engine.engine.successfulRequests.intValue()

            linecount = len(req.response.split('\n'))
            codeline = str(req.status) + str(linecount)
            if codeline in CodeLines:
                if CodeLines[codeline] >= instances:
                    return
                else:
                    CodeLines[codeline] += 1
            else:
                CodeLines[codeline] = 1
            func(req, interesting)
        return handleResponse
    return decorator

def UniqueSize(instances=1):
    def decorator(func):
        def handleResponse(req, interesting):
            global CodeLength
            try:
                CodeLength
            except:
                CodeLength = {}

            if "lastreq" in CodeLength:
                currreqs = req.engine.engine.successfulRequests.intValue()
                lastreqs = CodeLength["lastreq"]
                if currreqs < lastreqs:
                    CodeLength = {}
                    CodeLength["lastreq"] = currreqs

            CodeLength["lastreq"] = req.engine.engine.successfulRequests.intValue()

            codelen = str(req.status) + str(req.length)
            if codelen in CodeLength:
                if CodeLength[codelen] >= instances:
                    return
                else:
                    CodeLength[codelen] += 1
            else:
                CodeLength[codelen] = 1
            func(req, interesting)
        return handleResponse
    return decorator

def mean(data):
    return sum(data)/len(data)

def stddev(data):
    if len(data) == 1:
        return 0
    avg = mean(data)
    base = sum((entry-avg)**2 for entry in data)
    return math.sqrt(base/(len(data)-1))

def randstr(length=12, allow_digits=True):
    candidates = string.ascii_lowercase
    if allow_digits:
        candidates += string.digits
    return ''.join(random.choice(candidates) for x in range(length))

def queueForever(engine, req):
    # infinitely-running bruteforce (a, b ... aaa, aab etc)
    seed = 0
    while True:
        batch = []
        seed = wordlists.bruteforce.generate(seed, 5000, batch)
        for word in batch:
            engine.queue(target.req, word)

class Engine:
    BURP = 1
    THREADED = 2
    HTTP2 = 3
    BURP2 = 4
    SPIKE = 5

class RequestEngine:

    def __init__(self, endpoint, callback=None, engine=Engine.THREADED, concurrentConnections=50, requestsPerConnection=100, pipeline=False, maxQueueSize=100, timeout=10, maxRetriesPerRequest=3, idleTimeout=0, readCallback=None, readSize=1024, resumeSSL=True, autoStart=True, explodeOnEarlyRead=False, warmLocalConnection=True):
        concurrentConnections = int(concurrentConnections)
        requestsPerConnection = int(requestsPerConnection)

        if not callback:
            callback = handleResponse

        if pipeline > 1:
            readFreq = int(pipeline)
        elif pipeline:
            readFreq = requestsPerConnection
        else:
            readFreq = 1

        if (engine == Engine.BURP or engine == Engine.BURP2):
            if(engine == Engine.BURP and (requestsPerConnection > 1 or pipeline)):
                print('requestsPerConnection has been forced to 1 and pipelining has been disabled due to Burp engine limitations')
            if(readCallback != None):
                print('Read callbacks are not supported in the Burp request engine. Try Engine.THREADED instead.')

        if(engine == Engine.BURP):
            self.engine = burp.BurpRequestEngine(endpoint, concurrentConnections, maxQueueSize, maxRetriesPerRequest, idleTimeout, callback, readCallback, True)
        elif(engine == Engine.BURP2):
            self.engine = burp.BurpRequestEngine(endpoint, concurrentConnections, maxQueueSize, maxRetriesPerRequest, idleTimeout, callback, readCallback, False)
        elif(engine == Engine.THREADED):
            self.engine = burp.ThreadedRequestEngine(endpoint, concurrentConnections, maxQueueSize, readFreq, requestsPerConnection, maxRetriesPerRequest, idleTimeout, callback, timeout, readCallback, readSize, resumeSSL, explodeOnEarlyRead)
        elif(engine == Engine.HTTP2):
            self.engine = burp.HTTP2RequestEngine(endpoint, concurrentConnections, maxQueueSize, requestsPerConnection, maxRetriesPerRequest, idleTimeout, callback, readCallback)
        elif(engine == Engine.SPIKE):
            self.engine = burp.SpikeEngine(endpoint, concurrentConnections, maxQueueSize, requestsPerConnection, maxRetriesPerRequest, idleTimeout, callback, readCallback, warmLocalConnection)
        else:
            print('Unrecognised engine. Valid engines are Engine.BURP, Engine.THREADED')

        handler.setRequestEngine(self.engine)
        self.engine.setOutput(outputHandler)
        self.userState = self.engine.userState
        self.autoStart = False
        if autoStart:
            self.autoStart = True
            self.engine.start(5)


    def queue(self, template, payloads=None, learn=0, callback=None, gate=None, label=None, pauseBefore=0, pauseTime=1000, pauseMarker=[], delay=0, endpoint=None):
        if payloads == None:
            payloads = []
        elif not isinstance(payloads, list):
            payloads = [str(payloads)]
        self.engine.queue(template, payloads, learn, callback, gate, label, pauseBefore, pauseTime, pauseMarker, delay, endpoint, self)


    def openGate(self, gate):
        self.engine.openGate(gate)

    def start(self, timeout=5):
        if self.autoStart or self.engine.attackState.get() != 0:
            print 'The engine has already started - you no longer need to invoke engine.start() manually. If you prefer to invoke engine.start() manually, set autoStart=False in the constructor'
            return
        self.engine.start(timeout)

    def complete(self, timeout=-1):
        self.engine.showStats(timeout)

    def cancel(self):
        self.engine.cancel()

def completed(ignored):
    pass