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

_AUTO_UNSET = object()

def _autoEligibleProtocols(endpoint):
    from java.util import HashSet
    eligible = HashSet()
    eligible.add(burp.AutoProtocol.HTTP1)
    if endpoint.lower().startswith('https://') and 'callbacks' in globals():
        eligible.add(burp.AutoProtocol.HTTP2)
        try:
            if callbacks.getBurpVersion()[0] == 'Burp Suite Professional':
                eligible.add(burp.AutoProtocol.HTTP3)
        except:
            pass
    return eligible

def _autoProbe(endpoint, verifyCertificates):
    from java.net import URL
    prober = burp.AutoProtocolProber()
    return prober.probe(URL(endpoint), verifyCertificates, _autoEligibleProtocols(endpoint))

def _autoBuildEngine(protocol, options):
    if protocol == burp.AutoProtocol.HTTP3:
        return burp.HTTP3RequestEngine(
            options['endpoint'],
            options['concurrentConnections'],
            options['maxQueueSize'],
            options['requestsPerConnection'],
            options['maxRetriesPerRequest'],
            options['idleTimeout'],
            options['callback'],
            options['readCallback'],
            options['verifyCertificates'],
            options['gateMode'],
            options['adaptive'])
    if protocol == burp.AutoProtocol.HTTP2:
        return burp.BurpRequestEngine(
            options['endpoint'],
            options['concurrentConnections'],
            options['maxQueueSize'],
            options['maxRetriesPerRequest'],
            options['idleTimeout'],
            options['callback'],
            options['readCallback'],
            False,
            options['adaptive'])
    if protocol == burp.AutoProtocol.HTTP1:
        return burp.ThreadedRequestEngine(
            options['endpoint'],
            options['concurrentConnections'],
            options['maxQueueSize'],
            1,
            options['requestsPerConnection'],
            options['maxRetriesPerRequest'],
            options['idleTimeout'],
            options['callback'],
            options['timeout'],
            options['readCallback'],
            options['readSize'],
            options['resumeSSL'],
            options['explodeOnEarlyRead'],
            options['adaptive'])
    raise Exception('Unrecognised AUTO protocol: %s' % protocol)

def _autoBuildController(candidate, policy):
    return burp.AdaptiveController(candidate, policy)

class Engine:
    BURP = 1
    THREADED = 2
    HTTP2 = 3
    BURP2 = 4
    SPIKE = 5
    HTTP3 = 6
    AUTO = 7

class RequestEngine:

    def __init__(self, endpoint, callback=None, engine=None, concurrentConnections=None, requestsPerConnection=None, pipeline=_AUTO_UNSET, maxQueueSize=100, timeout=10, maxRetriesPerRequest=3, idleTimeout=0, readCallback=None, readSize=1024, resumeSSL=True, autoStart=True, explodeOnEarlyRead=False, warmLocalConnection=True, fatPacket=False, verifyCertificates=False, gateMode='auto'):
        from burp import Utils as TurboUtils

        # Default engine based on desync-agent-mode setting
        if engine is None:
            if desyncAgentMode:
                engine = Engine.BURP
            elif TurboUtils.isBurpProfessional():
                engine = Engine.AUTO
            else:
                engine = Engine.THREADED

        self._autoController = None
        self._autoProtocol = None
        self._autoDispatched = False

        if engine == Engine.AUTO:
            TurboUtils.requireAutoEngineAvailable()
            if concurrentConnections is not None or requestsPerConnection is not None or pipeline is not _AUTO_UNSET:
                raise Exception('Engine.AUTO owns concurrentConnections, requestsPerConnection, and pipeline')
            if maxRetriesPerRequest <= 0:
                raise Exception('Engine.AUTO requires a positive maxRetriesPerRequest')
            if not callback:
                callback = handleResponse
            self._configureAuto(
                endpoint,
                callback,
                maxQueueSize,
                timeout,
                maxRetriesPerRequest,
                idleTimeout,
                readCallback,
                readSize,
                resumeSSL,
                explodeOnEarlyRead,
                verifyCertificates,
                gateMode)
            return

        if pipeline is _AUTO_UNSET:
            pipeline = False

        if concurrentConnections is None:
            if engine == Engine.HTTP3:
                # 50 is an HTTP/1.1 number: a socket carries one request at a time, so the pool
                # size is the parallelism. One QUIC connection carries 256 streams at once, so ten
                # of them already hold more requests in flight than the engine will run, at a
                # fifth of the handshakes. The rest of a larger pool is opened up front and then
                # left idle until the target's QUIC idle timeout kills it, and a gate that claims
                # one of those loses its whole batch.
                concurrentConnections = 10
            else:
                concurrentConnections = 50

        if requestsPerConnection is None:
            if engine == Engine.HTTP3:
                # 100 is an HTTP/1.1 number: on a socket it buys 100 round trips of reuse, but a
                # QUIC connection carries 256 requests at a time, so 100 retires it before its
                # streams have been filled once and charges a handshake for the replacement.
                requestsPerConnection = 1000000
            else:
                requestsPerConnection = 100

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
        elif(engine == Engine.HTTP3):
            self.engine = burp.HTTP3RequestEngine(endpoint, concurrentConnections, maxQueueSize, requestsPerConnection, maxRetriesPerRequest, idleTimeout, callback, readCallback, verifyCertificates, gateMode)
        elif(engine == Engine.SPIKE):
            self.engine = burp.SpikeEngine(endpoint, concurrentConnections, maxQueueSize, requestsPerConnection, maxRetriesPerRequest, idleTimeout, callback, readCallback, warmLocalConnection, fatPacket)
        else:
            print('Unrecognised engine. Valid engines are Engine.BURP, Engine.THREADED')

        handler.setRequestEngine(self.engine)
        self.engine.setOutput(outputHandler)
        self.engine.setRequestTable(requestTable)
        self.userState = self.engine.userState
        self.autoStart = False
        if autoStart:
            self.autoStart = True
            self.engine.start(5)

    def _configureAuto(self, endpoint, callback, maxQueueSize, timeout, maxRetriesPerRequest, idleTimeout, readCallback, readSize, resumeSSL, explodeOnEarlyRead, verifyCertificates, gateMode):
        results = _autoProbe(endpoint, verifyCertificates)
        probeResults = {}
        failures = []
        for result in results:
            probeResults[result.protocol] = result
            if result.succeeded:
                print('AUTO probe %s: available' % result.protocol)
            else:
                reason = result.failure or 'unavailable'
                failures.append('%s probe failed: %s' % (result.protocol, reason))
                print('AUTO probe %s: %s' % (result.protocol, reason))

        commonOptions = {
            'endpoint': endpoint,
            'callback': callback,
            'maxQueueSize': maxQueueSize,
            'timeout': timeout,
            'maxRetriesPerRequest': maxRetriesPerRequest,
            'idleTimeout': idleTimeout,
            'readCallback': readCallback,
            'readSize': readSize,
            'resumeSSL': resumeSSL,
            'explodeOnEarlyRead': explodeOnEarlyRead,
            'verifyCertificates': verifyCertificates,
            'gateMode': gateMode,
            'pipeline': False,
            'adaptive': True,
        }

        selectedEngine = None
        selectedProtocol = None
        selectedController = None
        preferences = (
            (burp.AutoProtocol.HTTP3, 10, 1000000),
            (burp.AutoProtocol.HTTP2, 50, None),
            (burp.AutoProtocol.HTTP1, 50, 100),
        )
        for protocol, concurrency, requestLimit in preferences:
            result = probeResults.get(protocol)
            if result is None or not result.succeeded:
                continue
            if self._autoDispatched:
                raise Exception('Engine.AUTO protocol is immutable after the first queued request')

            options = dict(commonOptions)
            options['concurrentConnections'] = concurrency
            options['requestsPerConnection'] = requestLimit
            candidate = None
            controller = None
            controllerInstalled = False
            try:
                candidate = _autoBuildEngine(protocol, options)
                candidate.setOutput(outputHandler)
                candidate.setRequestTable(requestTable)
                candidate.start(5)
                policy = burp.AdaptivePolicy(protocol, candidate.defaultAdaptiveLimits())
                controller = _autoBuildController(candidate, policy)
                candidate.installAdaptiveController(controller)
                controllerInstalled = True
                controller.start()
                selectedEngine = candidate
                selectedProtocol = protocol
                selectedController = controller
                break
            except:
                import sys
                setupFailure = sys.exc_info()[1]
                failures.append('%s setup failed: %s' % (protocol, setupFailure))
                if candidate is not None:
                    try:
                        candidate.cancel()
                    except:
                        pass
                if controller is not None and not controllerInstalled:
                    controller.stop()

        if selectedEngine is None:
            detail = '; '.join(failures) if failures else 'no eligible protocol was available'
            raise Exception('Engine.AUTO could not start: %s' % detail)

        self.engine = selectedEngine
        self._autoProtocol = selectedProtocol
        self._autoController = selectedController
        handler.setRequestEngine(self.engine)
        self.userState = self.engine.userState
        self.autoStart = True
        print('AUTO selected %s' % selectedProtocol)

    @property
    def autoProtocol(self):
        return self._autoProtocol


    def queue(self, template, payloads=None, learn=0, callback=None, gate=None, label="", pauseBefore=0, pauseTime=1000, pauseMarker=[], delay=0, endpoint=None, fixContentLength=True, connectionId=None, kettled=False):
        if payloads == None:
            payloads = []
        elif not isinstance(payloads, list):
            payloads = [str(payloads)]
        self.engine.queue(template, payloads, learn, callback, gate, label, pauseBefore, pauseTime, pauseMarker, delay, endpoint, self, fixContentLength, connectionId, kettled)
        self._autoDispatched = True


    def openGate(self, gate):
        self.engine.openGate(gate)

    def applySetting(self, settingName, settingValue):
        self.engine.applySetting(settingName, settingValue)

    def start(self, timeout=5):
        if self.autoStart or self.engine.runState.get() != 0:
            print 'The engine has already started - you no longer need to invoke engine.start() manually. If you prefer to invoke engine.start() manually, set autoStart=False in the constructor'
            return
        self.engine.start(timeout)

    def complete(self, timeout=-1):
        try:
            self.engine.showStats(timeout)
        finally:
            self.engine.stopAdaptiveController()

    def cancel(self):
        try:
            self.engine.cancel()
        finally:
            self.engine.stopAdaptiveController()

def completed(ignored):
    pass
