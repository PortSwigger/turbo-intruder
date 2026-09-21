package burp
import java.lang.RuntimeException
import java.net.URL
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import kotlin.collections.ArrayList

internal fun interface BurpRequestSender {
    fun send(service: IHttpService, request: Request)
}

internal fun interface BurpBatchRequestSender {
    fun send(service: IHttpService, requests: List<Request>, protocolVersion: HttpMode): List<HttpRequestResponse>
}

open class BurpRequestEngine private constructor(url: String, threads: Int, maxQueueSize: Int, override val maxRetriesPerRequest: Int, override var idleTimeout: Long, override val callback: (Request, Boolean) -> Boolean, override var readCallback: ((String) -> Boolean)?, val useHTTP1: Boolean, private val adaptive: Boolean, requestSender: BurpRequestSender?, batchRequestSender: BurpBatchRequestSender?, @Suppress("UNUSED_PARAMETER") internalMarker: Unit): RequestEngine(), AdaptiveTransport {

    @JvmOverloads
    constructor(url: String, threads: Int, maxQueueSize: Int, maxRetriesPerRequest: Int, idleTimeout: Long = 0, callback: (Request, Boolean) -> Boolean, readCallback: ((String) -> Boolean)?, useHTTP1: Boolean, adaptive: Boolean = false) : this(url, threads, maxQueueSize, maxRetriesPerRequest, idleTimeout, callback, readCallback, useHTTP1, adaptive, null, null, Unit)

    companion object {
        @JvmSynthetic
        internal fun withRequestSender(url: String, threads: Int, maxQueueSize: Int, maxRetriesPerRequest: Int, idleTimeout: Long = 0, callback: (Request, Boolean) -> Boolean, readCallback: ((String) -> Boolean)?, useHTTP1: Boolean, adaptive: Boolean = false, requestSender: BurpRequestSender, batchRequestSender: BurpBatchRequestSender? = null, adaptiveWorkerStarter: AdaptiveWorkerStarter? = null) =
            AdaptiveWorkerStarterConstructionContext.withStarter(adaptiveWorkerStarter) {
                BurpRequestEngine(url, threads, maxQueueSize, maxRetriesPerRequest, idleTimeout, callback, readCallback, useHTTP1, adaptive, requestSender, batchRequestSender, Unit)
            }
    }

    private val threadPool = Collections.synchronizedList(ArrayList<Thread>())
    private val workerRegistry = DynamicWorkerRegistry()
    private val adaptiveWorkerStarter = AdaptiveWorkerStarterConstructionContext.current()
    private val adaptiveWorkersReady = CountDownLatch(if (adaptive) 1 else 0)
    // ConcurrentHashMap with synchronised lists: every worker thread parks gated requests here
    // while the sending side iterates and removes, and a plain HashMap + LinkedList loses or
    // duplicates parked requests under that race.
    private val gatedRequests = ConcurrentHashMap<String, MutableList<Request>>()
    private val connectionLocks = ConcurrentHashMap<String, ReentrantLock>()
    private val hasInjectedRequestSender = requestSender != null
    private val montoyaRequestBuilder = BurpMontoyaRequestBuilder()
    private val requestSender = requestSender ?: BurpRequestSender(::sendMontoyaRequest)
    private val batchRequestSender = batchRequestSender ?: BurpBatchRequestSender(::sendMontoyaBatch)
    private lateinit var service: IHttpService

    init {
        try {
            require(!adaptive || !useHTTP1) { "Adaptive Burp workers require HTTP/2" }
            require(!adaptive || threads > 0) { "Adaptive worker count must be positive" }

            requestQueue = if (maxQueueSize > 0) {
                LinkedBlockingQueue(maxQueueSize)
            }
            else {
                LinkedBlockingQueue()
            }


            completedLatch = CountDownLatch(threads)

            target = URL(url)
            val port = if (target.port == -1) target.defaultPort else target.port
            service = buildService(target, port)

            if (adaptive) {
                workerRegistry.resizeTo(threads, ::startWorker)
                adaptiveWorkersReady.countDown()
            } else {
                repeat(threads) { startFixedWorker() }
            }
        } catch (failure: Throwable) {
            if (adaptive) {
                runState.set(3)
                workerRegistry.abort()
                adaptiveWorkersReady.countDown()
                val partialWorkers = synchronized(threadPool) {
                    threadPool.toList().also { threadPool.clear() }
                }
                partialWorkers.forEach(Thread::interrupt)
            }
            if (Utils.gotBurp && !Utils.unloaded) {
                Utils.callbacks.removeExtensionStateListener(this)
            }
            throw failure
        }
    }

    override fun start(timeout: Int) {
        runState.set(1)
        start = System.nanoTime()
    }

    override val autoProtocol = AutoProtocol.HTTP2
    override val supportsKettledRequests: Boolean
        get() = !useHTTP1

    override fun defaultAdaptiveLimits() = AdaptiveLimits(50, null)

    override fun currentAdaptiveLimits() = AdaptiveLimits(workerRegistry.desiredSize(), null)

    override fun adaptiveMetrics(): AdaptiveMetrics {
        val limits = currentAdaptiveLimits()
        val saturated = requestQueue.isNotEmpty() || activeRequests.get() >= limits.concurrency
        return baseAdaptiveMetrics(limits, saturated).copy(
            safeToMeasure = !adaptive || workerRegistry.isConverged(),
        )
    }

    override fun resizeConcurrency(newLimit: Int) {
        require(adaptive) { "Live resize is available only to adaptive Burp engines" }
        require(newLimit > 0) { "Adaptive worker count must be positive" }
        workerRegistry.resizeTo(
            target = newLimit,
            start = ::startWorker,
            onStartFailure = ::handleAdaptiveWorkerStartFailure,
        )
    }

    private fun handleAdaptiveWorkerStartFailure(failure: Throwable) {
        if (isRecoverableAdaptiveCapacityFailure(failure)) recordTransportFailure(failure)
        else throw failure
    }

    override fun resizeRequestsPerConnection(newLimit: Int) = false

    internal fun awaitAdaptiveWorkerCount(target: Int, timeout: Long, unit: TimeUnit): Int {
        require(adaptive)
        workerRegistry.awaitCount(target, timeout, unit)
        return workerRegistry.size()
    }

    override fun completionInitialized(): Boolean = if (adaptive) true else super.completionInitialized()

    override fun awaitCompletion(timeout: Long, unit: TimeUnit): Boolean =
        if (adaptive) workerRegistry.awaitEmptyAndSeal(timeout, unit) else super.awaitCompletion(timeout, unit)

    override fun sealCompletion() {
        if (adaptive) workerRegistry.seal() else super.sealCompletion()
    }


    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): Request {
        var prepared = template
        if (useHTTP1) {
            prepared = prepared.replaceFirst("HTTP/2\r\n", "HTTP/1.1\r\n")
        } else {
            if (!Utilities.isHTTP2(prepared.toByteArray())) {
                prepared = prepared.replaceFirst("HTTP/1.1\r\n", "HTTP/2\r\n")
            }
        }
        return Request(prepared, payloads, learnBoring ?: 0, label)
    }

    private fun sendMontoyaRequest(service: IHttpService, req: Request) {
        if (req.endpointOverride != null) {
            val montoyaService = HttpService.httpService(service.host, service.port, "https".equals(service.protocol))
            val protocolVersion = if (useHTTP1) HttpMode.HTTP_1 else HttpMode.HTTP_2
            val raw = if (req.kettled) {
                req.getRequest()
            } else {
                req.getRequest().replace("HTTP/2\r\n", "HTTP/1.1\r\n")
            }
            val montoyaResp = Utils.montoyaApi.http().sendRequest(
                montoyaRequestBuilder.build(montoyaService, raw, req.kettled, useHTTP1),
                protocolVersion,
            )
            req.response = montoyaResp.response()?.toString()
            req.montoyaReq = montoyaResp
            req.ttfb = montoyaResp.timingData().get().timeBetweenRequestSentAndStartOfResponse().toNanos() / 1000
            req.ttlb = montoyaResp.timingData().get().timeBetweenRequestSentAndEndOfResponse().toNanos() / 1000
            req.time = req.ttfb
            return
        }

        // Lock on connectionId to ensure sequential requests for connection reuse
        val lock = req.connectionId?.let { connectionLocks.computeIfAbsent(it) { ReentrantLock() } }
        lock?.lock()
        try {
            val montoyaService = HttpService.httpService(service.host, service.port, "https".equals(service.protocol))
            val protocolVersion = if (useHTTP1) HttpMode.HTTP_1 else HttpMode.HTTP_2

            val montoyaResp = if (req.connectionId != null) {
                Utils.montoyaApi.http().sendRequest(
                    montoyaRequestBuilder.build(montoyaService, req.getRequest(), req.kettled, useHTTP1),
                    protocolVersion,
                    req.connectionId
                )
            } else {
                Utils.montoyaApi.http().sendRequest(
                    montoyaRequestBuilder.build(montoyaService, req.getRequest(), req.kettled, useHTTP1),
                    protocolVersion
                )
            }

            req.ttfb = montoyaResp.timingData().get().timeBetweenRequestSentAndStartOfResponse().toNanos() / 1000
            req.ttlb = montoyaResp.timingData().get().timeBetweenRequestSentAndEndOfResponse().toNanos() / 1000
            req.time = req.ttfb
            if (montoyaResp.response() != null) {
                req.response = montoyaResp.response().toString()
            }
            if (req.connectionId == null) {
                req.connectionId = connections.incrementAndGet().toString()
            }
        } finally {
            lock?.unlock()
        }
    }

    private fun buildService(target: URL, port: Int): IHttpService = if (hasInjectedRequestSender) {
        object : IHttpService {
            override fun getHost() = target.host
            override fun getPort() = port
            override fun getProtocol() = target.protocol
        }
    } else {
        Utils.callbacks.helpers.buildHttpService(target.host, port, target.protocol == "https")
    }

    private fun sendMontoyaBatch(service: IHttpService, requests: List<Request>, protocolVersion: HttpMode): List<HttpRequestResponse> {
        val montoyaService = HttpService.httpService(service.host, service.port, "https".equals(service.protocol))
        val batch = requests.map { request ->
            montoyaRequestBuilder.build(montoyaService, request.getRequest(), request.kettled, useHTTP1)
        }
        return Utils.montoyaApi.http().sendRequests(batch, protocolVersion)
    }

    private fun startFixedWorker() = launchWorker(null)

    private fun startWorker(handle: DynamicWorkerRegistry.Handle) {
        adaptiveWorkerStarter?.start(handle) ?: launchWorker(handle)
    }

    private fun launchWorker(handle: DynamicWorkerRegistry.Handle?) {
        val worker = thread(start = false) {
            handle?.markStarted()
            try {
                if (handle != null) adaptiveWorkersReady.await()
                sendRequests(service, handle)
            } finally {
                threadPool.remove(Thread.currentThread())
            }
        }
        startTrackedWorker(worker, threadPool)
    }

    private fun shouldRetire(handle: DynamicWorkerRegistry.Handle?): Boolean =
        handle != null && workerRegistry.claimRetirement(handle)


    // this will return null unless there's an open gate with pending requests
    private fun getGatedRequests(): List<Request>? {
        for (gate in gatedRequests.keys) {
            if (floodgates.get(gate)?.isOpen?.get() == true) {
                // remove() is the claim: exactly one worker walks away with the batch.
                gatedRequests.remove(gate)?.let { return it }
            }
        }
        return null
    }

    private fun sendRequests(service: IHttpService, handle: DynamicWorkerRegistry.Handle?) {
        try {
            while(runState.get()<1) {
                Thread.sleep(10)
            }


            while(runState.get() < 3 && !Utils.unloaded) {

                if (shouldRetire(handle)) return

                try {
                val requestGroup = getGatedRequests()
                if (requestGroup != null) {
                    if (adaptive) activeRequests.addAndGet(requestGroup.size)
                    try {
                    val protocolVersion: HttpMode
                    var sharedConnectionId: String? = null
                    if (useHTTP1) {
                        connections.addAndGet(requestGroup.size)
                        protocolVersion = HttpMode.HTTP_1
                    } else {
                        protocolVersion = HttpMode.HTTP_2
                        sharedConnectionId = connections.incrementAndGet().toString()
                    }

                    val timer = System.nanoTime()
                    val responses = try {
                        batchRequestSender.send(service, requestGroup, protocolVersion)
                    } catch (failure: Exception) {
                        if (adaptive) repeat(requestGroup.size) { recordTransportFailure(failure) }
                        throw failure
                    }

                    var n = 0

                    val reqs: ArrayList<Request> = ArrayList()
                    for (resp in responses) {
                        val req = requestGroup.get(n++)
                        val response = resp.response()

                        // we don't need to support retries for batches requests
                        if (response == null) {
                            if (adaptive) recordTransportFailure(IllegalStateException("Montoya returned no response"))
                            req.response = "The server closed the connection without issuing a response."
                            permaFails.incrementAndGet()
                        } else {
                            successfulRequests.getAndIncrement()
                            req.response = response.toString()
                        }

                        req.ttfb = resp.timingData().get().timeBetweenRequestSentAndStartOfResponse().toNanos() / 1000
                        req.ttlb = resp.timingData().get().timeBetweenRequestSentAndEndOfResponse().toNanos() / 1000
                        req.time = req.ttfb
                        req.arrival = (timer - start) / 1000 + req.ttfb

                        if (req.connectionId == null) {
                            req.connectionId = if (useHTTP1) {
                                connections.incrementAndGet().toString()
                            } else {
                                sharedConnectionId
                            }
                        }
                        req.interesting = if (response == null) {
                            true
                        } else {
                            processResponse(req, response.toByteArray().bytes)
                        }
                        reqs.add(req)
                    }

                    reqs.sortBy { it.ttfb }

                    var i = 0
                    for (req in reqs) {
                        req.order = i++
                        invokeCallback(req, req.interesting)
                    }
                    } finally {
                        if (adaptive) activeRequests.addAndGet(-requestGroup.size)
                        requestGroup.firstOrNull()?.gate?.let { finishGateLifecycle(it.name) }
                    }
                    continue
                }

                val req = requestQueue.poll(100, TimeUnit.MILLISECONDS)

                if (req == null) {
                    if (gatedRequests.isNotEmpty()) {
                        continue;
                    }

                    if (runState.get() == 2) {
                        return
                    } else {
                        continue
                    }
                }

                if (req.gate != null) {
                    gatedRequests.computeIfAbsent(req.gate!!.name) {
                        Collections.synchronizedList(LinkedList<Request>())
                    }.add(req)
                    req.gate!!.remaining.decrementAndGet() // todo is this right?
                    continue
                }


                if (req.endpointOverride != null) {
                    val overrideTarget = URL(req.endpointOverride)
                    val tempService = buildService(overrideTarget, getEffectivePort(overrideTarget))

                    connections.incrementAndGet()
                    if (adaptive) activeRequests.incrementAndGet()
                    try {
                        try {
                            requestSender.send(tempService, req)
                        } catch (failure: Exception) {
                            if (adaptive) recordTransportFailure(failure)
                            throw failure
                        }
                        if (req.response == null) {
                            val failure = IllegalStateException("Montoya returned no response")
                            if (adaptive) recordTransportFailure(failure)
                            throw failure
                        }
                        req.interesting = processResponse(req, req.getResponseAsBytes()!!)
                        successfulRequests.getAndIncrement()
                        invokeCallback(req, req.interesting)
                    } finally {
                        if (adaptive) activeRequests.decrementAndGet()
                    }
                    continue
                }

                if (adaptive) {
                    activeRequests.incrementAndGet()
                    try {
                        sendAdaptiveRequest(service, req)
                        finishRequest(req)
                    } finally {
                        activeRequests.decrementAndGet()
                    }
                    continue
                }

                requestSender.send(service, req)
                connections.incrementAndGet()
                while (req.response == null && shouldRetry(req)) {
                    Utils.out("Retrying ${req.words}")
                    requestSender.send(service, req)
                    connections.incrementAndGet()
                    Utils.out("Retried ${req.words}")
                }

                finishRequest(req)

            } catch (ex: Exception) {
                ex.printStackTrace()
                Utils.err("Ignoring error: "+ex.toString())
                lastError = ex.toString()
                permaFails.getAndIncrement()
                // todo add null response to table
                continue
                }
            }
        } finally {
            if (handle == null) completedLatch.countDown() else handle.close()
        }
    }

    private fun sendAdaptiveRequest(service: IHttpService, req: Request) {
        var retrying = false
        while (true) {
            req.response = null
            if (retrying) Utils.out("Retrying ${req.words}")
            val failure = try {
                requestSender.send(service, req)
                if (req.response == null) {
                    IllegalStateException("Montoya returned no response")
                } else {
                    null
                }
            } catch (failure: Exception) {
                req.response = null
                failure
            }
            connections.incrementAndGet()

            if (failure == null) {
                if (retrying) Utils.out("Retried ${req.words}")
                return
            }
            recordTransportFailure(failure)
            if (!shouldRetry(req)) return
            retrying = true
        }
    }

    private fun finishRequest(req: Request) {
        if (req.response == null) {
            req.response = "The server closed the connection without issuing a response."
            invokeCallback(req, true)
        } else {
            successfulRequests.getAndIncrement()
            val interesting = processResponse(req, req.getResponseAsBytes()!!)
            invokeCallback(req, interesting)
        }
    }

}
