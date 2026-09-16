package burp

//import jdk.net.ExtendedSocketOptions
import burp.api.montoya.utilities.CompressionType
import java.io.*
import java.net.*
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.GZIPInputStream
import javax.net.SocketFactory
import javax.net.ssl.*
import kotlin.IllegalStateException
import kotlin.concurrent.thread

open class ThreadedRequestEngine @JvmOverloads constructor(url: String, val threads: Int, maxQueueSize: Int, val readFreq: Int, requestsPerConnection: Int, override val maxRetriesPerRequest: Int, override var idleTimeout: Long = 0, override val callback: (Request, Boolean) -> Boolean, var timeout: Int, override var readCallback: ((String) -> Boolean)?, val readSize: Int, val resumeSSL: Boolean, var explodeOnEarlyRead: Boolean = false, private val adaptive: Boolean = false): RequestEngine(), AdaptiveTransport {

    private val connectedLatch = CountDownLatch(threads)
    private val threadPool = Collections.synchronizedList(ArrayList<Thread>())
    private val workerRegistry = DynamicWorkerRegistry()
    private val adaptiveWorkerStarter = AdaptiveWorkerStarterConstructionContext.current()
    private val adaptiveWorkersReady = CountDownLatch(if (adaptive) 1 else 0)
    private val requestLimit = AtomicInteger(requestsPerConnection)
    private val retryQueue = LinkedBlockingQueue<Request>()
    private lateinit var ipAddress: InetAddress
    private var port: Int = 0
    private lateinit var trustingSslSocketFactory: SSLSocketFactory

    val requestsPerConnection: Int
        get() = requestLimit.get()

    var domains = HashSet<String>()

    init {
        try {
            require(!adaptive || requestsPerConnection in 1..1_000_000) {
                "Adaptive request lifetime must be between 1 and 1,000,000"
            }
            val desyncMode = Utilities.globalSettings?.getBoolean("desync-agent-mode")
            Utils.out("desync-agent-mode = $desyncMode, requestsPerConnection = $requestsPerConnection")
            if (desyncMode == true && requestsPerConnection > 1) {
                throw IllegalArgumentException("desync-agent-mode is enabled: requestsPerConnection must be 1 to prevent false-positives (currently set to $requestsPerConnection)")
            }

            internalSettings.put("ignoreLength", false)

            idleTimeout *= 1000
            lastLife = System.currentTimeMillis()

            require(!adaptive || threads > 0) { "Adaptive worker count must be positive" }
            target = URL(url)

            requestQueue = if (maxQueueSize > 0) {
                LinkedBlockingQueue(maxQueueSize)
            }
            else {
                LinkedBlockingQueue()
            }

            completedLatch = CountDownLatch(threads)
            ipAddress = InetAddress.getByName(target.host)
            port = if (target.port == -1) { target.defaultPort } else { target.port }

            trustingSslSocketFactory = createSSLSocketFactory()

            Utils.err("Establishing $threads connection to $url ...");
            if (adaptive) {
                workerRegistry.resizeTo(threads, ::startAdaptiveWorker)
                // Gate admission counts only workers that have actually entered their run loop.
                workerRegistry.awaitLiveSize(threads)
                adaptiveWorkersReady.countDown()
            } else {
                repeat(threads) { startFixedWorker() }
            }
        } catch(failure: Throwable) {
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

    companion object {

        @JvmSynthetic
        internal fun withAdaptiveWorkerStarter(
            url: String,
            threads: Int,
            maxQueueSize: Int,
            readFreq: Int,
            requestsPerConnection: Int,
            maxRetriesPerRequest: Int,
            idleTimeout: Long,
            callback: (Request, Boolean) -> Boolean,
            timeout: Int,
            readCallback: ((String) -> Boolean)?,
            readSize: Int,
            resumeSSL: Boolean,
            explodeOnEarlyRead: Boolean,
            starter: AdaptiveWorkerStarter,
        ) = AdaptiveWorkerStarterConstructionContext.withStarter(starter) {
            ThreadedRequestEngine(
                url, threads, maxQueueSize, readFreq, requestsPerConnection, maxRetriesPerRequest,
                idleTimeout, callback, timeout, readCallback, readSize, resumeSSL, explodeOnEarlyRead,
                adaptive = true,
            )
        }

        internal fun connectionBackoffMillis(consecutiveFailures: Int, adaptive: Boolean): Long {
            val exponent = if (adaptive) consecutiveFailures.coerceIn(1, 7) else consecutiveFailures
            return Math.pow(2.0, exponent.toDouble()).toLong() * 200L
        }

        fun uncompressIfNecessary(headers: String, body: String): String {
            if (headers.lowercase().indexOf("content-encoding: ") == -1) {
                return body
            }
            val compressionType: CompressionType
            if (headers.lowercase().indexOf("content-encoding: gzip") != -1) {
                compressionType = CompressionType.GZIP
            } else if (headers.lowercase().indexOf("content-encoding: deflate") != -1) {
                compressionType = CompressionType.DEFLATE
            } else if (headers.lowercase().indexOf("content-encoding: br") != -1) {
                compressionType = CompressionType.BROTLI
            } else {
                return body
            }

            if (Utilities.montoyaApi == null) {
                if (compressionType == CompressionType.GZIP) {
                    return ungzip(body.toByteArray(Charsets.ISO_8859_1))
                }
                Utils.out("Can't decompress response")
                return body;
            }


            val decompressed = Utils.montoyaApi.utilities().compressionUtils().decompress(burp.api.montoya.core.ByteArray.byteArray(body), compressionType)
            return Utils.montoyaApi.utilities().byteUtils().convertToString(decompressed.bytes)
        }

        fun ungzip(compressed: ByteArray): String {
            if (compressed.isEmpty()) {
                return ""
            }

            val out = ByteArrayOutputStream()
            try {
                val bytesIn = ByteArrayInputStream(compressed)
                val unzipped = GZIPInputStream(bytesIn)
                while (true) {
                    val bytes = ByteArray(1024)
                    val read = unzipped.read(bytes, 0, 1024)
                    if (read <= 0) {
                        break
                    }
                    out.write(bytes, 0, read)
                }
            } catch (e: IOException) {
                Utils.err("GZIP decompression failed - possible partial response. Using undecompressed bytes instead.")
                return String(compressed)
            }

            return String(out.toByteArray())
        }


    }
    fun createSSLSocketFactory(): SSLSocketFactory {
        val trustingSslContext = SSLContext.getInstance("TLS")
        trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager(this)), null)
        return trustingSslContext.socketFactory
    }

    // val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("localhost", 6574))

    override fun start(timeout: Int) {
        connectedLatch.await(timeout.toLong(), TimeUnit.SECONDS)
        runState.set(1)
        start = System.nanoTime()
    }

    override val autoProtocol = AutoProtocol.HTTP1

    override fun defaultAdaptiveLimits() = AdaptiveLimits(50, 100)

    override fun currentAdaptiveLimits() = AdaptiveLimits(
        if (adaptive) workerRegistry.desiredSize() else threads,
        requestLimit.get(),
    )

    override fun adaptiveMetrics(): AdaptiveMetrics {
        val limits = currentAdaptiveLimits()
        val saturated = requestQueue.isNotEmpty() || retryQueue.isNotEmpty() || activeRequests.get() >= limits.concurrency
        return baseAdaptiveMetrics(limits, saturated).copy(
            safeToMeasure = !adaptive || workerRegistry.isConverged(),
        )
    }

    override fun resizeConcurrency(newLimit: Int) {
        require(adaptive) { "Live resize is available only to adaptive threaded engines" }
        require(newLimit > 0) { "Adaptive worker count must be positive" }
        workerRegistry.resizeTo(
            target = newLimit,
            start = ::startAdaptiveWorker,
            onStartFailure = ::handleAdaptiveWorkerStartFailure,
        )
    }

    private fun handleAdaptiveWorkerStartFailure(failure: Throwable) {
        if (isRecoverableAdaptiveCapacityFailure(failure)) recordTransportFailure(failure)
        else throw failure
    }

    override fun resizeRequestsPerConnection(newLimit: Int): Boolean {
        require(adaptive) { "Live request lifetime is available only to adaptive threaded engines" }
        requestLimit.set(newLimit.coerceIn(1, 1_000_000))
        return true
    }

    internal fun currentWorkerCapacity(): Int = if (adaptive) workerRegistry.liveSize() else threads

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

    private fun startFixedWorker() = launchWorker(null, readFreq)

    private fun startAdaptiveWorker(handle: DynamicWorkerRegistry.Handle) {
        adaptiveWorkerStarter?.start(handle) ?: launchWorker(handle, 1)
    }

    private fun launchWorker(handle: DynamicWorkerRegistry.Handle?, workerReadFreq: Int) {
        val worker = thread(start = false) {
            handle?.markStarted()
            try {
                if (handle != null) adaptiveWorkersReady.await()
                sendRequests(handle, workerReadFreq)
            } finally {
                threadPool.remove(Thread.currentThread())
            }
        }
        startTrackedWorker(worker, threadPool)
    }

    private fun shouldRetire(handle: DynamicWorkerRegistry.Handle?): Boolean =
        handle != null && workerRegistry.claimRetirement(handle)

    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): Request {
        var prepared = template

        if (Utilities.isHTTP2(prepared.toByteArray())) {
            prepared = prepared.replaceFirst("HTTP/2\r\n", "HTTP/1.1\r\n")
        }

        if(Utils.getHeaders(prepared).contains("Connection: close")) {
            prepared = prepared.replaceFirst("Connection: close", "Connection: keep-alive")
        }

        return Request(prepared, payloads, learnBoring?: 0, label)
    }

    private fun sendRequests(handle: DynamicWorkerRegistry.Handle?, baseReadFreq: Int) {
        val readFreq = baseReadFreq
        val inflight = ArrayDeque<Request>()
        var connected = false
        var reqWithResponse: Request? = null
        var answeredRequests = 0
        val badWords = HashSet<String>()
        var consecutiveFailedConnections = 0
        var startTime: Long = 0
        var reuseSSL = resumeSSL
        var requestReservedForSetup: Request? = null

        try {
            while (!shouldAbandonRun()) {
                if (shouldRetire(handle)) return
                if (adaptive && runState.get() >= 1 && requestReservedForSetup == null) {
                    while (!shouldAbandonRun() && !shouldRetire(handle)) {
                        requestReservedForSetup = retryQueue.poll() ?: requestQueue.poll(100, TimeUnit.MILLISECONDS)
                        if (requestReservedForSetup != null || runState.get() >= 2) break
                    }
                    if (requestReservedForSetup == null) {
                        if (runState.get() >= 2 || shouldAbandonRun() || shouldRetire(handle)) return
                        continue
                    }
                    activeRequests.incrementAndGet()
                }
                try {

                val socket: Socket?
                try {
                    socket = if (target.protocol == "https") {
                        if (reuseSSL) {
                            trustingSslSocketFactory.createSocket(ipAddress, port)
                        } else {
                            createSSLSocketFactory().createSocket(ipAddress, port)
                        }
                    } else {
                        SocketFactory.getDefault().createSocket(ipAddress, port)
                    }
                }
                catch (ex: Exception) {
                    recordTransportFailure(ex)
                    Utils.out("Thread failed to connect")
                    val stackTrace = StringWriter()
                    ex.printStackTrace(PrintWriter(stackTrace))
                    Utils.err(stackTrace.toString())
                    consecutiveFailedConnections += 1
                    if (adaptive) {
                        requestReservedForSetup?.let { request ->
                            if (!shouldRetry(request)) {
                                finishFailedSetupRequest(request, ex)
                                activeRequests.decrementAndGet()
                                requestReservedForSetup = null
                            }
                        }
                        if (!waitForAdaptiveConnectionBackoff(consecutiveFailedConnections, handle)) return
                    } else {
                        retries.getAndIncrement()
                        Thread.sleep(connectionBackoffMillis(consecutiveFailedConnections, adaptive = false))
                    }
                    continue
                }
                val connectionIdAuto = connections.incrementAndGet().toString()
                try {
                //(socket as SSLSocket).session.peerCertificates
                socket!!.soTimeout = timeout * 1000
                socket.tcpNoDelay = true
                socket.receiveBufferSize = readSize
                socket.keepAlive = true
                // socket.setOption(ExtendedSocketOptions.TCP_KEEPIDLE, 30)
                // todo tweak other TCP options for max performance

                if(!connected) {
                    connected = true
                    connectedLatch.countDown()
                    while(!Utils.unloaded && runState.get() == 0 && !shouldAbandonRun()) {
                        Thread.sleep(10)
                    }
                }

                consecutiveFailedConnections = 0

                var requestsSent = 0
                answeredRequests = 0
                while (requestsSent < requestLimit.get() && !shouldAbandonRun()) {
                    if (shouldRetire(handle)) return
                    val ignoreLength = internalSettings.get("ignoreLength") as Boolean
                    var ditchConnection = false;
                    var readCount = 0
                    startTime = 0
                    var endTime: Long = 0
                    var bodyEndTime: Long = 0
                    var buffer = ""

                    for (j in 1..readFreq) {
                        if (requestsSent >= requestLimit.get() || shouldRetire(handle)) {
                            break
                        }

                        val wasReservedForSetup = requestReservedForSetup != null
                        var req = requestReservedForSetup.also { requestReservedForSetup = null }
                            ?: retryQueue.poll()
                        while (req == null && !shouldAbandonRun() && !shouldRetire(handle) && requestsSent < requestLimit.get()) {
                            req = requestQueue.poll(100, TimeUnit.MILLISECONDS)

                            if (req == null) {
                                if (readCount > 0) {
                                    break
                                }
                                if(runState.get() >= 2) {
                                    return
                                }
                            }
                        }

                        if (req == null) break
                        if (requestsSent >= requestLimit.get() || shouldRetire(handle)) {
                            // The bounded request queue may refill after poll returns. The retry
                            // queue is unbounded and checked first by every worker, so this stays
                            // non-blocking without dropping the request during shrink or shutdown.
                            retryQueue.add(req)
                            if (wasReservedForSetup) activeRequests.decrementAndGet()
                            break
                        }

                        inflight.addLast(req)
                        if (!wasReservedForSetup) activeRequests.incrementAndGet()
                        val byteReq = req.getRequestAsBytes()
                        val outputstream = socket.getOutputStream()
                        if (req.gate != null) {
                            val withHold = 1
                            outputstream.write(byteReq, 0, byteReq.size-withHold)
                            req.gate!!.waitForGo()
                            startTime = System.nanoTime()
                            outputstream.write(byteReq, byteReq.size-withHold, withHold)
                        }
                        else if (req.pauseBefore != 0) {
                            val end: Int
                            if (req.pauseBefore < 0) {
                                end = byteReq.size + req.pauseBefore
                            } else {
                                end = req.pauseBefore - 1 // since it's 0-indexed
                            }
                            val part1 = byteReq.sliceArray(0 until end)
                            //Utils.out("'"+Utilities.helpers.bytesToString(part1)+"'")
                            outputstream.write(part1)
                            startTime = System.nanoTime()

                            buffer = waitForData(socket, req.pauseTime)

                            val part2 = byteReq.sliceArray(end until byteReq.size)
                            outputstream.write(part2)
                            //Utils.out("'"+Utilities.helpers.bytesToString(part2)+"'")
                        } else if (!req.pauseMarkers.isEmpty()) {
                            var i = 0
                            startTime = System.nanoTime()
                            // pauses *after* sending the pauseMarker
                            while (i < byteReq.size && !shouldAbandonRun()) {
                                var pausePoint = -1
                                //val z: ByteArray = req.pauseMarkers.get(0)
                                for (pauseMarker in req.pauseMarkers) {
                                    val pauseBytes = pauseMarker.toByteArray(Charsets.ISO_8859_1)
                                    pausePoint = Utils.helpers.indexOf(byteReq, pauseBytes, true, i, byteReq.size)
                                    if (pausePoint != -1) {
                                        outputstream.write(byteReq.sliceArray(i until (pausePoint+pauseBytes.size)))
                                        buffer = waitForData(socket, req.pauseTime)
                                        i = pausePoint + pauseBytes.size
                                        break
                                    }
                                }

                                if (pausePoint == -1) {
                                    outputstream.write(byteReq.sliceArray(i until byteReq.size))
                                    break
                                }

                            }
                        }
                        else {
                            outputstream.write(byteReq)
                            startTime = System.nanoTime()
                        }

                        readCount++
                        requestsSent++

                    }

                    val readBuffer = ByteArray(readSize)

                    for (k in 1..readCount) {

                        var bodyStart = buffer.indexOf("\r\n\r\n")
                        if (bodyStart != -1) {
                            endTime = System.nanoTime()
                        }

                        var consumeFirstBlock = buffer.startsWith("HTTP/1.1 100")
                        var ateContinue = false
                        var continueBlock = ""


                        while (bodyStart == -1 && !shouldAbandonRun()) {
                            val len = socket.getInputStream().read(readBuffer)
                            if(len == -1) {
                                break
                            }
                            endTime = System.nanoTime()

                            val read = Utils.bytesToString(readBuffer.copyOfRange(0, len))
                            triggerReadCallback(read)
                            buffer += read
                            bodyStart = buffer.indexOf("\r\n\r\n")
                        }

                        while ((bodyStart == -1 || (consumeFirstBlock && !ateContinue)) && !shouldAbandonRun()) {
                            try {
                                val len = socket.getInputStream().read(readBuffer)
                                if(len == -1) {
                                    break
                                }
                                endTime = System.nanoTime()

                                val read = Utils.bytesToString(readBuffer.copyOfRange(0, len))
                                triggerReadCallback(read)
                                buffer += read
                                consumeFirstBlock = buffer.startsWith("HTTP/1.1 100")
                                bodyStart = buffer.indexOf("\r\n\r\n")
                                if (consumeFirstBlock && bodyStart != -1 && !ateContinue && !ignoreLength) {
                                    consumeFirstBlock = false
                                    ateContinue = true
                                    continueBlock = buffer.substring(0, bodyStart+4)
                                    buffer = buffer.substring(bodyStart+4)
                                    bodyStart = buffer.indexOf("\r\n\r\n")
                                }
                            } catch (ex: SocketTimeoutException) {
                                break
                            }
                        }

                        if (buffer.isEmpty() && ateContinue) {
                            buffer = continueBlock
                            continueBlock = ""
                            bodyStart = buffer.length
                            // todo handle missing body
                        }

                        val contentLength = getContentLength(buffer)

                        if (buffer.isEmpty()) {
                            throw ConnectException("No response")
                        } else if (bodyStart == -1) {
                            throw ConnectException("Unterminated response: '"+buffer+"'")
                        }

                        if (contentLength > 10000000) {
                            throw ConnectException("Response too large - 10mb max")
                        }

                        if (bodyStart+4 > buffer.length) {
                            bodyStart = buffer.length - 4
                        }

                        val headers = buffer.substring(0, bodyStart+4)
                        var body = ""

                        if (contentLength != -1 && !ignoreLength) {
                            val responseLength = bodyStart + contentLength + 4

                            while (buffer.length < responseLength && !shouldAbandonRun()) {
                                val len = socket.getInputStream().read(readBuffer)
                                if (len == -1) {
                                    ditchConnection = true
                                    body = buffer.substring(bodyStart + 4)
                                    buffer = ""
                                    break
                                    //throw RuntimeException("CL response finished unexpectedly")
                                }
                                val read =  Utils.bytesToString(readBuffer.copyOfRange(0, len))
                                triggerReadCallback(read)
                                buffer += read
                            }

                            if (!ditchConnection && !shouldAbandonRun()) {
                                body = buffer.substring(bodyStart + 4, responseLength)
                                buffer = buffer.substring(responseLength)
                            }
                        }
                        else if (headers.lowercase().contains("transfer-encoding: chunked") || headers.contains("^transfer-encoding:[ ]*chunked".toRegex(setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)))  && !ignoreLength) {

                            buffer = buffer.substring(bodyStart + 4)

                            while (!shouldAbandonRun()) {
                                var chunk = getNextChunkLength(buffer)
                                while (chunk.length == -1 || buffer.length < (chunk.length+2)) {
                                    val len = socket.getInputStream().read(readBuffer)
                                    if (len == -1) {
                                        throw RuntimeException("Chunked response finished unexpectedly")
                                    }
                                    val read = Utils.bytesToString(readBuffer.copyOfRange(0, len))
                                    triggerReadCallback(read)
                                    buffer += read
                                    chunk = getNextChunkLength(buffer)
                                }

                                body += buffer.substring(chunk.skip, chunk.length)
                                buffer = buffer.substring(chunk.length + 2)

                                if (chunk.length == chunk.skip) {
                                    break
                                }
                            }
                        }
                        else {

                            if (ignoreLength) {
                                socket.soTimeout = 5000
                            } else if (ateContinue) {
                                socket.soTimeout = 100
                            } else {
                                Utils.err("Response has no content-length - doing a one-second socket read instead. This is slow!")
                                socket.soTimeout = 1000
                                ditchConnection = true
                            }

                            try {
                                body += buffer.substring(bodyStart + 4)
                                while (!shouldAbandonRun()) {
                                    val len = socket.getInputStream().read(readBuffer)

                                    if (len == -1) {
                                        break
                                    }

                                    buffer = Utils.bytesToString(readBuffer.copyOfRange(0, len))
                                    body += buffer
                                }
                            } catch (ex: SocketTimeoutException) {

                            } catch (ex: SSLProtocolException) {

                            } catch (ex: java.lang.Exception) {
                                Utils.err("Exception during timed read: "+ex)
                            }
                        }

                        bodyEndTime = System.nanoTime()

                        if (shouldAbandonRun()) {
                            break
                        }

                        if (!headers.startsWith("HTTP")) {
                            throw Exception("no http")
                        }

                        var msg = headers
                        if (continueBlock.isNotEmpty()) {
                            msg = continueBlock + msg
                        }

                        msg += uncompressIfNecessary(headers, body)

                        reqWithResponse = inflight.removeFirst()
                        try {
                            successfulRequests.getAndIncrement()
                            reqWithResponse.response = msg
                            if (reqWithResponse.connectionId == null) {
                                reqWithResponse.connectionId = connectionIdAuto
                            }
                            reqWithResponse.ttfb = (endTime - startTime) / 1000 // convert ns to microseconds
                            reqWithResponse.ttlb = (bodyEndTime - startTime) / 1000
                            reqWithResponse.time = reqWithResponse.ttfb
                            reqWithResponse.arrival = (endTime - start) / 1000

                            answeredRequests += 1
                            val interesting = try {
                                processResponse(
                                    reqWithResponse,
                                    (reqWithResponse.response as String).toByteArray(Charsets.ISO_8859_1),
                                )
                            } catch (exception: Throwable) {
                                recordResponseProcessingFailure(exception)
                                null
                            }
                            if (interesting != null) invokeCallback(reqWithResponse, interesting)
                        } finally {
                            activeRequests.decrementAndGet()
                            finishGatedRequest(reqWithResponse)
                        }

                    }
                    badWords.clear()

                    if (ditchConnection) {
                        break
                    }
                }
                } finally {
                    runCatching { socket.close() }
                    retiredConnections.incrementAndGet()
                }
            } catch (ex: Exception) {

                val failedAttemptCount = inflight.size
                if (ex !is InterruptedException) {
                    repeat(maxOf(1, failedAttemptCount)) { recordTransportFailure(ex) }
                }

                if (reuseSSL && (ex is SSLHandshakeException || ex is SSLException)) {
                    reuseSSL = false
                }
                else {
                    // todo distinguish couldn't send vs couldn't read
                    val activeRequest = inflight.peek()
                    if (activeRequest != null) {
                        val activeWord = activeRequest.words.joinToString(separator="/")
                        if (shouldRetry(activeRequest)) {
                            if (reqWithResponse != null) {
                                Utils.out("Autorecovering error after $answeredRequests answered requests. After '${reqWithResponse.words.joinToString(separator = "/")}' during '$activeWord'")
                            } else {
                                Utils.out("Autorecovering first-request error during '$activeWord'")
                            }
                        } else {
                            ex.printStackTrace()
                            Utils.err("Ignoring error: "+ex.toString())
                            val badReq = inflight.pop()
                            if (ex is IllegalStateException) {
                                badReq.response = "early-response"
                            } else {
                                badReq.response = "null"
                            }
                            if (startTime != 0L) {
                                val elapsed = (System.nanoTime() - startTime) / 1000
                                badReq.ttfb = elapsed
                                badReq.ttlb = elapsed
                                badReq.time = elapsed
                            }
                            invokeCallback(badReq, true)
                            finishGatedRequest(badReq)
                        }
                    } else {
                        if (ex !is InterruptedException) {
                            Utils.out("Autorecovering error with empty queue: ${ex.message}")
                            ex.printStackTrace()
                        }
                    }
                }

                // do callback here (allow user code change
                //readFreq = max(1, readFreq / 2)
                //requestsPerConnection = max(1, requestsPerConnection/2)
                //println("Lost ${inflight.size} requests. Changing requestsPerConnection to $requestsPerConnection and readFreq to $readFreq")
                activeRequests.addAndGet(-failedAttemptCount)
                retryQueue.addAll(inflight)
                inflight.clear()
                }
            }
        } finally {
            requestReservedForSetup?.let { request ->
                if (runState.get() < 3) retryQueue.add(request)
                activeRequests.decrementAndGet()
            }
            activeRequests.addAndGet(-inflight.size)
            inflight.clear()
            if (handle == null) completedLatch.countDown() else handle.close()
        }
    }

    private fun finishFailedSetupRequest(request: Request, failure: Throwable) {
        request.gate?.let { gate ->
            gate.reportReadyWithoutWaiting()
            while (!gate.isOpen.get() && runState.get() < 3 && !Thread.currentThread().isInterrupted) {
                Thread.sleep(10)
            }
        }
        if (runState.get() >= 3) return
        request.response = "null"
        Utils.err("Ignoring error: $failure")
        invokeCallback(request, true)
        finishGatedRequest(request)
    }

    private fun waitForAdaptiveConnectionBackoff(
        consecutiveFailures: Int,
        handle: DynamicWorkerRegistry.Handle?,
    ): Boolean {
        var remainingMillis = connectionBackoffMillis(consecutiveFailures, adaptive = true)
        while (remainingMillis > 0) {
            if (shouldAbandonRun() || shouldRetire(handle)) return false
            val pause = minOf(remainingMillis, 50L)
            try {
                Thread.sleep(pause)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
            remainingMillis -= pause
        }
        return !shouldAbandonRun() && !shouldRetire(handle)
    }

    private fun waitForData(socket: Socket, pauseTime: Int): String {

        val oldTimeout = socket.soTimeout
        socket.soTimeout = pauseTime
        var len = -1
        val readBuffer = ByteArray(readSize)
        try {
            len = socket.getInputStream().read(readBuffer)
        } catch (e: Exception) {

        }
        socket.soTimeout = oldTimeout
        if (explodeOnEarlyRead && len != -1) {
            throw IllegalStateException()
        }
        var read = ""
        if (len != -1) {
            read = Utils.bytesToString(readBuffer.copyOfRange(0, len))
        }

        return read
    }

    fun getContentLength(buf: String): Int {
        val cstart = buf.indexOf("Content-Length: ")+16
        if (cstart == 15) {
            return -1
        }

        val cend = buf.indexOf("\r", cstart)
        try {
            return buf.substring(cstart, cend).trim().toInt()
        } catch (e: NumberFormatException) {
            throw RuntimeException("Can't parse content length in $buf")
        }
    }

    data class Result(val skip: Int, val length: Int)

    fun getNextChunkLength(buf: String): Result {
        if (buf.isEmpty()) {
            return Result(-1, -1)
        }

        val chunkLengthStart = 0
        val chunkLengthEnd = buf.indexOf("\r\n")
        if(chunkLengthEnd == -1) {
            return Result(-1, -1)
            //throw RuntimeException("Couldn't find the chunk length. Response size may be unspecified - try Burp request engine instead?")
        }

        try {
            val skip = 2+chunkLengthEnd-chunkLengthStart
            return Result(skip, Integer.parseInt(buf.substring(chunkLengthStart, chunkLengthEnd).trim(), 16)+skip)
        } catch (e: NumberFormatException) {
            throw RuntimeException("Can't parse followup chunk length '${buf.substring(chunkLengthStart, chunkLengthEnd)}' in $buf")
        }
    }

    private class TrustingTrustManager(val engine: ThreadedRequestEngine) : X509TrustManager {

        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val altNames = chain.get(0).subjectAlternativeNames ?: return
            for (x in altNames) {
                engine.domains.add(x.get(1).toString())
            }
        }
    }

    override fun cleanup() {
        // Clean up thread-specific resources first
        domains.clear()

        // Interrupt and clean up threads (copy to avoid ConcurrentModificationException)
        val workers = synchronized(threadPool) { threadPool.toList() }
        for (thread in workers) {
            try {
                if (thread.isAlive) {
                    thread.interrupt()
                    // Give thread a brief moment to stop gracefully
                    thread.join(1000)
                }
            } catch (e: Exception) {
                // Ignore exceptions during cleanup
            }
        }
        threadPool.clear()

        // Call parent cleanup for shared resources
        super.cleanup()
    }
}
