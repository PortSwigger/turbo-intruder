package burp

import org.apache.commons.lang3.RandomStringUtils
import java.io.*
import java.net.URL
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantReadWriteLock
import java.util.zip.GZIPInputStream
import kotlin.collections.HashMap
import kotlin.math.ceil
import kotlin.math.max
import kotlin.math.min

abstract class RequestEngine(
    requiresBurpProfessional: Boolean = false,
) : IExtensionStateListener {

    private companion object {
        /** Marker replaced with a fresh random value on every queued request that carries it. */
        const val RANDOM_MARKER = "\$randomplz"
    }


    var start: Long = System.nanoTime()

    /**
     * When the run stopped, or 0 while it is still going. The status line is read after the fact -
     * by the GUI on its next repaint, by an MCP client whenever it asks - so timing a finished run
     * up to the moment someone looks charges it for the wait: the same 200,000 request run read
     * 100,000 rps immediately and 18,182 rps twelve seconds later.
     */
    private val finished = AtomicLong(0)
    val failedWords = HashMap<Int, AtomicInteger>()
    var successfulRequests = AtomicInteger(0)
    val userState = HashMap<String, Any>()
    val lastRequestID = AtomicInteger(0)
    var connections = AtomicInteger(0)
    val runState = AtomicInteger(0) // 0 = connecting, 1 = live, 2 = fully queued, 3 = cancelled, 4 = completed
    lateinit var completedLatch: CountDownLatch
    private val baselines = LinkedList<SafeResponseVariations>()
    val retries = AtomicInteger(0)
    val permaFails = AtomicInteger(0)
    val transportFailures = AtomicInteger(0)
    val activeRequests = AtomicInteger(0)
    val retiredConnections = AtomicInteger(0)
    private val adaptiveControllerLock = Any()
    private var adaptiveController: AdaptiveController? = null
    private var adaptiveControllerTerminal = false
    private val adaptiveStatus = AdaptiveStatusSource()
    lateinit var outputHandler: OutputHandler
    @set:JvmName("setRequestTableInternal")
    var requestTable: RequestTable? = null
    lateinit var requestQueue: LinkedBlockingQueue<Request>
    abstract val callback: (Request, Boolean) -> Boolean?
    abstract var readCallback: ((String) -> Boolean)?
    abstract val maxRetriesPerRequest: Int
    protected open val supportsKettledRequests: Boolean = false
    lateinit var target: URL
    // Concurrent so that an engine's dispatcher can ask whether the run uses gates at all without
    // taking the monitor. openGate() holds that monitor while it blocks waiting for every gated
    // request to be staged, and the thread doing the staging is the one that would be shut out.
    val floodgates = ConcurrentHashMap<String, Floodgate>()
    // A metric snapshot is a one-use resize token. Gate admission and consuming that token share
    // this monitor, so either the resize commits first and admission validates the new capacity,
    // or admission advances the epoch and the stale resize is rejected.
    private val adaptiveAdmissionLock = Any()
    private var gateAdmissionEpoch = 0L
    private var latestAdaptiveSnapshot = Long.MIN_VALUE
    private var latestAdaptiveSnapshotEpoch = Long.MIN_VALUE
    private val activeGateLifecycles = ConcurrentHashMap.newKeySet<String>()
    private val gateOutstandingRequests = ConcurrentHashMap<String, AtomicInteger>()
    var lastLife: Long = System.currentTimeMillis()
    abstract var idleTimeout: Long
    var fixContentLength: Boolean = true
    var lastError: String? = null

    val internalSettings: HashMap<String, Any> = HashMap()

    init {
        if (requiresBurpProfessional) {
            Utils.requireBurpProfessional()
        }
        lastLife = System.currentTimeMillis()

        if (runState.get() == 3) {
            throw Exception("You cannot create a new request engine for a cancelled run")
        }

        if (Utils.gotBurp) {
            // todo use a helper method instead
            Utils.callbacks.registerExtensionStateListener(this)
        }

        internalSettings["calculateAnomalyRank"] = true
        internalSettings["anomalyRankAlgorithm"] = "burp"
    }

    override fun extensionUnloaded() {
        cancel()
        cleanup()
    }

    fun recordTransportFailure(cause: Throwable) {
        transportFailures.incrementAndGet()
        lastError = cause.toString()
    }

    fun baseAdaptiveMetrics(limits: AdaptiveLimits, saturated: Boolean): AdaptiveMetrics {
        synchronized(adaptiveAdmissionLock) {
            val capturedAt = maxOf(System.nanoTime(), latestAdaptiveSnapshot + 1)
            latestAdaptiveSnapshot = capturedAt
            latestAdaptiveSnapshotEpoch = gateAdmissionEpoch
            val gateActive = activeGateLifecycles.isNotEmpty()
            return AdaptiveMetrics(
                capturedAtNanos = capturedAt,
                successfulResponses = successfulRequests.get(),
                transportFailures = transportFailures.get(),
                retryAttempts = retries.get(),
                permanentFailures = permaFails.get(),
                activeRequests = activeRequests.get(),
                queuedRequests = if (::requestQueue.isInitialized) requestQueue.size else 0,
                openedConnections = connections.get(),
                retiredConnections = retiredConnections.get(),
                limits = limits,
                saturated = saturated,
                freezeReason = if (gateActive) "gate in progress" else null,
            )
        }
    }

    internal fun tryApplyAdaptiveResize(snapshot: AdaptiveMetrics, resize: () -> Unit): Boolean =
        synchronized(adaptiveAdmissionLock) {
            if (activeGateLifecycles.isNotEmpty() ||
                snapshot.capturedAtNanos != latestAdaptiveSnapshot ||
                latestAdaptiveSnapshotEpoch != gateAdmissionEpoch
            ) {
                return@synchronized false
            }
            latestAdaptiveSnapshot = Long.MIN_VALUE
            resize()
            true
        }

    fun invokeCallback(req: Request, interesting: Boolean){
        updateLastLife()
        try {
            req.invokeCallback(interesting)
        } catch (ex: Throwable){
            Utils.out("Error in user-defined callback: $ex")
            ex.printStackTrace()
            permaFails.incrementAndGet()
        }
    }

    fun recordResponseProcessingFailure(cause: Throwable) {
        Utils.out("Error processing received response: $cause")
        cause.printStackTrace()
        permaFails.incrementAndGet()
    }

    abstract fun start(timeout: Int = 10)

    abstract fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): Request

    fun triggerReadCallback(data: String) {
        readCallback?.invoke(data)
    }

    /**
     * Replaces every `${'$'}randomplz` with a fresh random value, and does nothing else.
     *
     * Guarded by a scan rather than replacing unconditionally: this runs twice for every queued
     * request on every engine, and generating the random value alone measured 0.16us against a
     * per-request CPU budget of about 8.6us. Almost no template carries the marker, so the common
     * case should not pay for it.
     */
    private fun substituteRandom(value: String): String {
        if (!value.contains(RANDOM_MARKER, ignoreCase = true)) {
            return value
        }
        return value.replace(
            RANDOM_MARKER,
            RandomStringUtils.randomAlphanumeric(10).lowercase(),
            true,
        )
    }

    fun queue(req: String) {
        queue(req, emptyList())
    }

    fun queue(req: String, payload: kotlin.Any) {
        queue(req, listOf(payload), 0)
    }

    fun queue(template: String, payloads:  List<kotlin.Any?>) {
        queue(template, payloads, 0, null)
    }

    fun queue(
        template: String,
        payloads: List<kotlin.Any?> = emptyList<kotlin.Any>(),
        learnBoring: Int = 0,
        callback: ((Request, Boolean) -> Boolean)? = null,
        gateName: String? = null,
        label: String = "",
        pauseBefore: Int = 0,
        pauseTime: Int = 1000,
        pauseMarkers: List<String> = emptyList(),
        delay: Long = 0,
        endpoint: String? = null,
        pythonEngine: Any? = null,
        fixContentLength: Boolean = true,
        connectionId: String? = null,
    ) = queue(
        template,
        payloads,
        learnBoring,
        callback,
        gateName,
        label,
        pauseBefore,
        pauseTime,
        pauseMarkers,
        delay,
        endpoint,
        pythonEngine,
        fixContentLength,
        connectionId,
        false,
    )

    fun queue(template: String, payloads: List<kotlin.Any?> = emptyList<kotlin.Any>(), learnBoring: Int = 0, callback: ((Request, Boolean) -> Boolean)? = null, gateName: String? = null, label: String = "", pauseBefore: Int = 0, pauseTime: Int = 1000, pauseMarkers: List<String> = emptyList(), delay: Long = 0, endpoint: String? = null, pythonEngine: Any? = null, fixContentLength: Boolean = true, connectionId: String? = null, kettled: Boolean = false) {
        updateLastLife()

        require(!kettled || supportsKettledRequests) {
            "kettled requests are supported only by Engine.BURP2, Engine.HTTP3, or Engine.AUTO when it selects HTTP/2 or HTTP/3"
        }

        if (gateName != null && connectionId != null) {
            throw Exception("Cannot specify both gate and connectionId - they are mutually exclusive")
        }

        val noPayload = payloads.isEmpty()
        val noMarker = !template.contains("%s")

        if (noMarker && !noPayload) {
            throw Exception("The request has payloads specified, but no %s injection markers")
        }
        if (!noMarker && noPayload) {
            val bad = template.indexOf("%s")
            val context = template.slice(max(bad-5, 0).. min(bad+5, template.length))
            throw Exception("The request has a %s injection point, but no payloads specified: '$context'")
        }

        val payloadsAsStrings = payloads.map { substituteRandom(it.toString()) }

        if (learnBoring != 0 && !Utils.gotBurp) {
            throw Exception("Automatic interesting response detection using 'learn=X' isn't support in command line mode.")
        }

        val request = buildRequest(substituteRandom(template), payloadsAsStrings, learnBoring, label)
        request.targetUrl = target
        if (pythonEngine != null) {
            request.engine = pythonEngine
        }
        else {
            request.engine = this
        }

        request.id = lastRequestID.incrementAndGet()
        request.callback = callback ?: { req, interesting -> this.callback(req, interesting) ?: false }
        request.pauseBefore = pauseBefore
        request.pauseTime = pauseTime
        request.pauseMarkers = pauseMarkers
        request.delayCompletion = delay
        request.endpointOverride = endpoint
        request.autoFixContentLength = fixContentLength
        request.connectionId = connectionId
        request.kettled = kettled

        val state = runState.get()

        if (state > 2) {
            throw IllegalStateException("Cannot queue any more items - the run has finished")
        }

        if (gateName != null) {
            synchronized(adaptiveAdmissionLock) {
                synchronized(floodgates) {
                    val existingGate = floodgates[gateName]
                    if (existingGate != null) {
                        if (existingGate.hasStartedOpening()) {
                            throw IllegalStateException("Cannot add a request to gate '$gateName' after openGate() has started")
                        }
                        if (this is ThreadedRequestEngine && existingGate.remaining.get() + 1 > this.currentWorkerCapacity()) {
                            throw Exception("You have queued more gated requests than concurrentConnections, so your run will deadlock. Consider increasing concurrentConnections")
                        }
                        request.gate = existingGate
                        existingGate.addWaiter()
                    } else {
                        request.gate = Floodgate(gateName, this)
                        if (this is ThreadedRequestEngine && request.gate!!.remaining.get() > this.currentWorkerCapacity()) {
                            throw Exception("You have queued more gated requests than concurrentConnections, so your run will deadlock. Consider increasing concurrentConnections")
                        }
                        floodgates[gateName] = request.gate!!
                    }
                    activeGateLifecycles += gateName
                    gateOutstandingRequests.computeIfAbsent(gateName) { AtomicInteger() }.incrementAndGet()
                    gateAdmissionEpoch += 1
                }
            }
        }

        var timeout = 1800L
        if (state == 0) {
            timeout = 1
        }

        // Untimed offer first. Every queued request comes through here, and where the queue has
        // room — which is the whole of a non-streaming run, whose queue is unbounded — the timed
        // form only adds deadline bookkeeping to a call that was never going to block.
        var queued = requestQueue.offer(request)
        var attempt = 0L
        while (!queued && runState.get() <= 2 && attempt < timeout) {
            queued = requestQueue.offer(request, 1, TimeUnit.SECONDS)
            attempt += 1
        }

        if (!queued) {
            finishGatedRequest(request)
            if (state == 0 && requestQueue.size == 100) {
                Utils.out("Looks like a non-streaming run, unlimiting the queue")
                requestQueue = LinkedBlockingQueue(requestQueue)
            }
            else if (attempt == timeout) {
                Utils.out("Timeout queuing request. Aborting.")
                this.cancel()
            } else {
                // the run has been cancelled so we don't need to do anything
            }
        }
    }

    open fun openGate(gateName: String) {
        // Utils.out("Requested gate open: $gateName")
        synchronized(floodgates) {
            if (!floodgates.containsKey(gateName)) {
                throw Exception("Unrecognised gate name in openGate() invocation")
            }
            floodgates[gateName]!!.open()
        }
    }

    internal fun finishGateLifecycle(gateName: String): Boolean {
        gateOutstandingRequests.remove(gateName)
        return activeGateLifecycles.remove(gateName)
    }

    internal fun finishGatedRequest(request: Request): Boolean {
        val gateName = request.gate?.name ?: return false
        val outstanding = gateOutstandingRequests[gateName] ?: return false
        if (outstanding.decrementAndGet() != 0) return false
        if (!gateOutstandingRequests.remove(gateName, outstanding)) return false
        return activeGateLifecycles.remove(gateName)
    }

    internal fun activeGateLifecycleCount(): Int = activeGateLifecycles.size

    fun shouldAbandonRun(): Boolean {
        if (Utils.unloaded) {
            return true
        }
        if (Thread.currentThread().isInterrupted) {
            return true
        }
        if (runState.get() >= 3) {
            return true
        }
        if (idleTimeout > 0 && System.currentTimeMillis() > lastLife + idleTimeout) {
            Utils.out("Cancelling run due to total timeout exceeded: "+ idleTimeout)
            cancel()
            return true
        }
        return false
    }

    fun updateLastLife() {
        if (idleTimeout == 0L) {
            return
        }
        lastLife = System.currentTimeMillis()
    }


    open fun showStats(timeout: Int = -1) {
        try {
            showStatsInternal(timeout)
        } finally {
            stopAdaptiveController()
        }
    }

    private fun showStatsInternal(timeout: Int) {
        if (runState.get() == 3) {
            return
        }

        var success = true
        runState.set(2)
        if (timeout > 0) {
            success = awaitCompletion(timeout.toLong(), TimeUnit.SECONDS)
        }
        else {
            while (!Utils.unloaded && runState.get() < 3) {
                success = awaitCompletion(10, TimeUnit.SECONDS)
                if (success) break
            }
        }

        if (runState.get() == 3) {
            return
        }

        if (!success) {
            Utils.out("Aborting run due to timeout")
            sealCompletion()
            finish(3)
        }
        else {
            sealCompletion()
            Utils.err("Completed run on " +target)
            finish(4)
        }
        showSummary()
    }

    fun cancel() {
        try {
            cancelInternal()
        } finally {
            stopAdaptiveController()
        }
    }

    private fun cancelInternal() {
        if (Utils.gotBurp && !Utils.unloaded) {
            Utils.callbacks.removeExtensionStateListener(this)
        }

        if (runState.get() != 3) {
            finish(3)
            sealCompletion()
            Utils.out("Cancelled run")

            // Wait for all worker threads to finish their callbacks before calculating anomaly rankings
            // This prevents ConcurrentModificationException when iterating the request list
            if (completionInitialized()) {
                val timeout = 30L // seconds
                val finished = awaitCompletion(timeout, TimeUnit.SECONDS)
                if (!finished) {
                    Utils.err("Warning: Worker threads did not complete within ${timeout}s during cancellation")
                }
            }

            showSummary()
        }

        // Clean up memory to prevent leaks
        cleanup()
    }

    fun installAdaptiveController(controller: AdaptiveController) {
        synchronized(adaptiveControllerLock) {
            check(!adaptiveControllerTerminal && runState.get() < 3) {
                "Cannot install an adaptive controller on a terminal engine"
            }
            check(adaptiveController == null) {
                "An adaptive controller is already installed"
            }
            controller.attachStatusSource(adaptiveStatus)
            adaptiveController = controller
        }
    }

    fun stopAdaptiveController() {
        val controller = synchronized(adaptiveControllerLock) {
            adaptiveControllerTerminal = true
            adaptiveController.also { adaptiveController = null }
        }
        controller?.stop()
    }

    protected open fun completionInitialized(): Boolean = ::completedLatch.isInitialized

    protected open fun awaitCompletion(timeout: Long, unit: TimeUnit): Boolean =
        completedLatch.await(timeout, unit)

    protected open fun sealCompletion() {}

    /**
     * Ends the run in [state] - 3 cancelled, 4 completed - and freezes how long it took, so every
     * later read of the status line reports the rate the run actually achieved.
     */
    fun finish(state: Int) {
        var controller: AdaptiveController? = null
        if (state >= 3) {
            synchronized(adaptiveControllerLock) {
                adaptiveControllerTerminal = true
                controller = adaptiveController
                adaptiveController = null
                finished.compareAndSet(0, System.nanoTime())
                runState.set(state)
            }
        } else {
            finished.compareAndSet(0, System.nanoTime())
            runState.set(state)
        }
        controller?.stop()
    }

    /** How long the run has taken, and once it is over, how long it took. */
    private fun elapsedNanos(): Long {
        val end = finished.get()
        return (if (end == 0L) System.nanoTime() else end) - start
    }

    fun showSummary() {
        // todo or invoke completedCallback here?
        if (Utils.gotBurp && !Utils.unloaded) {
            Utils.callbacks.removeExtensionStateListener(this)
        }
        val duration = elapsedNanos().toFloat()
        val requests = successfulRequests.get().toFloat()
        Utils.err("Sent ${requests.toInt()} requests over ${connections.toInt()} connections in ${duration / 1000000000} seconds")
        Utils.err(String.format("RPS: %.0f\n", requests / ceil((duration / 1000000000).toDouble())))

        // Calculate anomaly rankings when run is stopped or completed
        if (runState.get() >= 3) {
            // All worker threads have finished (waited in cancel() or showStats())
            // so it's safe to iterate the request list for anomaly ranking
            calculateAnomalyRankings()
        }

        // Clean up memory when run is completed
        if (runState.get() >= 4) {
            cleanup()
        }
    }

    private fun calculateAnomalyRankings() {
        if (!Utils.gotBurp || Utils.unloaded) {
            return
        }

        if (internalSettings["calculateAnomalyRank"] == false) {
            return
        }

        try {
            val totalStart = System.currentTimeMillis()

            val t0 = System.currentTimeMillis()
            val allRequests = outputHandler.getAllRquests()
            if (allRequests.isEmpty()) {
                return
            }
            Utils.err("Anomaly rank: getAllRequests=${System.currentTimeMillis() - t0}ms (${allRequests.size} requests)")

            val algorithm = internalSettings["anomalyRankAlgorithm"] as? String ?: "burp"
            val t1 = System.currentTimeMillis()

            if (algorithm == "local") {
                // Local ranker streams Montoya conversion internally — no need to
                // pre-build all Montoya objects, saving ~2x response memory
                try {
                    val rankerClass = Class.forName("burp.LocalAnomalyRanker")
                    val rankMethod = rankerClass.getMethod("rank", List::class.java)
                    rankMethod.invoke(null, allRequests)
                    Utils.err("Anomaly rank: localAlgorithm=${System.currentTimeMillis() - t1}ms")
                } catch (e: ClassNotFoundException) {
                    Utils.err("LocalAnomalyRanker not found, falling back to burp algorithm")
                    runBurpRanking(allRequests, t1)
                }
            } else {
                runBurpRanking(allRequests, t1)
            }

            // Notify the table model to update the UI
            val t3 = System.currentTimeMillis()
            requestTable?.let { table ->
                table.model.updateRankings()

                // Auto-sort by anomaly rank if user hasn't customized sorting
                javax.swing.SwingUtilities.invokeLater {
                    if (!table.hasSortBeenModified()) {
                        table.autoSortByAnomalyRank()
                    }
                }
            }
            Utils.err("Anomaly rank: tableUpdate=${System.currentTimeMillis() - t3}ms")
            Utils.err("Anomaly rank: total=${System.currentTimeMillis() - totalStart}ms")
        } catch (e: Exception) {
            Utils.err("Error calculating anomaly rankings: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun runBurpRanking(allRequests: List<Request>, startTime: Long) {
        try {
            val t0 = System.currentTimeMillis()
            val requestsWithMontoya = allRequests.mapNotNull { req ->
                req.getMontoyaRequest()?.let { montoya -> req to montoya }
            }
            val withMontoyaSet = requestsWithMontoya.map { it.first }.toHashSet()
            allRequests.filter { it !in withMontoyaSet }.forEach { it.anomalyRank = -1 }
            if (requestsWithMontoya.isEmpty()) return
            Utils.err("Anomaly rank: burpConvertToMontoya=${System.currentTimeMillis() - t0}ms")

            val t1 = System.currentTimeMillis()
            val montoyaRequests = requestsWithMontoya.map { it.second }
            val rankedRequests = Utils.montoyaApi.utilities().rankingUtils().rank(montoyaRequests)

            for (i in requestsWithMontoya.indices) {
                if (i < rankedRequests.size) {
                    requestsWithMontoya[i].first.anomalyRank = rankedRequests[i].rank()
                }
            }
            Utils.err("Anomaly rank: burpAlgorithm=${System.currentTimeMillis() - t1}ms, total=${System.currentTimeMillis() - startTime}ms")
        } catch (e: NoSuchMethodError) {
            Utils.err("Anomaly ranking API not available in Burp versions below 2025.10")
            allRequests.forEach { it.anomalyRank = 0 }
        } catch (e: NoClassDefFoundError) {
            Utils.err("Anomaly ranking API not available in Burp versions below 2025.10")
            allRequests.forEach { it.anomalyRank = 0 }
        }
    }

    /**
     * Why the run has produced nothing, or null while there is nothing conclusive to say.
     *
     * <p>A run where every request failed to reach the target reads on the status line exactly
     * like a run that had nothing to do: zero requests, zero connections, a count of fails and
     * "Completed". The cause is already recorded in [lastError], but until this it was composed
     * into a sentence only by the MCP layer, so a GUI user was left guessing between a target
     * that does not speak the protocol, the wrong port and a rejected certificate.
     */
    open fun failureSummary(): String? {
        val fails = permaFails.get()
        if (successfulRequests.get() > 0 || fails == 0) {
            return null
        }
        val error = lastError ?: return null
        return "All $fails requests failed with connection errors: $error"
    }

    fun statusString(): String {
        val elapsedNanos = elapsedNanos()
        val duration = ceil((elapsedNanos.toFloat() / 1000000000).toDouble()).toInt()
        val requests = successfulRequests.get().toFloat()
        // Divided by the time actually taken, not the whole second Duration rounds up to. The
        // ceiling only ever understates, and worst just past a boundary: 500,000 requests in
        // 6.01s reported 71,429 where the rate was 83,200. Duration stays rounded up, so it
        // never claims a run was quicker than it was, and requests/rps now recovers the real
        // elapsed time to the millisecond.
        val seconds = elapsedNanos.toDouble() / 1_000_000_000
        val rps = if (seconds > 0) requests / seconds else 0.0
        val nextWord = requestQueue.peek()?.words?.joinToString(separator="/")
        val statusString = String.format("Reqs: %d | Queued: %d | Duration: %d | RPS: %.0f | Connections: %d | Retries: %d | Fails: %d | Next: %s", requests.toInt(), requestQueue.count(), duration, rps, connections.get(), retries.get(), permaFails.get(), nextWord)
        val withAdaptiveStatus = adaptiveStatus.snapshot()?.let { status ->
            val protocol = when (status.protocol) {
                AutoProtocol.HTTP1 -> "THREADED"
                AutoProtocol.HTTP2 -> "BURP2"
                AutoProtocol.HTTP3 -> "HTTP3"
            }
            val requestsPerConnection = status.limits.requestsPerConnection?.toString() ?: "N/A"
            "$statusString | AUTO $protocol" +
                " | concurrentConnections=${status.limits.concurrency}" +
                " | requestsPerConnection=$requestsPerConnection"
        } ?: statusString
        // In front of the metrics rather than after them: the GUI status bar is a single JLabel
        // that clips at the width of the window, so a reason appended to the end of an already
        // long line is one the user never sees. A run with nothing to report loses only zeros.
        val withFailure = failureSummary()?.let { it + " | " + withAdaptiveStatus } ?: withAdaptiveStatus
        return when (runState.get()) {
            in Int.MIN_VALUE..2 -> withFailure
            3 -> "$withFailure | Cancelled"
            else -> "$withFailure | Completed"
        }
    }

    fun setOutput(outputHandler: OutputHandler) {
        this.outputHandler = outputHandler
    }

    fun setRequestTable(table: RequestTable?) {
        this.requestTable = table
    }

    open fun processResponse(req: Request, response: ByteArray): Boolean {
        if (!Utils.gotBurp) {
            return false
        }

        if (req.learnBoring == 0 && baselines.isEmpty()) {
            return true
        }

        val resp = req.details ?: Utils.callbacks.helpers.analyzeResponseVariations(response)

        // fixme might screw over the user if they try to add multiple overlapping fingerprints?
        for(base in baselines) {
            if (invariantsMatch(base, resp)) {
                return false
            }
        }

        if (req.learnBoring != 0) {
            var base = baselines.getOrNull(req.learnBoring-1)
            if (base == null) {
                base = SafeResponseVariations()
                baselines.add(base)
            }
            base.updateWith(response)

            //reinvokeCallbacks()
            return false
        }

        return true
    }

    fun shouldRetry(req: Request): Boolean {
        if (maxRetriesPerRequest < 1) {
            permaFails.getAndIncrement()
            return false
        }

        val reqID = req.id // req.getRequest().hashCode().toString() +

        val fails = failedWords[reqID]
        if (fails == null){
            failedWords[reqID] = AtomicInteger(1)
        }
        else {
            if(fails.incrementAndGet() > maxRetriesPerRequest) {
                permaFails.getAndIncrement()
                Utils.out("Skipping word due to multiple failures: $reqID")
                return false
            }
        }

        retries.getAndIncrement()
        return true
    }

    fun applySetting(settingName: String, settingValue: Any) {
        if (!internalSettings.containsKey(settingName)) {
            val msg = "Unrecognised setting name: $settingName. This engine supports the following settings: ${internalSettings.keys}"
            throw Exception(msg)
        }
        internalSettings[settingName] = settingValue
    }

    fun clearErrors() {
        failedWords.clear()
    }

    private fun invariantsMatch(base: SafeResponseVariations, resp: IResponseVariations): Boolean {
        val invariants = base.getInvariantAttributes()

        for(attribute in invariants) {
            if (base.getAttributeValue(attribute) != resp.getAttributeValue(attribute, 0)) {
                return false
            }
        }

        return true
    }

    open fun cleanup() {
        // Clear collections to free memory
        failedWords.clear()
        baselines.clear()
        floodgates.clear()
        synchronized(adaptiveAdmissionLock) {
            activeGateLifecycles.clear()
            gateOutstandingRequests.clear()
            gateAdmissionEpoch += 1
            latestAdaptiveSnapshot = Long.MIN_VALUE
        }
        requestQueue.clear()
        userState.clear()
    }

}


class SafeResponseVariations {
    private val lock = ReentrantReadWriteLock()
    private val variations = Utils.callbacks.helpers.analyzeResponseVariations()

    fun updateWith(response: ByteArray) {
        val writelock = lock.writeLock()
        writelock.lock()
        variations.updateWith(response)
        writelock.unlock()
    }

    fun getInvariantAttributes(): List<String> {
        val readlock = lock.readLock()
        readlock.lock()
        val invariants = variations.invariantAttributes
        readlock.unlock()
        return invariants
    }

    fun getAttributeValue(attribute: String): Int {
        return variations.getAttributeValue(attribute, 0)
    }
}
