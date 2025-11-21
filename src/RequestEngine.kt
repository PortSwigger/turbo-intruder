package burp

import org.apache.commons.lang3.RandomStringUtils
import java.io.*
import java.net.URL
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantReadWriteLock
import java.util.zip.GZIPInputStream
import kotlin.collections.HashMap
import kotlin.math.ceil
import kotlin.math.max
import kotlin.math.min

abstract class RequestEngine: IExtensionStateListener {

    var start: Long = System.nanoTime()
    val failedWords = HashMap<Int, AtomicInteger>()
    var successfulRequests = AtomicInteger(0)
    val userState = HashMap<String, Any>()
    val lastRequestID = AtomicInteger(0)
    var connections = AtomicInteger(0)
    val attackState = AtomicInteger(0) // 0 = connecting, 1 = live, 2 = fully queued, 3 = cancelled, 4 = completed
    lateinit var completedLatch: CountDownLatch
    private val baselines = LinkedList<SafeResponseVariations>()
    val retries = AtomicInteger(0)
    val permaFails = AtomicInteger(0)
    lateinit var outputHandler: OutputHandler
    lateinit var requestQueue: LinkedBlockingQueue<Request>
    abstract val callback: (Request, Boolean) -> Boolean?
    abstract var readCallback: ((String) -> Boolean)?
    abstract val maxRetriesPerRequest: Int
    lateinit var target: URL
    val floodgates = HashMap<String, Floodgate>()
    var lastLife: Long = System.currentTimeMillis()
    abstract var idleTimeout: Long
    var fixContentLength: Boolean = true

    val internalSettings: HashMap<String, Any> = HashMap()

    init {
        lastLife = System.currentTimeMillis()

        if (attackState.get() == 3) {
            throw Exception("You cannot create a new request engine for a cancelled attack")
        }

        if (Utils.gotBurp) {
            // todo use a helper method instead
            Utils.callbacks.registerExtensionStateListener(this)
        }
    }

    override fun extensionUnloaded() {
        cancel()
        cleanup()
    }

    fun invokeCallback(req: Request, interesting: Boolean){
        updateLastLife()
        try {
            req.invokeCallback(interesting)
        } catch (ex: Exception){
            Utils.out("Error in user-defined callback: $ex")
            ex.printStackTrace()
            permaFails.incrementAndGet()
        }
    }

    abstract fun start(timeout: Int = 10)

    abstract fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): Request

    fun triggerReadCallback(data: String) {
        readCallback?.invoke(data)
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

    fun queue(template: String, payloads: List<kotlin.Any?> = emptyList<kotlin.Any>(), learnBoring: Int = 0, callback: ((Request, Boolean) -> Boolean)? = null, gateName: String? = null, label: String = "", pauseBefore: Int = 0, pauseTime: Int = 1000, pauseMarkers: List<String> = emptyList(), delay: Long = 0, endpoint: String? = null, pythonEngine: Any? = null, fixContentLength: Boolean = true) {
        updateLastLife()

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

        val payloadsAsStrings = payloads.map { it.toString().replace("\$randomplz", RandomStringUtils.randomAlphanumeric(8).lowercase(), true) }

        if (learnBoring != 0 && !Utils.gotBurp) {
            throw Exception("Automatic interesting response detection using 'learn=X' isn't support in command line mode.")
        }

        val request = buildRequest(template.replace("\$randomplz", RandomStringUtils.randomAlphanumeric(8).lowercase(), true), payloadsAsStrings, learnBoring, label)
        request._engine = this
        if (pythonEngine != null) {
            request.engine = pythonEngine
        }
        else {
            request.engine = this
        }

        request.id = lastRequestID.incrementAndGet()
        request.callback = callback
        request.pauseBefore = pauseBefore
        request.pauseTime = pauseTime
        request.pauseMarkers = pauseMarkers
        request.delayCompletion = delay
        request.endpointOverride = endpoint
        request.autoFixContentLength = fixContentLength

        if (gateName != null) {
            synchronized(gateName) {
                request.gate = floodgates[gateName] ?: Floodgate(gateName, this)

                if (floodgates.containsKey(gateName)) {
                    floodgates[gateName]!!.addWaiter()
                } else {
                    floodgates[gateName] = request.gate!!
                }

                if (this is ThreadedRequestEngine && request.gate!!.remaining.get() > this.threads) {
                    throw Exception("You have queued more gated requests than concurrentConnections, so your attack will deadlock. Consider increasing concurrentConnections")
                }
            }
        }

        val state = attackState.get()

        if (state > 2) {
            throw IllegalStateException("Cannot queue any more items - the attack has finished")
        }

        var timeout = 1800L
        if (state == 0) {
            timeout = 1
        }

        var queued = false
        var attempt = 0L
        while (!queued && attackState.get() <= 2 && attempt < timeout) {
            queued = requestQueue.offer(request, 1, TimeUnit.SECONDS)
            attempt += 1
        }

        if (!queued) {
            if (state == 0 && requestQueue.size == 100) {
                Utils.out("Looks like a non-streaming attack, unlimiting the queue")
                requestQueue = LinkedBlockingQueue(requestQueue)
            }
            else if (attempt == timeout) {
                Utils.out("Timeout queuing request. Aborting.")
                this.cancel()
            } else {
                // the attack has been cancelled so we don't need to do anything
            }
        }
    }

    open fun openGate(gateName: String) {
        // Utils.out("Requested gate open: $gateName")
        if (!floodgates.containsKey(gateName)) {
            throw Exception("Unrecognised gate name in openGate() invocation")
        }
        floodgates[gateName]!!.open()
    }

    fun shouldAbandonAttack(): Boolean {
        if (Utils.unloaded) {
            return true
        }
        if (Thread.currentThread().isInterrupted) {
            return true
        }
        if (attackState.get() >= 3) {
            return true
        }
        if (idleTimeout > 0 && System.currentTimeMillis() > lastLife + idleTimeout) {
            Utils.out("Cancelling attack due to total timeout exceeded: "+ idleTimeout)
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
        if (attackState.get() == 3) {
            return
        }

        var success = true
        attackState.set(2)
        if (timeout > 0) {
            success = completedLatch.await(timeout.toLong(), TimeUnit.SECONDS)
        }
        else {
            while (completedLatch.count > 0 && !Utils.unloaded && attackState.get() < 3) {
                completedLatch.await(10, TimeUnit.SECONDS)
            }
        }

        if (attackState.get() == 3) {
            return
        }

        if (!success) {
            Utils.out("Aborting attack due to timeout")
            attackState.set(3)
        }
        else {
            Utils.err("Completed attack on " +target)
            attackState.set(4)
        }
        showSummary()
    }

    fun cancel() {
        if (Utils.gotBurp && !Utils.unloaded) {
            Utils.callbacks.removeExtensionStateListener(this)
        }

        if (attackState.get() != 3) {
            attackState.set(3)
            Utils.out("Cancelled attack")

            // Wait for all worker threads to finish their callbacks before calculating anomaly rankings
            // This prevents ConcurrentModificationException when iterating the request list
            if (::completedLatch.isInitialized) {
                val timeout = 30L // seconds
                val finished = completedLatch.await(timeout, TimeUnit.SECONDS)
                if (!finished) {
                    Utils.err("Warning: Worker threads did not complete within ${timeout}s during cancellation")
                }
            }

            showSummary()
        }

        // Clean up memory to prevent leaks
        cleanup()
    }

    fun showSummary() {
        // todo or invoke completedCallback here?
        if (Utils.gotBurp && !Utils.unloaded) {
            Utils.callbacks.removeExtensionStateListener(this)
        }
        val duration = System.nanoTime().toFloat() - start
        val requests = successfulRequests.get().toFloat()
        Utils.err("Sent ${requests.toInt()} requests over ${connections.toInt()} connections in ${duration / 1000000000} seconds")
        Utils.err(String.format("RPS: %.0f\n", requests / ceil((duration / 1000000000).toDouble())))

        // Calculate anomaly rankings when attack is stopped or completed
        if (attackState.get() >= 3 && shouldCalculateAnomalyRankings()) {
            // All worker threads have finished (waited in cancel() or showStats())
            // so it's safe to iterate the request list for anomaly ranking
            calculateAnomalyRankings()
        }

        // Clean up memory when attack is completed
        if (attackState.get() >= 4) {
            cleanup()
        }
    }

    private fun shouldCalculateAnomalyRankings(): Boolean {
        if (!Utils.gotBurp || Utils.unloaded) {
            return false
        }
        return Utilities.globalSettings.getBoolean("anomaly ranking")
    }

    private fun calculateAnomalyRankings() {
        if (!Utils.gotBurp || Utils.unloaded) {
            return
        }

        try {
            val allRequests = outputHandler.getAllRquests()
            if (allRequests.isEmpty()) {
                return
            }

            // Convert Request objects to Montoya HttpRequestResponse objects
            val montoyaRequests = allRequests.mapNotNull { it.getMontoyaRequest() }
            if (montoyaRequests.isEmpty()) {
                return
            }

            try {
                // Calculate rankings using Burp's RankingUtils
                val rankedRequests = Utils.montoyaApi.utilities().rankingUtils().rank(montoyaRequests)

                // Map rankings back to Request objects
                for (i in allRequests.indices) {
                    if (i < rankedRequests.size) {
                        val floatRank = rankedRequests[i].rank()
                        allRequests[i].anomalyRank = floatRank // kotlin.math.round(floatRank * 10000).toInt()
                    }
                }
            } catch (e: NoSuchMethodError) {
                Utils.err("Anomaly ranking API not available in Burp versions below 2025.10")
                // Set all ranks to 0 as fallback
                for (request in allRequests) {
                    request.anomalyRank = 0
                }
            } catch (e: NoClassDefFoundError) {
                Utils.err("Anomaly ranking API not available in Burp versions below 2025.10")
                // Set all ranks to 0 as fallback
                for (request in allRequests) {
                    request.anomalyRank = 0
                }
            }

            // Notify the table model to update the UI
            val handler = outputHandler
            if (handler is RequestTable) {
                handler.model.updateRankings()

                // Auto-sort by anomaly rank if user hasn't customized sorting
                javax.swing.SwingUtilities.invokeLater {
                    if (!handler.hasSortBeenModified()) {
                        handler.autoSortByAnomalyRank()
                    }
                }
            }
        } catch (e: Exception) {
            Utils.err("Error calculating anomaly rankings: ${e.message}")
            e.printStackTrace()
        }
    }

    fun statusString(): String {
        val duration = ceil(((System.nanoTime().toFloat() - start) / 1000000000).toDouble()).toInt()
        val requests = successfulRequests.get().toFloat()
        val nextWord = requestQueue.peek()?.words?.joinToString(separator="/")
        val statusString = String.format("Reqs: %d | Queued: %d | Duration: %d | RPS: %.0f | Connections: %d | Retries: %d | Fails: %d | Next: %s", requests.toInt(), requestQueue.count(), duration, requests / duration, connections.get(), retries.get(), permaFails.get(), nextWord)
        val state = attackState.get()
        return when {
            state < 3 -> statusString
            state == 3 -> statusString + " | Cancelled"
            else -> statusString + " | Completed"
        }
    }

    fun setOutput(outputHandler: OutputHandler) {
        this.outputHandler = outputHandler
    }

    fun processResponse(req: Request, response: ByteArray): Boolean {
        if (!Utils.gotBurp) {
            return false
        }

        val shouldLearn = req.learnBoring != 0
        val hasBaselines = baselines.isNotEmpty()

        if (!shouldLearn && !hasBaselines) {
            return true
        }

        val resp = Utils.callbacks.helpers.analyzeResponseVariations(response)

        // fixme might screw over the user if they try to add multiple overlapping fingerprints?
        for(base in baselines) {
            if (invariantsMatch(base, resp)) {
                return false
            }
        }

        if (shouldLearn) {
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
