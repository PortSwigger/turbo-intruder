package burp

import java.io.*
import java.net.URL
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantReadWriteLock
import java.util.zip.GZIPInputStream

abstract class RequestEngine: IExtensionStateListener {

    var start: Long = System.nanoTime()
    val failedWords = HashMap<String, AtomicInteger>()
    var successfulRequests = AtomicInteger(0)
    var connections = AtomicInteger(0)
    val attackState = AtomicInteger(0) // 0 = connecting, 1 = live, 2 = fully queued, 3 = cancelled, 4 = completed
    lateinit var completedLatch: CountDownLatch
    private val baselines = LinkedList<SafeResponseVariations>()
    val retries = AtomicInteger(0)
    val permaFails= AtomicInteger(0)
    lateinit var outputHandler: OutputHandler
    lateinit var requestQueue: LinkedBlockingQueue<Request>
    abstract val callback: (Request, Boolean) -> Boolean
    abstract var readCallback: ((String) -> Boolean)?
    abstract val maxRetriesPerRequest: Int
    lateinit var target: URL
    private val floodgates = HashMap<String, Floodgate>()

    init {
        if (Utils.gotBurp) {
            Utils.callbacks.registerExtensionStateListener(this)
        }
    }

    override fun extensionUnloaded() {
        cancel()
    }

    fun invokeCallback(req: Request, interesting: Boolean){
        try {
            req.invokeCallback(interesting)
        } catch (ex: Exception){
            Utils.out("Error in user-defined callback: "+ex)
            permaFails.incrementAndGet()
        }
    }

    abstract fun start(timeout: Int = 10)

    abstract fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?): Request

    fun triggerReadCallback(data: String) {
        readCallback?.invoke(data)
    }

    fun queue(req: String) {
        queue(req, emptyList<String>(), 0, null, null)
    }

    fun queue(req: String, payload: String) {
        queue(req, listOf(payload), 0, null, null)
    }

    fun queue(template: String, payloads:  List<String?>) {
        queue(template, payloads, 0, null, null)
    }

    fun queue(template: String, payloads: List<String?>, learnBoring: Int, callback: ((Request, Boolean) -> Boolean)?, gateName: String?) {

        val noPayload = payloads.isEmpty()
        val noMarker = !template.contains("%s")

        if (noMarker && !noPayload) {
            throw Exception("The request has payloads specified, but no %s injection markers")
        }
        if (!noMarker && noPayload) {
            throw Exception("The request has a %s injection point, but no payloads specified")
        }

        if (learnBoring != 0 && !Utils.gotBurp) {
            throw Exception("Automatic interesting response detection using 'learn=X' isn't support in command line mode.")
        }

        val request = buildRequest(template, payloads, learnBoring)
        request.engine = this
        request.callback = callback


        if (gateName != null) {
            synchronized(gateName) {
                request.gate = floodgates[gateName] ?: Floodgate()

                if (floodgates.containsKey(gateName)) {
                    floodgates[gateName]!!.addWaiter()
                } else {
                    floodgates[gateName] = request.gate!!
                }

                if (this is ThreadedRequestEngine && request.gate!!.remaining.get() > (this as ThreadedRequestEngine).threads) {
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

        val queued = requestQueue.offer(request, timeout, TimeUnit.SECONDS)
        if (!queued) {
            if (state == 0 && requestQueue.size == 100) {
                Utils.out("Looks like a non-streaming attack, unlimiting the queue")
                requestQueue = LinkedBlockingQueue(requestQueue)
            }
            else {
                Utils.out("Timeout queuing request. Aborting.")
                this.cancel()
            }
        }
    }

    open fun openGate(gateName: String) {
        //Utils.out("Opening gate "+gateName)
        if (!floodgates.containsKey(gateName)) {
            throw Exception("Unrecognised gate name in openGate() invocation")
        }
        floodgates[gateName]!!.open()
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
            Utils.err("Completed attack")
            attackState.set(4)
        }
        showSummary()
    }

    fun cancel() {
        attackState.set(3)
        Utils.out("Cancelled attack")
        showSummary()
    }

    fun showSummary() {
        val duration = System.nanoTime().toFloat() - start
        val requests = successfulRequests.get().toFloat()
        Utils.err("Sent " + requests.toInt() + " requests in "+duration / 1000000000 + " seconds")
        Utils.err(String.format("RPS: %.0f\n", requests / Math.ceil((duration / 1000000000).toDouble())))
    }

    fun statusString(): String {
        val duration = Math.ceil(((System.nanoTime().toFloat() - start) / 1000000000).toDouble()).toInt()
        val requests = successfulRequests.get().toFloat()
        val nextWord = requestQueue?.peek()?.words?.joinToString(separator="/")
        var statusString = String.format("Reqs: %d | Queued: %d | Duration: %d |RPS: %.0f | Connections: %d | Retries: %d | Fails: %d | Next: %s", requests.toInt(), requestQueue.count(), duration, requests / duration, connections.get(), retries.get(), permaFails.get(), nextWord)
        val state = attackState.get()
        if (state < 3) {
            return statusString
        }
        else if (state == 3) {
            return statusString + " | Cancelled"
        }
        else {
            return statusString + " | Completed"
        }
    }

    fun reinvokeCallbacks() {
        val reqTable = outputHandler

        // if the request engine isn't a table, we can't update the output
        if (reqTable is RequestTable) {

            val requestsFromTable = reqTable.model.requests

            if (requestsFromTable.size == 0) {
                return
            }

            val copy = ArrayList<Request>(requestsFromTable.size)
            for (tableReq in requestsFromTable) {
                copy.add(tableReq)
            }

            requestsFromTable.clear()
            //reqTable.model.fireTableRowsDeleted(0, requestsFromTable.size)

            for (request in copy) {
                val interesting = processResponse(request, request.getResponseAsBytes()!!)
                callback(request, interesting)
            }

            reqTable.model.fireTableDataChanged()
            //reqTable.repaint()
        }
    }

    fun setOutput(outputHandler: OutputHandler) {
        this.outputHandler = outputHandler
    }

    fun processResponse(req: Request, response: ByteArray): Boolean {
        if (!Utils.gotBurp) {
            return false
        }


        val resp = Utils.callbacks.helpers.analyzeResponseVariations(response)

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

            reinvokeCallbacks()
            return false
        }
        else if (baselines.isEmpty()) {
            return true
        }

        return true
    }

    fun shouldRetry(req: Request): Boolean {
        if (maxRetriesPerRequest < 1) {
            permaFails.getAndIncrement()
            return false
        }

        val reqID = req.getRequest().hashCode().toString()

        val fails = failedWords.get(reqID)
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

    fun decompress(compressed: ByteArray): String {
        if (compressed.size == 0) {
            return ""
        }

        val bytesIn = ByteArrayInputStream(compressed)
        val unzipped = GZIPInputStream(bytesIn)
        val out = ByteArrayOutputStream()
        try {
            while (true) {
                val bytes = ByteArray(1024)
                val read = unzipped.read(bytes, 0, 1024)
                if (read <= 0) {
                    break
                }
                out.write(bytes)
            }
        } catch (e: IOException) {
            Utils.err("GZIP decompression failed - possible partial response")
        }
        return String(out.toByteArray())
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