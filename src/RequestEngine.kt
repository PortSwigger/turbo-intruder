package burp

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantReadWriteLock

abstract class RequestEngine {
    var start: Long = System.nanoTime()
    val failedWords = HashMap<String, AtomicInteger>()
    var successfulRequests = AtomicInteger(0)
    val attackState = AtomicInteger(0) // 0 = connecting, 1 = live, 2 = fully queued, 3 = cancelled, 4 = completed
    lateinit var completedLatch: CountDownLatch
    private val baselines = LinkedList<SafeResponseVariations>()
    val retries = AtomicInteger(0)
    val permaFails= AtomicInteger(0)
    lateinit var requestTable: RequestTable
    lateinit var requestQueue: LinkedBlockingQueue<Request>
    abstract val callback: (Request, Boolean) -> Boolean

    abstract fun start(timeout: Int = 10)

    abstract fun buildRequest(template: String, payload: String?, learnBoring: Int?): Request

    fun queue(req: String) {
        queue(req, null, 0)
    }

    fun queue(template: String, payload: String?) {
        queue(template, payload, 0)
    }


    fun queue(template: String, payload: String?, learnBoring: Int?) {

        val request = buildRequest(template, payload, learnBoring)

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
                Utilities.out("Looks like a non-streaming attack, unlimiting the queue")
                requestQueue = LinkedBlockingQueue(requestQueue)
            }
            else {
                Utilities.out("Timeout queuing request. Aborting.")
                this.cancel()
            }
        }
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
            completedLatch.await()
        }

        if (attackState.get() == 3) {
            return
        }

        if (!success) {
            Utilities.out("Aborting attack due to timeout")
            attackState.set(3)
        }
        else {
            Utilities.out("Completed attack")
            attackState.set(4)
        }
        showSummary()
    }

    fun cancel() {
        attackState.set(3)
        Utilities.out("Cancelled attack")
        showSummary()
    }

    fun showSummary() {
        val duration = System.nanoTime().toFloat() - start
        val requests = successfulRequests.get().toFloat()
        Utilities.out("Sent " + requests.toInt() + " requests in "+duration / 1000000000 + " seconds")
        Utilities.out(String.format("RPS: %.0f\n", requests / (duration / 1000000000)))
    }

    fun statusString(): String {
        val duration = ((System.nanoTime().toFloat() - start) / 1000000000).toInt()
        val requests = successfulRequests.get().toFloat()
        var statusString = String.format("Reqs: %d | Queued: %d | Duration: %d |RPS: %.0f | Retries: %d | Fails: %d | Next: %s", requests.toInt(), requestQueue.count(), duration, requests / duration, retries.get(), permaFails.get(), requestQueue.peek()?.word?: "")
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
        val requestsFromTable = requestTable.model.requests

        if (requestsFromTable.size == 0) {
            return
        }

        val copy = ArrayList<Request>(requestsFromTable.size)
        for (tableReq in requestsFromTable) {
            copy.add(tableReq.req)
        }

        requestsFromTable.clear()
        requestTable.model.fireTableRowsDeleted(0, requestsFromTable.size)

        for (request in copy) {
            val interesting = processResponse(request, request.getRawResponse()!!)
            callback(request, interesting)
        }

        requestTable.repaint()
    }

    fun setTable(table: RequestTable) {
        requestTable = table
    }

    fun processResponse(req: Request, response: ByteArray): Boolean {
        val resp = BurpExtender.callbacks.helpers.analyzeResponseVariations(response)

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
        val reqID = req.word ?: req.getRequest().hashCode().toString()

        val fails = failedWords.get(reqID)
        if (fails == null){
            failedWords[reqID] = AtomicInteger(1)
        }
        else {
            if(fails.incrementAndGet() > 3) {
                permaFails.getAndIncrement()
                Utilities.out("Skipping word due to multiple failures: $reqID")
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

}


open class Request(val template: String, val word: String?, val learnBoring: Int) {

    var response: String? = null
    var details: IResponseVariations? = null

    constructor(template: String): this(template, null, 0)

    fun getRequest(): String {
        if (word == null) {
            return template
        }

        if (!template.contains("%s")) {
            Utilities.out("Bad base request - nowhere to inject payload")
        }

        val req = template.replace("%s", word)

        if (req.contains("%s")) {
            Utilities.out("Bad base request - contains too many %s")
        }

        return template.replace("%s", word)
    }

    fun getRawRequest(): ByteArray {
        return fixContentLength(getRequest().toByteArray(Charsets.ISO_8859_1))
    }

    fun getRawResponse(): ByteArray? {
        return response?.toByteArray(Charsets.ISO_8859_1)
    }


    fun fixContentLength(request: ByteArray): ByteArray {
        if (countMatches(request, BurpExtender.callbacks.helpers.stringToBytes("Content-Length: ")) > 0) {
            val start = getBodyStart(request)
            val contentLength = request.size - start
            return setHeader(request, "Content-Length", Integer.toString(contentLength))
        } else {
            return request
        }
    }

    fun setHeader(request: ByteArray, header: String, value: String): ByteArray {
        val offsets = getHeaderOffsets(request, header)
        val outputStream = ByteArrayOutputStream()
        try {
            outputStream.write(Arrays.copyOfRange(request, 0, offsets[1]))
            outputStream.write(value.toByteArray(Charsets.ISO_8859_1))
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.size))
            return outputStream.toByteArray()
        } catch (e: IOException) {
            throw RuntimeException("Request creation unexpectedly failed")
        } catch (e: NullPointerException) {
            Utilities.out("header locating fail: $header")
            throw RuntimeException("Can't find the header")
        }

    }

    fun getHeaderOffsets(request: ByteArray, header: String): IntArray {
        var i = 0
        val end = request.size
        while (i < end) {
            val line_start = i
            while (i < end && request[i++] != ' '.toByte()) {
            }
            val header_name = Arrays.copyOfRange(request, line_start, i - 2)
            val headerValueStart = i
            while (i < end && request[i++] != '\n'.toByte()) {
            }
            if (i == end) {
                break
            }

            val header_str = BurpExtender.callbacks.helpers.bytesToString(header_name)

            if (header == header_str) {
                return intArrayOf(line_start, headerValueStart, i - 2)
            }

            if (i + 2 < end && request[i] == '\r'.toByte() && request[i + 1] == '\n'.toByte()) {
                break
            }
        }
        throw RuntimeException("Couldn't find header: '$header'")
    }

    fun countMatches(response: ByteArray, match: ByteArray): Int {
        var matches = 0
        if (match.size < 4) {
            return matches
        }

        var start = 0
        while (start < response.size) {
            start = BurpExtender.callbacks.helpers.indexOf(response, match, true, start, response.size)
            if (start == -1)
                break
            matches += 1
            start += match.size
        }

        return matches
    }

    fun getBodyStart(response: ByteArray): Int {
        var i = 0
        var newlines_seen = 0
        while (i < response.size) {
            val x = response[i]
            if (x == '\n'.toByte()) {
                newlines_seen++
            } else if (x != '\r'.toByte()) {
                newlines_seen = 0
            }

            if (newlines_seen == 2) {
                break
            }
            i += 1
        }


        while (i < response.size && (response[i] == ' '.toByte() || response[i] == '\n'.toByte() || response[i] == '\r'.toByte())) {
            i++
        }

        return i
    }

}


class SafeResponseVariations {
    private val lock = ReentrantReadWriteLock()
    private val variations = BurpExtender.callbacks.helpers.analyzeResponseVariations()

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