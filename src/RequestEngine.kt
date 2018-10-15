package burp

import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantReadWriteLock

abstract class RequestEngine {
    var start: Long = 0
    var successfulRequests = AtomicInteger(0)
    val attackState = AtomicInteger(0) // 0 = connecting, 1 = live, 2 = fully queued, 3 = cancelled, 4 = completed
    lateinit var completedLatch: CountDownLatch
    private val baselines = LinkedList<SafeResponseVariations>()

    abstract fun start(timeout: Int = 10)
    abstract fun queue(req: String)
    //abstract fun queue(template: String, payload: String?)

    open fun showStats(timeout: Int = -1) {
        if (attackState.get() == 3) {
            return
        }

        attackState.set(2)
        val success = completedLatch.await(timeout.toLong(), TimeUnit.SECONDS)
        if (!success) {
            Utilities.out("Aborting attack due to timeout")
            attackState.set(3)
        }
        else {
            attackState.set(4)
        }
        showSummary()
    }

    fun cancel() {
        attackState.set(3)
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
        var statusString = String.format("Reqs: %d | RPS: %.0f | Duration: %d", requests.toInt(), requests / duration, duration)
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

    fun processResponse(req: Request, response: ByteArray): Boolean {
        if (req.learnBoring != 0) {
            var base = baselines.getOrNull(req.learnBoring-1)
            if (base == null) {
                base = SafeResponseVariations()
                baselines.add(base)
            }
            base.updateWith(response)
            return false
        }
        else if (baselines.isEmpty()) {
            return true
        }

        val resp = BurpExtender.callbacks.helpers.analyzeResponseVariations(response)

        for(base in baselines) {
            if (invariantsMatch(base, resp)) {
                return false
            }
        }

        return true
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

class Request(val template: String, val word: String?, val learnBoring: Int) {

    var response: String? = null

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
        return getRequest().toByteArray(Charsets.ISO_8859_1)
    }

    fun getRawResponse(): ByteArray? {
        return response?.toByteArray(Charsets.ISO_8859_1)
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