package burp

import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

data class LimitSnapshot(val limit: Int, val acquired: Int)

/**
 * A capacity limit that can shrink below its current owner count without revoking any owner.
 * New acquisitions resume only after enough owners release or the limit grows again.
 */
class ResizableLimit(initialLimit: Int) {
    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private var limit = initialLimit
    private var acquired = 0

    init {
        require(initialLimit >= 0) { "limit must be non-negative" }
    }

    fun tryAcquire(): Boolean = lock.withLock {
        if (acquired >= limit) return false
        acquired += 1
        true
    }

    fun tryAcquire(timeout: Long, unit: TimeUnit, cancelled: () -> Boolean): Boolean {
        require(timeout >= 0) { "timeout must be non-negative" }
        var remainingNanos = unit.toNanos(timeout)
        var measuredAt = System.nanoTime()
        lock.lockInterruptibly()
        try {
            remainingNanos = subtractElapsed(remainingNanos, measuredAt)
            while (true) {
                if (cancelled()) return false
                if (acquired < limit) {
                    acquired += 1
                    return true
                }
                if (remainingNanos <= 0) return false
                measuredAt = System.nanoTime()
                changed.awaitNanos(minOf(remainingNanos, CANCELLATION_POLL_NANOS))
                remainingNanos = subtractElapsed(remainingNanos, measuredAt)
            }
        } finally {
            lock.unlock()
        }
    }

    fun release() = lock.withLock {
        check(acquired > 0) { "limit owner was released twice" }
        acquired -= 1
        changed.signalAll()
    }

    fun resize(newLimit: Int) = lock.withLock {
        require(newLimit >= 0) { "limit must be non-negative" }
        val grew = newLimit > limit
        limit = newLimit
        if (grew) changed.signalAll()
    }

    fun snapshot(): LimitSnapshot = lock.withLock { LimitSnapshot(limit, acquired) }

    /** Uses elapsed deltas, so a negative nanoTime origin cannot overflow an absolute deadline. */
    private fun subtractElapsed(remainingNanos: Long, measuredAt: Long): Long {
        val elapsed = System.nanoTime() - measuredAt
        return if (elapsed <= 0) remainingNanos else (remainingNanos - elapsed).coerceAtLeast(0)
    }

    private companion object {
        val CANCELLATION_POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(50)
    }
}
