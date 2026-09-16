package burp

import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal fun interface AdaptiveWorkerStarter {
    fun start(handle: DynamicWorkerRegistry.Handle)
}

internal fun startTrackedWorker(worker: Thread, workers: MutableCollection<Thread>) {
    workers.add(worker)
    try {
        worker.start()
    } catch (failure: Throwable) {
        workers.remove(worker)
        throw failure
    }
}

internal fun isRecoverableAdaptiveCapacityFailure(failure: Throwable): Boolean =
    failure is Exception || failure is OutOfMemoryError

internal object AdaptiveWorkerStarterConstructionContext {
    private val currentStarter = ThreadLocal<AdaptiveWorkerStarter?>()

    fun current(): AdaptiveWorkerStarter? = currentStarter.get()

    fun <T> withStarter(starter: AdaptiveWorkerStarter?, construct: () -> T): T {
        currentStarter.set(starter)
        return try {
            construct()
        } finally {
            currentStarter.remove()
        }
    }
}

class DynamicWorkerRegistry {
    private data class ResizePlan(val generation: Long, val startsNeeded: Int)

    class Handle internal constructor(
        val id: Int,
        val retire: AtomicBoolean,
        private val startedAction: () -> Unit,
        private val closeAction: () -> Unit,
    ) : AutoCloseable {
        private val closed = AtomicBoolean(false)
        internal val started = AtomicBoolean(false)

        internal fun markStarted() {
            if (started.compareAndSet(false, true)) startedAction()
        }

        internal fun isClosed(): Boolean = closed.get()

        override fun close() {
            if (closed.compareAndSet(false, true)) closeAction()
        }
    }

    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private val handles = sortedMapOf<Int, Handle>()
    private val departing = HashSet<Int>()
    private var nextId = 1
    private var desired = 0
    private var sealed = false
    private var resizeGeneration = 0L

    fun register(): Handle = lock.withLock {
        check(!sealed) { "Worker registry is sealed" }
        val handle = newHandle()
        handles[handle.id] = handle
        desired += 1
        resizeGeneration += 1
        changed.signalAll()
        handle
    }

    fun resizeTo(target: Int, start: (Handle) -> Unit) =
        resizeTo(target, start, onStartFailure = { throw it })

    fun resizeTo(
        target: Int,
        start: (Handle) -> Unit,
        onStartFailure: (Throwable) -> Unit = { throw it },
    ) {
        require(target >= 0)
        val plan = try {
            prepareResize(target)
        } catch (failure: Throwable) {
            onStartFailure(failure)
            return
        }

        var remaining = plan.startsNeeded
        while (remaining > 0 && startOneIfNeeded(plan, start, onStartFailure)) {
            remaining -= 1
        }
    }

    private fun prepareResize(target: Int): ResizePlan = lock.withLock {
        if (sealed && target > desired) return ResizePlan(resizeGeneration, 0)
        desired = target
        resizeGeneration += 1

        var active = handles.values.count { !it.retire.get() && it.id !in departing }
        if (active < target) {
            for (handle in handles.values) {
                if (active == target) break
                if (handle.id in departing) continue
                if (handle.retire.compareAndSet(true, false)) active += 1
            }
        }

        val startsNeeded = maxOf(0, target - active)
        if (active > target) {
            for (handle in handles.values.toList().asReversed()) {
                if (active == target) break
                if (handle.retire.compareAndSet(false, true)) active -= 1
            }
        }
        changed.signalAll()
        ResizePlan(resizeGeneration, startsNeeded)
    }

    private fun startOneIfNeeded(
        plan: ResizePlan,
        start: (Handle) -> Unit,
        onStartFailure: (Throwable) -> Unit,
    ): Boolean {
        var handle: Handle? = null
        try {
            lock.lock()
            try {
                if (sealed || resizeGeneration != plan.generation) return false

                val allocated = newHandle()
                handle = allocated
                handles[allocated.id] = allocated
                changed.signalAll()
                start(allocated)
                return true
            } finally {
                lock.unlock()
            }
        } catch (failure: Throwable) {
            handle?.close()
            onStartFailure(failure)
            return false
        }
    }

    fun abort() {
        val toClose = lock.withLock {
            sealed = true
            desired = 0
            resizeGeneration += 1
            handles.values.toList().also { changed.signalAll() }
        }
        toClose.forEach(Handle::close)
    }

    fun awaitCount(target: Int, timeout: Long, unit: TimeUnit): Boolean {
        require(target >= 0)
        var remaining = unit.toNanos(timeout)
        lock.withLock {
            while (handles.size != target) {
                if (remaining <= 0) return false
                remaining = changed.awaitNanos(remaining)
            }
            return true
        }
    }

    fun awaitEmpty(timeout: Long, unit: TimeUnit): Boolean = awaitCount(0, timeout, unit)

    internal fun awaitEmptyAndSeal(timeout: Long, unit: TimeUnit): Boolean {
        var remaining = unit.toNanos(timeout)
        lock.withLock {
            while (handles.isNotEmpty()) {
                if (remaining <= 0) return false
                remaining = changed.awaitNanos(remaining)
            }
            sealed = true
            resizeGeneration += 1
            changed.signalAll()
            return true
        }
    }

    internal fun claimRetirement(handle: Handle): Boolean = lock.withLock {
        if (handles[handle.id] !== handle || !handle.retire.get()) return false
        departing += handle.id
        true
    }

    fun seal() {
        lock.withLock {
            sealed = true
            resizeGeneration += 1
            changed.signalAll()
        }
    }

    fun size(): Int = lock.withLock { handles.size }

    fun liveSize(): Int = lock.withLock {
        liveSizeLocked()
    }

    internal fun awaitLiveSize(target: Int) {
        require(target >= 0)
        lock.withLock {
            while (liveSizeLocked() < target) changed.await()
        }
    }

    fun desiredSize(): Int = lock.withLock { desired }

    fun isConverged(): Boolean = lock.withLock {
        handles.size == desired &&
            departing.isEmpty() &&
            handles.values.all { it.started.get() && !it.retire.get() }
    }

    private fun newHandle(): Handle {
        val id = nextId++
        return Handle(id, AtomicBoolean(false), { workerStarted(id) }) { deregister(id) }
    }

    private fun liveSizeLocked(): Int = handles.values.count { handle ->
        handle.started.get() && !handle.retire.get() && handle.id !in departing
    }

    private fun workerStarted(id: Int) {
        lock.withLock {
            if (handles.containsKey(id)) changed.signalAll()
        }
    }

    private fun deregister(id: Int) {
        lock.withLock {
            departing.remove(id)
            if (handles.remove(id) != null) changed.signalAll()
        }
    }
}
