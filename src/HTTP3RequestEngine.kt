package burp

import hp3.quic.ControlledKwikQuicTransport
import hp3.quic.QuicConfig
import http3.FirstByteTimingInputStream
import http3.GateConnection
import http3.GateMode
import http3.QpackGateLimits
import http3.SdaBatch
import http3.SdaOptions
import http3.StageDrain
import http3.TurboHttp3RequestTranslator
import java.net.URI
import java.net.URL
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * A thread for work that blocks inside Kwik: a handshake, or a response read. Virtual where the JVM
 * carries a blocked virtual thread without pinning a carrier, platform where it does not. Platform
 * threads are made daemon so a thread waiting on a response that never arrives cannot hold the JVM
 * open; virtual threads are daemon already.
 */
internal fun kwikBlockingThread(name: String): Thread.Builder =
    if (HTTP3RequestEngine.prefersVirtualThreads(Runtime.version().feature())) {
        Thread.ofVirtual().name(name)
    } else {
        Thread.ofPlatform().daemon().name(name)
    }

internal fun interface Http3AdaptiveTaskStarter {
    fun start(name: String, task: () -> Unit)
}

internal object Http3AdaptiveTaskStarterConstructionContext {
    private val currentStarter = ThreadLocal<Http3AdaptiveTaskStarter?>()

    fun current(): Http3AdaptiveTaskStarter? = currentStarter.get()

    fun <T> withStarter(starter: Http3AdaptiveTaskStarter?, construct: () -> T): T {
        currentStarter.set(starter)
        return try {
            construct()
        } finally {
            currentStarter.remove()
        }
    }
}

internal inline fun tryAcquireAdaptiveTaskSlot(
    isRunning: () -> Boolean,
    acquire: () -> Boolean,
    release: () -> Unit,
): Boolean {
    if (!isRunning() || !acquire()) return false
    if (isRunning()) return true
    release()
    return false
}

open class HTTP3RequestEngine @JvmOverloads constructor(
    url: String,
    private val threads: Int,
    maxQueueSize: Int,
    val requestsPerConnection: Int,
    override val maxRetriesPerRequest: Int,
    override var idleTimeout: Long = 0,
    override val callback: (Request, Boolean) -> Boolean,
    override var readCallback: ((String) -> Boolean)?,
    private val verifyCertificates: Boolean = false,
    private val connectionFactory: H3ConnectionFactory = defaultConnectionFactory(idleTimeout),
    private val maxConcurrentStreams: Int = DEFAULT_MAX_CONCURRENT_STREAMS,
    private val gateMode: GateMode = GateMode.AUTO,
    private val adaptive: Boolean = false,
) : RequestEngine(requiresBurpProfessional = true), AdaptiveTransport {
    private val options = SdaOptions()
    private var connectionSlots: Semaphore? = null
    private var adaptiveConnectionSlots: ResizableLimit? = null
    private var dispatchSlots: Semaphore? = null
    private var adaptiveDispatchSlots: ResizableLimit? = null
    private val batches = ConcurrentHashMap<String, SdaBatch>()
    /**
     * Membership is the exactly-once resource token for an active gate connection. The finisher
     * normally removes it after probing connectivity; cancellation removes anything whose probe
     * outlives the bounded drain and closes/releases it instead.
     */
    private val unsettledGateConnections = ConcurrentHashMap.newKeySet<GateConnection>()
    private val gateSettlementLock = Object()
    private val activeJobs = AtomicInteger()
    private val connectionSetupsInFlight = AtomicInteger()
    private val started = AtomicBoolean(false)
    private val resizeLock = Object()
    /**
     * Never guards ordinary request leases. It is the rendezvous a request parks on when the pool
     * has no lease to give, and serializes gate-return publication with cancellation's final pool
     * snapshot so a returned session cannot appear after cleanup has passed it.
     */
    private val poolLock = Object()

    /**
     * Copy-on-write so a request can walk the pool without taking anything. Writes are connections
     * opening and retiring, which happen [threads] times in a run rather than once per request.
     */
    private val ordinaryConnections = CopyOnWriteArrayList<OrdinaryConnection>()
    private val waitingGates = AtomicInteger()
    private val adaptiveTaskStarter = Http3AdaptiveTaskStarterConstructionContext.current()
        ?: Http3AdaptiveTaskStarter { name, task -> kwikBlockingThread(name).start(task) }
    private val retirementDrainScheduled = AtomicBoolean()

    /**
     * Where the next request starts looking for a lease. Requests would otherwise all walk the
     * pool from the front and pile onto the same connection's counter, turning one connection's
     * compare-and-set into the contention the monitor used to be.
     */
    private val leaseCursor = AtomicInteger()

    /**
     * Request threads parked in [acquireOrdinaryConnection], the only place that waits on
     * [poolLock]. Measured rather than assumed: at full rate threads park constantly, because the
     * pool hands out more leases than the transport can carry streams for, so wake-ups here are
     * on the critical path and must not be skipped. Read before every wake-up so that a run whose
     * pool always has room never touches the monitor at all.
     */
    private val poolWaiters = AtomicInteger()

    /** Requests the configuration asks to have in flight: one per stream on every connection. */
    private val targetConcurrency =
        (threads.toLong() * maxConcurrentStreams).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

    /**
     * Requests actually allowed in flight, which is [targetConcurrency] capped at
     * [maxRequestsInFlight]. On a JDK that still pins, each in-flight request holds an OS thread, so an unbounded
     * product would ask the OS for more threads than it will give: concurrentConnections defaults
     * to 50 in the Python API and multiplies by 100 streams, so raising it to 800 asks for 80,000.
     */
    private val useVirtualThreads = prefersVirtualThreads(Runtime.version().feature())

    private val initialRequestsInFlightLimit = dispatchCapacity(threads)

    val requestsInFlightLimit: Int
        get() = adaptiveDispatchSlots?.snapshot()?.limit ?: initialRequestsInFlightLimit

    /** Names request threads in creation order, so a stack dump is readable. */
    private val requestThreads = AtomicInteger()

    /**
     * Gates that were answered before they were released, and so raced nothing.
     *
     * A gate holds only while the server still needs what was withheld from it. One that answers
     * without reading the withheld bytes — a redirect, a static handler, a 405 — replies to the
     * whole batch before the release, and the run then reports a race as absent when it was never
     * tested. Measured across 100 hosts, the single-datagram gate did this on 21 of 94; the QPACK
     * gate, which withholds the header decode that no HTTP/3 server can skip, on none of 93.
     *
     * Counted as well as logged so a caller can act on it rather than having to read output.
     */
    val gatesThatDidNotHold = AtomicInteger()

    /**
     * The longest any one gate took from firing its release to that release returning.
     *
     * The client's own contribution to how spread the batch landed, and so the part of the result
     * that is this engine's to improve. A transport that queues a release for a thread of its own
     * can hold it for hundreds of microseconds, which would otherwise look like a perfect
     * release.
     */
    val gateReleaseSendSpanNanos = AtomicLong()

    /**
     * Carries the ungated requests, one thread per request in flight.
     *
     * Which kind of thread depends on the JVM. Kwik reads a response inside
     * `synchronized (addMonitor)` (`tech.kwik.core.stream.StreamInputStreamImpl`). Before JDK 24 a
     * virtual thread that blocks inside a synchronized block pins its carrier without the scheduler
     * compensating, so an in-flight request cost a whole carrier anyway and the run was capped at a
     * pool size only a JVM option can raise — measured on 18 cores, a run configured for 800
     * requests in flight carried 18. There, pooled platform threads are strictly better.
     *
     * JEP 491 removed that pinning in JDK 24, and Burp ships a JRE well past it, so in the case
     * that matters most the threads can be virtual: a run holding 1200 requests costs 1200 cheap
     * virtual threads instead of 1200 OS threads for the scheduler to move around.
     *
     * The platform pool is fixed rather than one thread per request because starting an OS thread
     * costs tens of microseconds and the single dispatcher pays it per request. Either way
     * [dispatchSlots] bounds submissions to [requestsInFlightLimit], so neither executor queues
     * work behind a busy thread.
     */
    private lateinit var requestExecutor: ExecutorService

    @JvmOverloads
    constructor(
        url: String,
        threads: Int,
        maxQueueSize: Int,
        requestsPerConnection: Int,
        maxRetriesPerRequest: Int,
        idleTimeout: Long,
        callback: (Request, Boolean) -> Boolean,
        readCallback: ((String) -> Boolean)?,
        verifyCertificates: Boolean,
        gateMode: String,
        adaptive: Boolean = false,
    ) : this(
        url,
        threads,
        maxQueueSize,
        requestsPerConnection,
        maxRetriesPerRequest,
        idleTimeout,
        callback,
        readCallback,
        verifyCertificates,
        defaultConnectionFactory(idleTimeout),
        DEFAULT_MAX_CONCURRENT_STREAMS,
        GateMode.fromScriptName(gateMode),
        adaptive,
    )

    init {
        try {
            require(threads > 0) { "concurrentConnections must be positive" }
            require(requestsPerConnection > 0) { "requestsPerConnection must be positive" }
            require(maxRetriesPerRequest >= 0) { "maxRetriesPerRequest must be non-negative" }
            require(maxConcurrentStreams > 0) { "maxConcurrentStreams must be positive" }
            require(readCallback == null) { "readCallback is not supported by Engine.HTTP3" }
            target = URI(url).toURL()
            require(target.protocol.equals("https", ignoreCase = true)) {
                "Engine.HTTP3 requires an https endpoint"
            }
            requestQueue = if (maxQueueSize > 0) LinkedBlockingQueue(maxQueueSize) else LinkedBlockingQueue()
            completedLatch = CountDownLatch(1)
            if (adaptive) {
                adaptiveConnectionSlots = ResizableLimit(threads)
                adaptiveDispatchSlots = ResizableLimit(initialRequestsInFlightLimit)
            } else {
                // Unfair. A fair semaphore routes every acquire through the AQS wait queue even
                // when a permit is free; neither fixed limit needs FIFO ordering to be correct.
                connectionSlots = Semaphore(threads)
                dispatchSlots = Semaphore(initialRequestsInFlightLimit)
            }
            requestExecutor = if (useVirtualThreads) {
                // Unnamed on purpose. A named virtual thread factory formats a fresh name string
                // for every request on the hot path.
                Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory())
            } else {
                // Adaptive execution is sized once for its immutable safety ceiling. Live work is
                // controlled by adaptiveDispatchSlots rather than replacing this executor.
                val executorCapacity = if (adaptive) {
                    maxRequestsInFlight(useVirtualThreads)
                } else {
                    initialRequestsInFlightLimit
                }
                Executors.newFixedThreadPool(executorCapacity) { runnable ->
                    Thread.ofPlatform()
                        .daemon()
                        .name("http3-request-${requestThreads.incrementAndGet()}")
                        .unstarted(runnable)
                }
            }
            // Started here rather than in start() so that a run cancelled before it ever started
            // still has something to count the completion latch down.
            Thread.ofPlatform().daemon().name("http3-dispatcher").start(::dispatchForever)
        } catch (failure: Throwable) {
            if (::requestExecutor.isInitialized) requestExecutor.shutdownNow()
            if (Utils.gotBurp && !Utils.unloaded) {
                Utils.callbacks.removeExtensionStateListener(this)
            }
            throw failure
        }
    }

    override fun start(timeout: Int) {
        if (started.compareAndSet(false, true)) {
            openInitialConnections(timeout)
            if (runState.get() >= 3) {
                return
            }
            // Engine.HTTP2 offers only "h2" over ALPN and lets the failed TLS handshake out of the
            // engine constructor, so a target that does not speak the protocol stops the script
            // right there. Engine.HTTP3 promises no fallback, so a run where not one QUIC
            // handshake completed has nothing left to try and stops the same way, rather than
            // working through the whole queue at one failed handshake per connection slot. The
            // tolerance in openInitialConnections is still worth keeping for a target that refuses
            // part of the opening burst, which is why this asks whether any connection opened
            // rather than whether any failed.
            if (connections.get() == 0 && connectionOpenFailures.get() > 0) {
                // Leaves the dispatcher no run to wait for. It is parked on runState being 0.
                finish(3)
                throw Exception(failureSummary())
            }
            // Stamped after the handshakes, the way ThreadedRequestEngine stamps it after its
            // connected latch. A QUIC handshake can take seconds, and charging it to the run
            // offsets every request's arrival and understates the reported RPS.
            start = System.nanoTime()
            if (requestsInFlightLimit < targetConcurrency) {
                Utils.out(
                    "HTTP/3: $threads connections x $maxConcurrentStreams streams would put " +
                        "$targetConcurrency requests in flight, and each one holds a thread. " +
                        "Capping at $requestsInFlightLimit."
                )
            }
            // The dispatcher is parked until this point, so nothing is sent over a pool that is
            // still being filled.
            runState.set(1)
            startIdleTimeoutWatchdog()
            startResponseDeadlineWatchdog()
        }
    }

    override val autoProtocol = AutoProtocol.HTTP3
    override val supportsKettledRequests = true

    override fun defaultAdaptiveLimits() = AdaptiveLimits(DEFAULT_ADAPTIVE_CONNECTIONS, null)

    override fun currentAdaptiveLimits() = AdaptiveLimits(
        adaptiveConnectionSlots?.snapshot()?.limit ?: threads,
        null,
    )

    override fun adaptiveMetrics(): AdaptiveMetrics {
        val limits = currentAdaptiveLimits()
        val saturated = requestQueue.isNotEmpty() ||
            poolWaiters.get() > 0 ||
            activeRequests.get() >= requestsInFlightLimit
        return baseAdaptiveMetrics(limits, saturated).copy(
            safeToMeasure = adaptiveCapacityConverged(limits.concurrency, saturated),
        )
    }

    private fun adaptiveCapacityConverged(desiredConnections: Int, saturated: Boolean): Boolean {
        if (!adaptive) return true
        if (connectionSetupsInFlight.get() != 0 || waitingGates.get() != 0) return false
        val connectionLimit = requireNotNull(adaptiveConnectionSlots).snapshot()
        val dispatchLimit = requireNotNull(adaptiveDispatchSlots).snapshot()
        if (connectionLimit.limit != desiredConnections || connectionLimit.acquired > connectionLimit.limit) return false
        if (dispatchLimit.limit != dispatchCapacity(desiredConnections) || dispatchLimit.acquired > dispatchLimit.limit) return false
        val connections = ordinaryConnectionSnapshot()
        if (connections.any { it.retired }) return false
        if (connections.size > desiredConnections) return false
        return !saturated || connections.size >= desiredConnections
    }

    override fun resizeConcurrency(newLimit: Int) {
        require(adaptive) { "Live resize is available only to adaptive HTTP3 engines" }
        require(newLimit > 0) { "Adaptive concurrentConnections must be positive" }
        synchronized(resizeLock) {
            val connectionLimit = requireNotNull(adaptiveConnectionSlots)
            val dispatchLimit = requireNotNull(adaptiveDispatchSlots)
            val previous = connectionLimit.snapshot().limit
            connectionLimit.resize(newLimit)
            dispatchLimit.resize(dispatchCapacity(newLimit))
            if (newLimit > previous) {
                replenishAdaptiveConnections()
            } else if (newLimit < previous) {
                retireExcessOrdinaryConnections()
            }
        }
        wakeAllPoolWaiters()
    }

    /**
     * Fills a live adaptive pool independently of request dispatch. This runs while [resizeLock]
     * is held, so every worker owns a slot before another resize can plan the same capacity.
     */
    private fun replenishAdaptiveConnections() {
        val connectionLimit = requireNotNull(adaptiveConnectionSlots).snapshot()
        val startBudget = (connectionLimit.limit - connectionLimit.acquired).coerceAtLeast(0)
        repeat(startBudget) {
            if (!tryAcquireAdaptiveTaskSlot(
                isRunning = { runState.get() in 1..2 },
                acquire = ::tryAcquireConnectionSlot,
                release = ::releaseConnectionSlot,
            )) return
            try {
                adaptiveTaskStarter.start("http3-connect-live", ::openReservedAdaptiveConnection)
            } catch (exception: Throwable) {
                releaseConnectionSlot()
                recordConnectionOpenFailure(exception)
                recordTransportFailure(exception)
                wakeAllPoolWaiters()
                return
            }
        }
    }

    /** Opens one ordinary connection against a slot reserved by [replenishAdaptiveConnections]. */
    private fun openReservedAdaptiveConnection() {
        var session: H3Session? = null
        var handedOffSlot = false
        try {
            if (runState.get() >= 3) return
            session = openConnection()
            synchronized(poolLock) {
                if (runState.get() < 3) {
                    val id = connections.incrementAndGet().toString()
                    ordinaryConnections.add(OrdinaryConnection(session, id))
                    handedOffSlot = true
                }
            }
            if (handedOffSlot) {
                retireExcessOrdinaryConnections()
            }
        } catch (exception: Throwable) {
            recordConnectionOpenFailure(exception)
            recordTransportFailure(exception)
        } finally {
            if (!handedOffSlot) {
                session?.let { opened -> runCatching { opened.close() } }
                releaseConnectionSlot()
            }
            wakeAllPoolWaiters()
        }
    }

    override fun resizeRequestsPerConnection(newLimit: Int): Boolean {
        require(adaptive) { "Live request lifetime is available only to adaptive HTTP3 engines" }
        return false
    }

    private fun dispatchCapacity(connections: Int): Int =
        (connections.toLong() * maxConcurrentStreams)
            .coerceAtMost(maxRequestsInFlight(useVirtualThreads).toLong())
            .toInt()

    private fun tryAcquireConnectionSlot(): Boolean =
        adaptiveConnectionSlots?.tryAcquire() ?: requireNotNull(connectionSlots).tryAcquire()

    private fun tryAcquireConnectionSlot(timeout: Long, unit: TimeUnit): Boolean =
        adaptiveConnectionSlots?.tryAcquire(timeout, unit) { runState.get() >= 3 }
            ?: requireNotNull(connectionSlots).tryAcquire(timeout, unit)

    private fun releaseConnectionSlot() {
        adaptiveConnectionSlots?.release() ?: requireNotNull(connectionSlots).release()
    }

    private fun tryAcquireDispatchSlot(): Boolean =
        adaptiveDispatchSlots?.tryAcquire() ?: requireNotNull(dispatchSlots).tryAcquire()

    private fun tryAcquireDispatchSlot(timeout: Long, unit: TimeUnit): Boolean =
        adaptiveDispatchSlots?.tryAcquire(timeout, unit) { runState.get() >= 3 }
            ?: requireNotNull(dispatchSlots).tryAcquire(timeout, unit)

    private fun releaseDispatchSlot() {
        adaptiveDispatchSlots?.release() ?: requireNotNull(dispatchSlots).release()
    }

    private fun retireExcessOrdinaryConnections() {
        if (!adaptive) return
        synchronized(resizeLock) {
            if (waitingGates.get() != 0) return
            val desired = requireNotNull(adaptiveConnectionSlots).snapshot().limit
            var remaining = (
                ordinaryConnections.count { !it.retired } - desired
            ).coerceAtLeast(0)
            if (remaining == 0) return

            var hasIdleRetirement = false
            // Retire idle capacity first so shrink convergence does not wait for live requests. The
            // copy-on-write iterator already owns a stable backing array; no filter/sort copies are
            // needed, and one bulk drain removes every idle retiree with one pool-array rewrite.
            for (connection in ordinaryConnections) {
                if (remaining == 0) break
                if (connection.inFlight != 0 || !connection.markRetiring()) continue
                remaining -= 1
                hasIdleRetirement = true
            }
            if (remaining > 0) {
                for (connection in ordinaryConnections) {
                    if (remaining == 0) break
                    if (!connection.markRetiring()) continue
                    remaining -= 1
                    if (connection.inFlight == 0) hasIdleRetirement = true
                }
            }
            if (hasIdleRetirement) scheduleRetirementDrain()
        }
    }

    private fun scheduleRetirementDrain() {
        if (!retirementDrainScheduled.compareAndSet(false, true)) return
        try {
            adaptiveTaskStarter.start("http3-retire-drain", ::drainRetiredOrdinaryConnections)
        } catch (failure: Throwable) {
            // Retirement is already irreversible. If the JVM cannot schedule the bounded drain,
            // finish it here so no retired session or connection slot is stranded.
            retirementDrainScheduled.set(false)
            drainRetiredOrdinaryConnectionsSynchronously()
            if (!isRecoverableAdaptiveCapacityFailure(failure)) throw failure
        }
    }

    private fun drainRetiredOrdinaryConnections() {
        var completed = false
        try {
            val removed = ArrayList<OrdinaryConnection>()
            ordinaryConnections.removeIf { connection ->
                (connection.retired && connection.inFlight == 0).also { ready ->
                    if (ready) removed += connection
                }
            }
            removed.forEach(::finishRemovedOrdinaryConnection)
            completed = true
        } catch (failure: Throwable) {
            drainRetiredOrdinaryConnectionsSynchronously()
            throw failure
        } finally {
            retirementDrainScheduled.set(false)
            if (completed && ordinaryConnections.any { it.retired && it.inFlight == 0 }) {
                scheduleRetirementDrain()
            }
        }
    }

    private fun drainRetiredOrdinaryConnectionsSynchronously() {
        while (true) {
            val connection = ordinaryConnections.firstOrNull {
                it.retired && it.inFlight == 0
            } ?: return
            retireOrdinaryConnection(connection, forceClose = false)
        }
    }

    private fun finishRemovedOrdinaryConnection(connection: OrdinaryConnection) {
        if (connection.claimClose()) runCatching { connection.session.close() }
        if (connection.claimSlot()) {
            releaseConnectionSlot()
            retiredConnections.incrementAndGet()
        }
        wakePoolWaiter()
    }

    private fun wakeAllPoolWaiters() {
        synchronized(poolLock) {
            poolLock.notifyAll()
        }
    }

    /**
     * Cancels a run whose responses have stopped arriving. This cannot live on the dispatcher
     * thread: shouldAbandonRun() cancels by blocking on the completion latch, and the dispatcher
     * is the thread that counts it down.
     */
    private fun startIdleTimeoutWatchdog() {
        if (idleTimeout <= 0) {
            return
        }
        Thread.ofVirtual().name("http3-idle-watchdog").start {
            while (runState.get() in 1..2) {
                if (shouldAbandonRun()) {
                    return@start
                }
                Thread.sleep(IDLE_POLL_MILLIS)
            }
        }
    }

    /**
     * Fails response reads that have waited past their deadline, across ordinary connections and
     * connections held exclusively by an active gate.
     *
     * <p>A response that never arrives leaves its reader parked inside Kwik, whose own per-read
     * bound is Long.MAX_VALUE with no setter to lower it. The engine counts that reader as work in
     * progress, so the run never completes, and because its clock goes on running against a
     * request count that has stopped, the rate it reports decays for as long as it is left open.
     *
     * <p>One sweeper for the whole pool rather than a timer per request: this is the path every
     * request takes, and at full rate arming and cancelling a scheduled task each would put all of
     * them through the single lock inside a scheduler's delay queue.
     */
    private fun startResponseDeadlineWatchdog() {
        // A platform thread, for the same reason the dispatcher is one. Measured against a live
        // target: as a virtual thread this slept once and was never scheduled again, because a
        // saturated run has 12,288 request threads competing for the carriers of an eight-core
        // box. A supervisor starved by the work it supervises never fails the reads it exists to
        // fail, and the run wedges exactly as it did without it.
        Thread.ofPlatform().daemon().name("http3-response-watchdog").start {
            while (runState.get() in 1..2) {
                val now = System.nanoTime()
                val ordinarySessions = ordinaryConnectionSnapshot().map { it.session }
                val gateSessions = batches.values.mapNotNull { it.connection?.session }
                (ordinarySessions + gateSessions).distinct().forEach { session ->
                    // A connection torn down between the snapshot and this is not a reason to
                    // stop sweeping the rest of the pool.
                    runCatching { session.failOverdueReads(now) }
                }
                Thread.sleep(RESPONSE_SWEEP_MILLIS)
            }
        }
    }

    /**
     * Opens the run's connections up front, the way the other engines do, rather than letting the
     * dispatcher open them on demand. Two reasons. A QUIC handshake can be slow — on a path where a
     * middlebox drops Initial packets it takes seconds — and opening one inside the dispatcher
     * stalls every other request behind it. And a gate that inherits a connection the run has
     * already used starts with a warm congestion window, where a freshly opened one does not.
     */
    private fun openInitialConnections(timeout: Int) {
        val desiredConnections = adaptiveConnectionSlots?.snapshot()?.limit ?: threads
        val ready = CountDownLatch(desiredConnections)
        repeat(desiredConnections) { index ->
            // A QUIC handshake blocks inside Kwik just as a response read does, so it needs the
            // same thread choice: on a JDK that still pins, a pool larger than the carrier count
            // would open in batches instead of at once.
            kwikBlockingThread("http3-connect-$index").start {
                var reservedSlot = false
                try {
                    if (runState.get() < 3 && tryAcquireConnectionSlot()) {
                        reservedSlot = true
                        val session = openConnection()
                        if (runState.get() >= 3) {
                            runCatching { session.close() }
                        } else {
                            val id = connections.incrementAndGet().toString()
                            reservedSlot = false
                            ordinaryConnections.add(OrdinaryConnection(session, id))
                            retireExcessOrdinaryConnections()
                            wakeAllPoolWaiters()
                        }
                    }
                } catch (exception: Throwable) {
                    // A connection that will not open is not fatal on its own: the dispatcher can
                    // still open one on demand. It is still reportable straight away, which is why
                    // it is counted rather than only remembered.
                    recordConnectionOpenFailure(exception)
                    if (adaptive) recordTransportFailure(exception)
                } finally {
                    if (reservedSlot) {
                        releaseConnectionSlot()
                    }
                    ready.countDown()
                }
            }
        }
        // ScriptEnvironment starts the engine with a 5 second timeout, which is shorter than a
        // QUIC handshake on any path that drops Initial packets. Giving up before the transport
        // itself would guarantees an empty pool at the moment the dispatcher starts, which is the
        // opposite of establishing connections up front.
        val waitSeconds = maxOf(timeout.toLong(), HANDSHAKE_WAIT_SECONDS)
        if (!ready.await(waitSeconds, TimeUnit.SECONDS)) {
            Utils.out(
                "HTTP/3: only ${desiredConnections - ready.count.toInt()} of $desiredConnections connections opened " +
                    "within ${waitSeconds}s; the rest will be opened on demand"
            )
        }
    }

    /**
     * What the run looks like right now, including the gate integrity counters that report a gate
     * which did not hold. Declared here rather than on [RequestEngine] because no other engine
     * reports anything like it, and the shared class should not carry a hook with one caller.
     */
    fun runtimeMetrics(): Map<String, Any?> = linkedMapOf(
        "run_state" to runState.get(),
        "queue_size" to requestQueue.size,
        "successful_requests" to successfulRequests.get(),
        "failed_requests" to permaFails.get(),
        "connections" to connections.get(),
        "retries" to retries.get(),
        "gates_that_did_not_hold" to gatesThatDidNotHold.get(),
        "gate_release_send_span_ns" to gateReleaseSendSpanNanos.get(),
    )

    override fun buildRequest(
        template: String,
        payloads: List<String?>,
        learnBoring: Int?,
        label: String,
    ): Request = Request(template, payloads, learnBoring ?: 0, label)

    override fun openGate(gateName: String) {
        super.openGate(gateName)
        val batch = batches[gateName] ?: throw IllegalStateException("No HTTP/3 batch exists for gate $gateName")
        try {
            batch.throwIfFailed()
            batch.awaitStagedRequestsSent(
                StageDrain(options.stageWaitCapMillis, options.stageFallbackMillis),
            )
            batch.markReleased()
            val exchanges = batch.stagedExchanges()
            val releasedBy = batch.mode.name.lowercase()
            val release = batch.release(options)
                ?: throw IllegalStateException("Gate $gateName has no QUIC connection to release")
            // The instant the batch actually left, not the instant it entered Kwik's sender
            // queue. Pacing can hold a queued packet while a server answers the staged prefix;
            // timing from that enqueue would hide the response that proved this gate did not hold.
            val releaseCallStarted = System.nanoTime()
            val releaseStarted = adaptiveTransportAttempt { release.send() }
            gateReleaseSendSpanNanos.updateAndGet { widest ->
                maxOf(widest, System.nanoTime() - releaseCallStarted)
            }
            exchanges.forEach { staged ->
                staged.request.sent = releaseStarted
                staged.request.gateMode = releasedBy
                staged.exchange.startResponseDeadline(releaseStarted)
            }
            // Blocks in Kwik like the readers it collects from, so it takes the same thread kind.
            kwikBlockingThread("http3-gate-$gateName").start {
                try {
                    // Recorded first, called back second. req.order is the rank of a response by
                    // arrival — 0 is the request the server answered first, which is the race
                    // outcome — and this loop reaches the exchanges in the order they were staged,
                    // which says nothing about the order they came back in. So the whole batch has
                    // to be in hand before a rank can be given to any of it, which also means a
                    // gate's callbacks fire together at the end rather than one at a time. That is
                    // what BurpRequestEngine already does with a gated batch, and a race cannot be
                    // acted on before it has resolved anyway.
                    val answered = ArrayList<Pair<Request, Boolean>>(exchanges.size)
                    exchanges.forEach { staged ->
                        val exchange = try {
                            staged.exchange.awaitResponse()
                        } catch (exception: Throwable) {
                            if (adaptive) recordTransportFailure(exception)
                            recordPermanentFailure(exception)
                            if (adaptive) activeRequests.decrementAndGet()
                            return@forEach
                        }
                        val interesting = try {
                            recordResponse(
                                staged.request,
                                exchange,
                                releaseStarted,
                                staged.connection.connectionId,
                            )
                        } catch (exception: Throwable) {
                            recordResponseProcessingFailure(exception)
                            if (adaptive) activeRequests.decrementAndGet()
                            return@forEach
                        }
                        answered.add(staged.request to interesting)
                    }
                    answered.sortBy { it.first.ttfb }
                    reportIfGateDidNotHold(gateName, answered.map { it.first })
                    answered.forEachIndexed { rank, (request, interesting) ->
                        request.order = rank
                        try {
                            invokeCallback(request, interesting)
                        } finally {
                            if (adaptive) activeRequests.decrementAndGet()
                        }
                    }
                } finally {
                    finishBatch(gateName, batch)
                }
            }
        } catch (exception: Throwable) {
            batch.fail(exception)
            abandonStagedExchanges(batch, exception)
            if (adaptive) activeRequests.addAndGet(-batch.stagedExchanges().size)
            finishBatch(gateName, batch)
            throw exception
        }
    }

    /**
     * Says so when a batch was answered before it was released, because the alternative is a run
     * that looks like a clean negative and tested nothing.
     *
     * A negative ttfb is unambiguous: it is measured from the release, so below zero means the
     * response was already on its way back. Exactly zero is left alone — that is a same-microsecond
     * arrival, which is suspicious but not evidence.
     */
    private fun reportIfGateDidNotHold(gateName: String, requests: List<Request>) {
        val early = requests.count { it.ttfb < 0 }
        if (early == 0) {
            return
        }
        gatesThatDidNotHold.incrementAndGet()
        Utils.out(
            "HTTP/3 gate $gateName did not hold: $early of ${requests.size} responses arrived " +
                "before the release, so the batch was never synchronised and a negative result " +
                "proves nothing. This server answers without reading the withheld bytes; try " +
                "gateMode='qpack', or a request with no body so the gate withholds header bytes " +
                "instead."
        )
    }

    /**
     * Counts every request that was staged but will never be released. Without this the requests
     * simply disappear: their responses are never awaited, so neither successfulRequests nor
     * permaFails ever accounts for them.
     */
    private fun abandonStagedExchanges(batch: SdaBatch, cause: Throwable) {
        batch.stagedExchanges().forEach { _ -> recordPermanentFailure(cause) }
    }

    private fun dispatchForever() {
        try {
            while (runState.get() == 0) {
                Thread.sleep(RUN_START_POLL_MILLIS)
            }
            while (runState.get() < 3) {
                val request = pollNextRequest()
                if (request != null) {
                    if (request.gate == null) {
                        dispatchOrdinary(request)
                    } else {
                        stageGated(request)
                    }
                    continue
                }
                if (runState.get() == 2 && activeJobs.get() == 0 && requestQueue.isEmpty()) {
                    return
                }
            }
        } finally {
            batches.entries.toList().forEach { (gateName, batch) ->
                finishBatch(gateName, batch)
            }
            // Gate returns publish under the same monitor. Either a return wins and appears in
            // this snapshot, or cancellation wins and the return sees runState >= 3 and closes.
            val pooledAtCancellation = synchronized(poolLock) { ordinaryConnectionSnapshot() }
            pooledAtCancellation.forEach { connection ->
                retireOrdinaryConnection(connection, forceClose = true)
            }
            awaitRequestsInFlight()
            forceCloseUnsettledGateConnections()
            // Safe after the drain above: dispatchSlots caps submissions at the pool size, so
            // every task that was handed to the executor already has a thread and none are sitting
            // in its queue waiting for one that shutdown would take away. Anything the drain gave
            // up on is interrupted here, which is what finally releases a parked reader.
            requestExecutor.shutdownNow()
            completedLatch.countDown()
        }
    }

    /**
     * Waits for the requests still in flight to finish, and gives up on them rather than waiting
     * for ever.
     *
     * <p>A response that never arrives leaves its reader parked inside Kwik, and closing the
     * connection does not reliably release it. The deadline watchdog cannot help either: it stops
     * the moment the run leaves state 1..2, which a cancelled run does before this drain begins.
     * So an unbounded wait here spins for the life of the JVM on a thread that is a GC root for
     * the whole engine - its queue, its connection pool, and every request those still reach.
     * Measured in Burp, seven of these accumulated over one session and runs that began at 11.5s
     * were taking 22-40s by the end of it.
     *
     * <p>Whatever is still running when the deadline passes is left to [requestExecutor]'s
     * shutdownNow(), which interrupts it.
     */
    private fun awaitRequestsInFlight() {
        val deadline = System.nanoTime() + DRAIN_WAIT_NANOS
        while (activeJobs.get() > 0 && System.nanoTime() - deadline < 0) {
            Thread.sleep(DRAIN_POLL_MILLIS)
        }
    }

    private fun pollNextRequest(): Request? {
        // Only walk the queue looking for a gated request when the run actually has a gate.
        // LinkedBlockingQueue's iterator takes both queue locks once per element, so an
        // unconditional scan costs O(queue depth) per dispatch, and a non-streaming run gets an
        // unbounded queue. Measured on a 50k-deep queue that is 273us per request, which caps the
        // engine at under 4k rps before a single packet is sent.
        if (gatesInUse()) {
            val gated = requestQueue.firstOrNull { it.gate != null }
            if (gated != null && requestQueue.remove(gated)) {
                return gated
            }
        }
        // Untimed poll first. The dispatcher runs this once per request, and a timed poll arms a
        // timeout even when the queue already has work, which at full rate is pure overhead on the
        // one thread every request passes through.
        return requestQueue.poll() ?: requestQueue.poll(QUEUE_POLL_MILLIS, TimeUnit.MILLISECONDS)
    }

    /**
     * Whether any gated request has been queued. Gates are registered in [floodgates] by
     * RequestEngine.queue() before the request reaches the queue, so a gated request can never
     * become visible here without its gate being visible first, and the map is only cleared once
     * the run is torn down. Read without the monitor on purpose: openGate() holds that monitor
     * while it waits for this very thread to finish staging.
     */
    private fun gatesInUse(): Boolean = floodgates.isNotEmpty()

    private fun dispatchOrdinary(request: Request) {
        // Taken on the dispatcher thread, before the request gets a thread of its own, so that a
        // backlog waits in the bounded queue rather than as an unbounded pile of request threads
        // all polling poolLock for the same connection. Without this, concurrentConnections capped
        // the pool but not the dispatch rate: every queued request got a thread immediately, and
        // once the pool was saturated their 50ms poll loops spent the run contending on one
        // monitor instead of sending. ThreadedRequestEngine bounds the same way, by owning exactly
        // `threads` workers and having them pull from the queue themselves.
        if (!acquireDispatchSlot()) {
            return
        }
        activeJobs.incrementAndGet()
        if (adaptive) activeRequests.incrementAndGet()
        requestExecutor.execute {
            try {
                validateRequestOptions(request)
                val translated = translate(request)
                var attempt = 0
                while (runState.get() < 3) {
                    var connection: OrdinaryConnection? = null
                    try {
                        connection = acquireOrdinaryConnection()
                        // Stamped once the connection is in hand. A connection carries one request
                        // at a time, so a request can wait for a free one, and charging that wait
                        // to the response would overstate every latency the run reports.
                        val startedAt = System.nanoTime()
                        request.sent = startedAt
                        val response = connection.session.send(translated)
                        val connectionId = connection.id
                        releaseOrdinaryConnection(connection, failed = false)
                        connection = null
                        try {
                            completeResponse(request, response, startedAt, connectionId)
                        } catch (exception: Throwable) {
                            recordResponseProcessingFailure(exception)
                        }
                        return@execute
                    } catch (exception: Throwable) {
                        connection?.let { releaseOrdinaryConnection(it, failed = true) }
                        if (adaptive && runState.get() < 3) recordTransportFailure(exception)
                        if (runState.get() < 3 && attempt < maxRetriesPerRequest) {
                            attempt += 1
                            retries.incrementAndGet()
                            continue
                        }
                        recordPermanentFailure(exception)
                        return@execute
                    }
                }
            } catch (exception: Throwable) {
                recordPermanentFailure(exception)
            } finally {
                if (adaptive) activeRequests.decrementAndGet()
                activeJobs.decrementAndGet()
                releaseDispatchSlot()
                wakePoolWaiter()
            }
        }
    }

    /**
     * Waits for a dispatch slot, giving up if the run is cancelled while waiting. Polled rather
     * than blocked on outright so that a cancelled run does not leave the dispatcher parked on a
     * semaphore nothing will ever release.
     */
    private fun acquireDispatchSlot(): Boolean {
        // Same reasoning as the queue poll: when the pool has capacity, which is the common case
        // while a run is ramping, the untimed acquire avoids arming a timer per request.
        if (tryAcquireDispatchSlot()) {
            return true
        }
        while (runState.get() < 3) {
            if (tryAcquireDispatchSlot(DISPATCH_POLL_MILLIS, TimeUnit.MILLISECONDS)) {
                return true
            }
        }
        return false
    }

    /**
     * Walks the pool for a connection with room, taking nothing. Each request starts one place
     * further along than the last, so requests spread across the pool instead of queueing on
     * whichever connection happens to be first.
     */
    private fun leaseFromPool(): OrdinaryConnection? {
        if (waitingGates.get() != 0) {
            return null
        }
        val pool = ordinaryConnections
        val size = pool.size
        if (size == 0) {
            return null
        }
        val from = Math.floorMod(leaseCursor.getAndIncrement(), size)
        for (offset in 0 until size) {
            // The pool can shrink underneath this walk, and a copy-on-write list throws rather
            // than returning null for an index that was valid when the size was read.
            val connection = pool.getOrNull((from + offset) % size) ?: continue
            if (connection.tryLease(requestsPerConnection, maxConcurrentStreams)) {
                // A pooled connection can reach its idle timeout while it waits for a request,
                // exactly as it can while it waits for a gate. A retry covers this wherever the
                // run allows one, but it costs a round trip to learn what the connection could
                // have been asked, and a run with retries turned off fails the request instead.
                if (!isStillConnected(connection)) {
                    releaseOrdinaryConnection(connection, failed = true)
                    continue
                }
                return connection
            }
        }
        return null
    }

    private fun acquireOrdinaryConnection(): OrdinaryConnection {
        while (runState.get() < 3) {
            leaseFromPool()?.let { return it }

            var reservedSlot = false
            synchronized(poolLock) {
                if (waitingGates.get() == 0) {
                    // Between the lock-free walk above and this monitor a request may well have
                    // finished, so look once more before deciding the pool is full and either
                    // opening a connection or parking.
                    leaseFromPool()?.let { return it }
                    reservedSlot = tryAcquireConnectionSlot()
                }
                if (!reservedSlot) {
                    poolWaiters.incrementAndGet()
                    try {
                        poolLock.wait(POOL_WAIT_MILLIS)
                    } finally {
                        poolWaiters.decrementAndGet()
                    }
                }
            }

            if (reservedSlot) {
                try {
                    val session = try {
                        openConnection()
                    } catch (exception: Throwable) {
                        recordConnectionOpenFailure(exception)
                        throw exception
                    }
                    val id = connections.incrementAndGet().toString()
                    if (runState.get() >= 3) {
                        session.close()
                        throw IllegalStateException("HTTP/3 run was cancelled while opening a connection")
                    }
                    return OrdinaryConnection(session, id).also { connection ->
                        connection.tryLease(requestsPerConnection, maxConcurrentStreams)
                        ordinaryConnections.add(connection)
                        retireExcessOrdinaryConnections()
                        wakeAllPoolWaiters()
                    }
                } catch (exception: Throwable) {
                    releaseConnectionSlot()
                    wakeAllPoolWaiters()
                    throw exception
                }
            }
        }
        throw IllegalStateException("HTTP/3 run is no longer accepting requests")
    }

    private fun releaseOrdinaryConnection(connection: OrdinaryConnection, failed: Boolean) {
        val alive = isStillConnected(connection)
        val cancelled = runState.get() >= 3
        // A failed request retires the connection. That looks wasteful - a stream error says
        // nothing about the other streams, and the pool pays a handshake to replace something
        // isConnected() still calls up - but it was measured both ways and retiring wins by a
        // wide margin: keeping the connection gave 26,175 and 47,784 rps on 500,000 requests
        // where retiring gave 78,320-85,260. isConnected() is a poor health signal, and a
        // connection that just lost a request is usually about to lose more, so retiring is
        // really load shedding away from a sick connection.
        //
        // What is not justified is closing it under the requests already on it, which took up
        // to maxConcurrentStreams - 1 live requests down per failure. Those close on the drain
        // in retireOrdinaryConnection instead, when the last lease comes back.
        val drop = failed || !alive || cancelled
        val shouldRetire = connection.releaseLease(retiring = drop)
        wakePoolWaiter()
        if (shouldRetire) {
            retireOrdinaryConnection(connection, forceClose = cancelled || !alive)
        }
    }

    /**
     * Wakes a request parked for a lease, and only then takes the monitor. A run whose pool has
     * room never parks anything, so the common case is one volatile read rather than a monitor
     * every request has to queue for.
     */
    private fun wakePoolWaiter() {
        if (poolWaiters.get() == 0) {
            return
        }
        synchronized(poolLock) {
            poolLock.notifyAll()
        }
    }

    /** Whether the session is usable, without allocating a Result on a path taken per request. */
    private fun isStillConnected(connection: OrdinaryConnection): Boolean =
        try {
            connection.session.isConnected()
        } catch (ignored: Throwable) {
            false
        }

    private fun retireOrdinaryConnection(connection: OrdinaryConnection, forceClose: Boolean) {
        // A delayed shrink runnable can arrive after a gate has claimed this object. It no longer
        // owns either the session or its slot and therefore has nothing it is allowed to close.
        if (!connection.retire()) return
        var closeSession = forceClose && connection.claimClose()
        var releaseSlot = false
        // A connection still carrying requests stays in the pool until the last of them gives its
        // lease back; whichever release takes it to zero is the one that takes it out.
        if (connection.inFlight == 0) {
            ordinaryConnections.remove(connection)
            closeSession = closeSession || connection.claimClose()
            releaseSlot = connection.claimSlot()
        }
        wakePoolWaiter()

        if (closeSession) {
            runCatching { connection.session.close() }
        }
        if (releaseSlot) {
            releaseConnectionSlot()
            if (adaptive) retiredConnections.incrementAndGet()
            wakePoolWaiter()
        }
    }

    private fun stageGated(request: Request) {
        val gate = request.gate ?: return
        var batch: SdaBatch? = null
        if (adaptive) activeRequests.incrementAndGet()
        try {
            batch = batches[gate.name] ?: openBatch(gate.name).also { batches[gate.name] = it }
            batch.throwIfFailed()
            validateRequestOptions(request)
            // The connection this gate claimed. Every bound a stage is charged against belongs
            // to it, so the batch is bounded by that one connection and nothing else.
            val connection = batch.requireConnection()
            val session = connection.session!!
            val translated = translate(request)
            val exchange = if (batch.mode == GateMode.QPACK) {
                // Reserved before the request is written, not counted after: by then the stream
                // exists and the peer's blocked-stream allowance has already been overrun.
                connection.reserveBlockedStream()
                adaptiveTransportAttempt { session.stageBlocked(translated) }
            } else {
                // Reserved after the stage rather than before it, because what a request costs the
                // release is its stream frame, and the stream ID and offset that size it are only
                // settled once the stream exists. Charging it here still stops the rest of the
                // batch reaching a target that will never see a release.
                adaptiveTransportAttempt { session.stage(translated, options.finalBytes) }
                    .also { connection.reserveReleaseBytes(it.fragment) }
            }
            batch.add(request, exchange)
        } catch (exception: Throwable) {
            batch?.fail(exception)
            lastError = exception.toString()
            permaFails.incrementAndGet()
            if (adaptive) activeRequests.decrementAndGet()
        } finally {
            gate.reportReadyWithoutWaiting()
        }
    }

    /**
     * Opens a gate's exclusive connection, deliberately outside any lock on the batches map. The
     * open blocks on a connection slot that finishBatch releases, and finishBatch has to reach the
     * same map to do it — holding the map across the open deadlocks the two against each other.
     * Only the dispatcher thread creates batches, so a get-then-put needs no atomicity beyond that.
     */
    private fun openBatch(gateName: String): SdaBatch {
        var connection: GateConnection? = null
        var lease: GateLease? = null
        var jobStarted = false
        return try {
            lease = acquireGateConnection()
            activeJobs.incrementAndGet()
            jobStarted = true
            val gate = resolveGate(lease.session, gateName)
            connection = GateConnection(
                gateName,
                lease.session,
                lease.id,
                gate.mode,
                gate.qpackLimits,
                lease.requestsCarried,
                gate.releaseBudgetBytes,
            )
            check(unsettledGateConnections.add(connection)) {
                "Gate $gateName registered the same connection twice"
            }
            SdaBatch(gateName, connection)
        } catch (exception: Throwable) {
            if (connection == null && lease != null) {
                try {
                    returnGateLeaseAfterSetupFailure(lease)
                } finally {
                    if (jobStarted) activeJobs.decrementAndGet()
                }
            }
            // Carrying the connection if it claimed one, so finishBatch hands it back rather than
            // leaking the slot a half-opened gate was holding.
            SdaBatch(gateName, connection).also { it.fail(exception) }
        }
    }

    private fun returnGateLeaseAfterSetupFailure(lease: GateLease) {
        val connected = lease.requestsCarried < requestsPerConnection &&
            runCatching { lease.session.isConnected() }.getOrDefault(false)
        val reusable = synchronized(poolLock) {
            if (connected && runState.get() < 3) {
                ordinaryConnections.add(OrdinaryConnection(lease.session, lease.id, lease.requestsCarried))
                true
            } else {
                false
            }
        }
        if (reusable) {
            retireExcessOrdinaryConnections()
        } else {
            runCatching { lease.session.close() }
            releaseConnectionSlot()
            if (adaptive) retiredConnections.incrementAndGet()
        }
        wakeAllPoolWaiters()
    }

    /**
     * How a gate will release, together with everything that decision was made from. A QPACK gate
     * has to carry the peer's exact limits away with it, because they bound what it may stage.
     */
    private data class ResolvedGate(
        val mode: GateMode,
        val qpackLimits: QpackGateLimits? = null,
        /**
         * What one release datagram carries on this gate's connection. Only a datagram gate is
         * bounded by it, so a QPACK gate leaves it unbounded.
         */
        val releaseBudgetBytes: Int = Int.MAX_VALUE,
    )

    /**
     * Settles how this gate will release, before a single request is staged.
     *
     * <p>It cannot be settled any later: the two modes put different bytes on the wire, so by the
     * time the batch is staged it is already committed to one of them.
     *
     * <p>A peer's SETTINGS arrive on a control stream it opens after the handshake, so a gate that
     * has just opened a connection may reach here before they land. Waiting is nearly always free
     * because a gate normally inherits a warm pooled connection whose SETTINGS arrived long ago.
     */
    private fun resolveGate(session: H3Session, gateName: String): ResolvedGate {
        if (gateMode == GateMode.SDA) {
            return ResolvedGate(GateMode.SDA, releaseBudgetBytes = releaseBudget(session))
        }
        if (gateMode == GateMode.QPACK) {
            val limits = session.awaitQpackGateLimits(SETTINGS_WAIT_MILLIS)
                ?: throw IllegalStateException(
                    "Gate $gateName asked for the QPACK blocked-stream gate, but this server did " +
                        "not advertise both QPACK_MAX_TABLE_CAPACITY and QPACK_BLOCKED_STREAMS, " +
                        "so a blocked field section would be a connection error rather than " +
                        "something it waits on. Use gateMode='auto' to fall back to the " +
                        "single-datagram gate.",
                )
            return ResolvedGate(GateMode.QPACK, limits)
        }
        // Auto prefers the QPACK gate wherever the peer allows it, because it is the only one
        // that cannot quietly fail to gate.
        //
        // The datagram gate holds only if the server actually reads the bytes it withheld. A
        // server that answers without reading the body — a redirect, a static handler, a 405 —
        // leaves the whole batch answered before the release, and the run reports a race as absent
        // when it was never tested. Measured across 100 hosts with a body: the datagram gate held
        // 243 of 294 runs and failed on every run against 16 of them, while the QPACK gate held
        // 291 of 291. The QPACK gate withholds the header decode, which no HTTP/3 server can skip.
        //
        // Nothing is traded for that. Across the 80 hosts where both gates held every run the two
        // were indistinguishable on how tightly responses clustered: 44 of 80 hosts and 127 of 240
        // paired rounds to the datagram gate, p around 0.4 either way. An earlier reading of eight
        // hosts had the datagram gate ahead and this preference reversed; it did not replicate.
        //
        // The QPACK gate's ceiling is also the peer's own SETTINGS_QPACK_BLOCKED_STREAMS rather
        // than a datagram, which is a number the peer states rather than one the engine has to
        // guess — and guessing is not available here anyway, since the dispatcher stages the first
        // gated request while the script is still queueing the rest.
        val limits = session.awaitQpackGateLimits(SETTINGS_WAIT_MILLIS)
        return if (limits != null) {
            ResolvedGate(GateMode.QPACK, limits)
        } else {
            ResolvedGate(GateMode.SDA, releaseBudgetBytes = releaseBudget(session))
        }
    }

    /**
     * What one release datagram carries on this connection, or unbounded where the session cannot
     * say. Read once per gate, because it depends on the path the connection settled on.
     */
    private fun releaseBudget(session: H3Session): Int =
        session.releaseDatagramBudget(options.maxDatagramSize)

    /** A gate's exclusive connection together with the ID its requests table under. */
    /**
     * A gate's exclusive connection, and how many requests it had already carried when the gate
     * took it. Carried rather than looked up later: the pooled connection object is retired the
     * moment the gate claims it, and the count has to survive that or requestsPerConnection stops
     * applying the first time a connection passes through a gate.
     */
    private class GateLease(val session: H3Session, val id: String, val requestsCarried: Int)

    private fun acquireGateConnection(): GateLease {
        waitingGates.incrementAndGet()
        try {
            claimPooledConnection()?.let { return it }
            ordinaryConnectionSnapshot().forEach { connection ->
                retireOrdinaryConnection(connection, forceClose = false)
            }
            // A connection can arrive either as a freed slot or as a gate handing one back to the
            // pool. Waiting on the semaphore alone misses the second and deadlocks against a gate
            // that returned its connection instead of closing it.
            while (runState.get() < 3) {
                claimPooledConnection()?.let { return it }
                if (tryAcquireConnectionSlot(50, TimeUnit.MILLISECONDS)) {
                    return openGateConnection()
                }
            }
            throw IllegalStateException("HTTP/3 run was cancelled while opening a gate connection")
        } finally {
            waitingGates.decrementAndGet()
            retireExcessOrdinaryConnections()
            wakeAllPoolWaiters()
        }
    }

    /**
     * Takes an idle connection out of the pool for a gate's exclusive use. The gate inherits the
     * connection's slot, so the connection is marked as having released it already and finishBatch
     * becomes the one place that hands it back.
     */
    private fun claimPooledConnection(): GateLease? {
        while (true) {
            // Claiming exclusive gate ownership is one compare-and-set, so a request cannot be
            // handed a lease on it between the two: either the gate wins and the request looks
            // elsewhere, or the request wins and this connection is not idle for the gate to take.
            val claimed = ordinaryConnections.firstOrNull { it.tryClaimIdle() } ?: return null
            ordinaryConnections.remove(claimed)
            // Asked on the way out as well as on the way in. Nothing keeps a pooled connection
            // alive and the idle timeout is the smaller of what the two ends asked for, so a
            // connection can reach it while it waits to be claimed. Staging is the first thing a
            // gate does with the connection it takes, and a gate has no retry behind it: where an
            // ordinary request survives a dead connection by asking for another one, a gate loses
            // its whole batch to it.
            if (!isStillConnected(claimed)) {
                discardGateClaim(claimed)
                continue
            }
            // The gate inherits the connection's slot, so nothing else may hand it back.
            check(claimed.claimSlot()) { "gate claimed a connection whose slot was already released" }
            synchronized(poolLock) {
                poolLock.notifyAll()
            }
            // The gate inherits the connection's ID as well as its slot, so a connection that
            // passes through a gate and back into the pool keeps tabling under the ID it started
            // with.
            return GateLease(claimed.session, claimed.id, claimed.requestsCarried)
        }
    }

    /** Closes a dead connection after this gate, rather than a pool retiree, won ownership. */
    private fun discardGateClaim(connection: OrdinaryConnection) {
        if (connection.claimClose()) runCatching { connection.session.close() }
        if (connection.claimSlot()) {
            releaseConnectionSlot()
            if (adaptive) retiredConnections.incrementAndGet()
        }
        wakeAllPoolWaiters()
    }

    /** Opens a connection against a slot the caller has already acquired. */
    private fun openGateConnection(): GateLease {
        var reservedSlot = true
        try {
            if (runState.get() >= 3) {
                throw IllegalStateException("HTTP/3 run was cancelled while opening a gate connection")
            }
            val session = try {
                openConnection()
            } catch (exception: Throwable) {
                recordConnectionOpenFailure(exception)
                if (adaptive) recordTransportFailure(exception)
                throw exception
            }
            val id = connections.incrementAndGet().toString()
            reservedSlot = false
            return GateLease(session, id, 0)
        } finally {
            if (reservedSlot) {
                releaseConnectionSlot()
            }
        }
    }

    private fun validateRequestOptions(request: Request) {
        request.endpointOverride?.let {
            throw IllegalArgumentException("endpoint override is not supported by Engine.HTTP3")
        }
        request.connectionId?.let {
            throw IllegalArgumentException("connectionId is not supported by Engine.HTTP3")
        }
    }

    private fun translate(request: Request) = TurboHttp3RequestTranslator.translate(
        request.getRequest(),
        "https",
        authority(target),
        request.kettled,
    )

    private fun completeResponse(
        request: Request,
        exchange: H3Exchange,
        startedAt: Long,
        connectionId: String?,
    ) {
        invokeCallback(request, recordResponse(request, exchange, startedAt, connectionId))
    }

    /**
     * Fills in everything a finished response tells us and returns whether it is interesting,
     * without invoking the callback. Split out so a gate can rank its whole batch by arrival
     * before any callback runs.
     */
    private fun recordResponse(
        request: Request,
        exchange: H3Exchange,
        startedAt: Long,
        connectionId: String?,
    ): Boolean {
        // Stamped when the response was actually read, not when this loop reached it: a gate
        // drains its staged exchanges in order, so reading the clock here would charge a slow
        // response to every response queued behind it.
        val lastByteAt = exchange.lastByteNanos
        // A response with no bytes at all never stamps an arrival, so fall back to the completion.
        val firstByteAt = exchange.firstByteNanos
            .takeIf { it != FirstByteTimingInputStream.UNREAD } ?: lastByteAt
        val elapsedMicros = (lastByteAt - startedAt) / 1_000
        request.ttfb = (firstByteAt - startedAt) / 1_000
        request.ttlb = elapsedMicros
        request.time = elapsedMicros
        request.arrival = (lastByteAt - start) / 1_000
        request.connectionId = connectionId
        request.response = exchange.response.toString(Charsets.ISO_8859_1)
        successfulRequests.incrementAndGet()
        return processResponse(request, exchange.response)
    }

    private fun finishBatch(gateName: String, batch: SdaBatch) {
        if (!batches.remove(gateName, batch)) {
            return
        }
        try {
            batch.connection?.let { connection -> finishConnection(batch, connection) }
        } finally {
            finishGateLifecycle(gateName)
        }
    }

    /**
     * Hands a gate's connection back, or closes it.
     *
     * Every question here is asked of that one connection: what it has carried, whether it is
     * still up, and whether its release got out.
     */
    private fun finishConnection(batch: SdaBatch, connection: GateConnection) {
        val session = connection.session
        try {
            if (session == null) return
            // Hand the connection back rather than closing it, so a later gate inherits its warm
            // congestion window instead of paying for another handshake. Only a batch that
            // released cleanly can be handed back: any other outcome leaves half-written request
            // streams dangling on the connection, along with reader threads still waiting.
            val connectionId = connection.connectionId
            // A gate's requests count against its connection like any other. Without this the same
            // connection served every gate in a run however long it ran, and
            // requestsPerConnection never reached a gate.
            val carried = connection.requestsCarried + connection.staged().size
            val connected = connectionId != null &&
                batch.releasedCleanly() &&
                carried < requestsPerConnection &&
                runCatching { session.isConnected() }.getOrDefault(false)
            synchronized(gateSettlementLock) {
                // Cancellation may have taken this token after its bounded drain while the probe
                // above was blocked. That path already closed the session and returned its slot.
                if (!unsettledGateConnections.remove(connection)) return
                // Publication and cancellation's pool snapshot share poolLock, and runState is
                // deliberately checked after the probe: either the returned session is swept, or
                // this path closes it itself, exactly once.
                val reusable = synchronized(poolLock) {
                    if (connected && runState.get() < 3) {
                        ordinaryConnections.add(OrdinaryConnection(session, connectionId!!, carried))
                        true
                    } else {
                        false
                    }
                }
                if (reusable) {
                    retireExcessOrdinaryConnections()
                    wakeAllPoolWaiters()
                    return
                }
                runCatching { session.close() }
                releaseConnectionSlot()
                if (adaptive) retiredConnections.incrementAndGet()
                wakeAllPoolWaiters()
            }
        } finally {
            // Cancellation's drain must keep waiting until the session and slot have reached one
            // of the two settled states above. Decrementing before isConnected created a window
            // where completedLatch fired and this method then republished a live connection.
            activeJobs.decrementAndGet()
        }
    }

    /** Takes over gate resources whose finisher did not settle before the bounded drain expired. */
    private fun forceCloseUnsettledGateConnections() {
        synchronized(gateSettlementLock) {
            unsettledGateConnections.toList().forEach { connection ->
                if (!unsettledGateConnections.remove(connection)) return@forEach
                connection.session?.let { session -> runCatching { session.close() } }
                releaseConnectionSlot()
                if (adaptive) retiredConnections.incrementAndGet()
            }
        }
        wakeAllPoolWaiters()
    }

    /**
     * Names the missing HTTP/3 support when the transport never got off the ground.
     *
     * <p>This engine speaks only QUIC, so a run that finished with no connection ever opened got
     * no handshake through at all, and that is a different diagnosis from requests failing on a
     * connection that did open. [connections] is the one thing that separates them: it is
     * incremented only once [H3ConnectionFactory.open] has returned a session. Once it has moved,
     * the handshake demonstrably worked and the generic wording is the honest one.
     *
     * <p>What the handshake failed on is left to the underlying error rather than guessed at. A
     * host with no HTTP/3, a wrong port and a firewall dropping UDP all look the same from here,
     * whereas a rejected certificate says so in the error text.
     */
    override fun failureSummary(): String? {
        if (connections.get() == 0 && connectionOpenFailures.get() > 0) {
            return "No HTTP/3 connection to ${authority(target)} was established: every QUIC handshake " +
                "failed, and Engine.HTTP3 has no fallback to HTTP/2 or HTTP/1.1. Last error: $lastError"
        }
        return super.failureSummary()
    }

    /**
     * How many attempts to open a QUIC connection have failed, as distinct from a request failing
     * on one that did open.
     *
     * <p>[permaFails] cannot stand in for this. With retries on, and ScriptEnvironment defaults to
     * three, one request has to lose four handshakes before it is counted, and the pool hands its
     * slots to whichever request is waiting rather than to the one part way through its retries.
     * Measured against a host with no HTTP/3 on the default settings, Fails was still 0 fifty
     * seconds into the run while Retries climbed, so a status line waiting on permaFails stayed
     * blank until the user halted the run, which failed every parked request at once.
     */
    private val connectionOpenFailures = AtomicInteger()

    private fun recordConnectionOpenFailure(exception: Throwable) {
        lastError = exception.toString()
        connectionOpenFailures.incrementAndGet()
    }

    private fun openConnection(): H3Session {
        connectionSetupsInFlight.incrementAndGet()
        return try {
            connectionFactory.open(target, verifyCertificates)
        } finally {
            connectionSetupsInFlight.decrementAndGet()
        }
    }

    private fun recordPermanentFailure(exception: Throwable) {
        lastError = exception.toString()
        permaFails.incrementAndGet()
    }

    /** Counts one failed external transport call before its caller evaluates the failed batch. */
    private inline fun <T> adaptiveTransportAttempt(attempt: () -> T): T = try {
        attempt()
    } catch (exception: Throwable) {
        if (adaptive) recordTransportFailure(exception)
        throw exception
    }

    private fun ordinaryConnectionSnapshot(): List<OrdinaryConnection> = ordinaryConnections.toList()

    /**
     * A pooled connection whose whole lease state - how many requests it has carried, how many are
     * on it now, and whether it is retired - lives in one long so that taking and giving back a
     * lease is a single compare-and-set. It used to be three fields under the engine's pool
     * monitor, which put every request through one monitor twice; measured in Burp against a live
     * target, that left 4,094 of 5,226 threads blocked entering it and 455 requests on the wire out
     * of the 4,800 the run had asked for.
     */
    private class OrdinaryConnection(
        val session: H3Session,
        val id: String,
        requestsCarried: Int = 0,
    ) {
        private val state = AtomicLong(pack(requestsCarried, 0, false))
        private val closing = AtomicBoolean(false)
        private val slotHandedBack = AtomicBoolean(false)

        val inFlight: Int get() = inFlightOf(state.get())
        val retired: Boolean get() = isOwned(state.get())
        val requestsCarried: Int get() = assignedOf(state.get())

        /** Whether this caller is the one that gets to close the session. */
        fun claimClose(): Boolean = closing.compareAndSet(false, true)

        /** Whether this caller is the one that gets to hand the connection's pool slot back. */
        fun claimSlot(): Boolean = slotHandedBack.compareAndSet(false, true)

        fun tryLease(requestLimit: Int, streamLimit: Int): Boolean {
            // Up to streamLimit requests in flight at once, matching HTTP2RequestEngine: a QUIC
            // connection multiplexes, so requestsPerConnection counts the requests a connection
            // carries over its lifetime and concurrentConnections bounds the pool, exactly as they
            // do for HTTP/2. Kwik's own stream credit is the backstop when the server grants less.
            while (true) {
                val current = state.get()
                if (isOwned(current)) {
                    return false
                }
                val assigned = assignedOf(current)
                val inFlight = inFlightOf(current)
                if (inFlight >= streamLimit || assigned >= requestLimit) {
                    return false
                }
                val next = pack(assigned + 1, inFlight + 1, assigned + 1 >= requestLimit)
                if (state.compareAndSet(current, next)) {
                    return true
                }
            }
        }

        /** Gives a lease back, and reports whether the connection is now retired. */
        fun releaseLease(retiring: Boolean): Boolean {
            while (true) {
                val current = state.get()
                val inFlight = inFlightOf(current)
                check(inFlight > 0) { "HTTP/3 connection lease was released twice" }
                val next = pack(assignedOf(current), inFlight - 1, retiring || isOwned(current))
                if (state.compareAndSet(current, next)) {
                    return isOwned(next)
                }
            }
        }

        /**
         * Claims retirement, whether or not requests remain. False means a gate already owns the
         * session and slot, so a delayed pool task must not touch either one.
         */
        fun retire(): Boolean {
            while (true) {
                val current = state.get()
                when (ownerOf(current)) {
                    GATE_OWNED -> return false
                    RETIRING -> return true
                }
                if (state.compareAndSet(current, current or RETIRING)) {
                    return true
                }
            }
        }

        /** Claims a new pool retirement; false if a gate or another shrink already owns it. */
        fun markRetiring(): Boolean {
            while (true) {
                val current = state.get()
                if (isOwned(current)) return false
                if (state.compareAndSet(current, current or RETIRING)) return true
            }
        }

        /** Takes exclusive gate ownership only while idle, atomically against ordinary leasing. */
        fun tryClaimIdle(): Boolean {
            while (true) {
                val current = state.get()
                if (isOwned(current) || inFlightOf(current) != 0) {
                    return false
                }
                if (state.compareAndSet(current, current or GATE_OWNED)) {
                    return true
                }
            }
        }

        private companion object {
            // 31 bits each for requests carried and requests in flight, which is every value
            // either can take: leasing stops at requestsPerConnection, itself an Int.
            const val COUNTER_BITS = 31
            const val COUNTER_MASK = (1L shl COUNTER_BITS) - 1
            const val RETIRING = 1L shl 62
            const val GATE_OWNED = 1L shl 63
            const val OWNER_MASK = RETIRING or GATE_OWNED

            fun inFlightOf(state: Long): Int = (state and COUNTER_MASK).toInt()

            fun assignedOf(state: Long): Int = ((state ushr COUNTER_BITS) and COUNTER_MASK).toInt()

            fun ownerOf(state: Long): Long = state and OWNER_MASK

            fun isOwned(state: Long): Boolean = ownerOf(state) != 0L

            fun pack(assigned: Int, inFlight: Int, retired: Boolean): Long =
                (assigned.toLong() shl COUNTER_BITS) or
                    inFlight.toLong() or
                    (if (retired) RETIRING else 0L)
        }
    }

    companion object {
        /** Matches QuicConfig's handshake timeout: no point giving up before the transport does. */
        /**
         * How long a QUIC handshake is given before the transport abandons it, and so the longest
         * an opening connection can take to report either way.
         */
        internal const val HANDSHAKE_TIMEOUT_SECONDS = 10L

        /**
         * How long [openInitialConnections] waits for the opening connections to report.
         *
         * <p>Strictly longer than [HANDSHAKE_TIMEOUT_SECONDS], because a wait that expires at the
         * same moment as the handshakes it is waiting on learns nothing from them. Both were 10s,
         * and against a host with no HTTP/3 the wait lost the race every time: the run read zero
         * connections and zero failures and carried on as though the pool were still filling,
         * instead of stopping the way Engine.HTTP2 does.
         */
        internal const val HANDSHAKE_WAIT_SECONDS = HANDSHAKE_TIMEOUT_SECONDS + 2

        /**
         * How long a gate waits for the peer's SETTINGS before settling how it will release.
         * Only reached by a gate that opened its own connection; an inherited one has them already.
         */
        private const val SETTINGS_WAIT_MILLIS = 1000L


        private const val RUN_START_POLL_MILLIS = 10L

        /**
         * How long the dispatcher waits for in-flight requests once the run is over. Long enough
         * that a request released by its connection closing is counted normally, short enough that
         * one that never comes back does not keep the engine reachable.
         */
        private val DRAIN_WAIT_NANOS = TimeUnit.SECONDS.toNanos(2)

        private const val DRAIN_POLL_MILLIS = 10L

        private const val IDLE_POLL_MILLIS = 100L

        /**
         * How often response reads are checked against their deadlines. The deadline itself is
         * tens of seconds, so this only has to be fine enough that a failed request is not left
         * holding its thread noticeably longer than that.
         */
        private const val RESPONSE_SWEEP_MILLIS = 250L

        private const val DISPATCH_POLL_MILLIS = 50L

        /** How long the dispatcher blocks for work once the queue has been found empty. */
        private const val QUEUE_POLL_MILLIS = 50L

        /**
         * How long a request thread parks when the pool has no free lease. Short because the
         * wake-up that would end the wait early is skipped when no thread appears to be parked,
         * and this timeout is what bounds that race.
         */
        private const val POOL_WAIT_MILLIS = 5L

        /**
         * Requests a single QUIC connection carries at once, and with `concurrentConnections` the
         * other half of what puts requests in flight.
         *
         * The peer advertises its own limit in `initial_max_streams_bidi` and Kwik blocks on that,
         * so asking for more than a server allows costs nothing but a parked thread. 100 was
         * inherited from HTTP2RequestEngine, where it is HTTP/2's protocol default rather than a
         * measured optimum. Against a real HTTP/3 server, on a 1,000,000 request fuzz: 100 streams
         * took 14s, 256 took 13s, and 512 collapsed into loss and retransmission. Raising it is
         * subject to the same cliff as raising connections, so this is the last point measured
         * stable rather than a number to keep climbing.
         */
        const val DEFAULT_MAX_CONCURRENT_STREAMS = 256

        const val DEFAULT_ADAPTIVE_CONNECTIONS = 10

        /**
         * Ceiling on requests in flight when each one holds an OS thread. Without it the configured
         * connections x streams product goes straight to the OS: an 800-connection run asks for
         * 80,000 threads, and a Burp with other work in flight died with "OutOfMemoryError: unable
         * to create native thread" before the engine could start its dispatcher.
         */
        const val MAX_REQUESTS_IN_FLIGHT_PLATFORM = 4096

        /**
         * Ceiling on requests in flight when the threads are virtual. Those cost heap rather than
         * OS threads, so the bound is only there to stop a runaway configuration exhausting memory,
         * and it can sit far higher. Measured in Burp on Java 26: the platform bound was throttling
         * the run, with 41 to 96 connections all flatlining at ~90k rps because each clamped to
         * 4096 in flight.
         */
        const val MAX_REQUESTS_IN_FLIGHT_VIRTUAL = 65536

        /** The in-flight ceiling appropriate to the kind of thread carrying each request. */
        @JvmStatic
        fun maxRequestsInFlight(virtualThreads: Boolean): Int =
            if (virtualThreads) MAX_REQUESTS_IN_FLIGHT_VIRTUAL else MAX_REQUESTS_IN_FLIGHT_PLATFORM

        /**
         * The first JDK where a virtual thread no longer pins its carrier while blocked inside a
         * synchronized block (JEP 491). Below it, every thread this engine parks in Kwik costs a
         * carrier regardless, so virtual threads are overhead with a ceiling attached.
         */
        private const val FIRST_JDK_WITHOUT_MONITOR_PINNING = 24

        /** Whether [jdkFeatureVersion] carries blocked virtual threads without pinning a carrier. */
        @JvmStatic
        fun prefersVirtualThreads(jdkFeatureVersion: Int): Boolean =
            jdkFeatureVersion >= FIRST_JDK_WITHOUT_MONITOR_PINNING

        private fun authority(target: URL): String {
            val port = getEffectivePort(target)
            return if (port == 443) target.host else "${target.host}:$port"
        }

        private fun defaultConnectionFactory(idleTimeout: Long): H3ConnectionFactory =
            H3ConnectionFactory { target, verifyCertificates ->
                val config = QuicConfig(
                    Duration.ofSeconds(HANDSHAKE_TIMEOUT_SECONDS),
                    if (idleTimeout > 0) Duration.ofMillis(idleTimeout) else Duration.ofSeconds(30),
                    verifyCertificates,
                )
                H3Connection.open(
                    ControlledKwikQuicTransport.connect(
                        target.host,
                        getEffectivePort(target),
                        config,
                    ),
                )
            }
    }
}
