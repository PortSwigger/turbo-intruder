package burp

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

fun interface AdaptiveClock {
    fun nanoTime(): Long
}

data class AdaptiveStatus(
    val protocol: AutoProtocol,
    val phase: AdaptivePhase,
    val limits: AdaptiveLimits,
    val bestRps: Double,
    val reason: String,
    val backoffReason: String?,
)

internal class AdaptiveStatusSource {
    private val status = AtomicReference<AdaptiveStatus?>()

    fun snapshot(): AdaptiveStatus? = status.get()

    fun publish(next: AdaptiveStatus): AdaptiveStatus? = status.getAndSet(next)
}

class AdaptiveController @JvmOverloads constructor(
    private val transport: AdaptiveTransport,
    private val policy: AdaptivePolicy,
    private val clock: AdaptiveClock = AdaptiveClock(System::nanoTime),
    private val beforeResizeApplication: () -> Unit = {},
    private val transitionLogger: (String) -> Unit = Utils::out,
    private val automaticSampling: Boolean = true,
) : AutoCloseable {
    private enum class ResizeGate { IDLE, APPLYING, STOPPED }

    companion object {
        private const val SAMPLE_INTERVAL_MILLIS = 250L
        private const val WINDOW_NANOS = 1_000_000_000L
        private const val REQUIRED_SATURATION_DENOMINATOR = 4L
    }

    private val running = AtomicBoolean(false)
    private val stopped = AtomicBoolean(false)
    @Volatile
    private var statusSource: AdaptiveStatusSource? = null
    @Volatile
    private var standaloneStatus: AdaptiveStatus? = null
    private val resizeGate = AtomicReference(ResizeGate.IDLE)
    private val sampleLock = Any()

    @Volatile
    private var sampler: Thread? = null

    private var baseline: AdaptiveMetrics? = null
    private var baselineNanos = 0L
    private var previousSampleNanos = 0L
    private var saturatedNanos = 0L
    private var transitionNextWindow = false

    fun start() {
        if (stopped.get() || !running.compareAndSet(false, true)) return
        if (!automaticSampling) return

        Thread(::sampleLoop, "adaptive-controller").also {
            it.isDaemon = true
            sampler = it
            it.start()
        }
    }

    fun stop() {
        stopped.set(true)
        resizeGate.set(ResizeGate.STOPPED)
        running.set(false)
        sampler?.interrupt()
    }

    fun sampleOnce() {
        if (stopped.get()) return

        synchronized(sampleLock) {
            if (stopped.get()) return

            val current = transport.adaptiveMetrics()
            val now = clock.nanoTime()
            if (!current.safeToMeasure) {
                observeUnconverged(current, now)
                return
            }

            if (current.frozen) {
                resetBaseline()
                publish(current.limits, current.freezeReason ?: "measurement frozen")
                return
            }

            val windowBaseline = baseline
            if (windowBaseline == null || now < baselineNanos) {
                startBaseline(current, now)
                publish(current.limits, "awaiting baseline")
                return
            }

            val sampleElapsedNanos = now - previousSampleNanos
            previousSampleNanos = now
            if (current.saturated) saturatedNanos = saturatedAdd(saturatedNanos, sampleElapsedNanos)
            val elapsedNanos = now - baselineNanos
            if (elapsedNanos < WINDOW_NANOS) return

            val window = AdaptiveWindow(
                limits = windowBaseline.limits,
                successfulRps = counterDelta(
                    current.successfulResponses,
                    windowBaseline.successfulResponses,
                ).toDouble() * WINDOW_NANOS / elapsedNanos,
                transportFailures = counterDelta(
                    current.transportFailures,
                    windowBaseline.transportFailures,
                ),
                eligible = saturatedNanos >= requiredSaturatedNanos(elapsedNanos),
                transition = transitionNextWindow,
                elapsedNanos = elapsedNanos,
            )
            transitionNextWindow = false

            observeWindow(window, current, now, window.successfulRps)
        }
    }

    fun snapshot(): AdaptiveStatus? = statusSource?.snapshot() ?: standaloneStatus

    internal fun attachStatusSource(source: AdaptiveStatusSource) {
        synchronized(sampleLock) {
            check(statusSource == null) { "Adaptive status is already attached" }
            if (standaloneStatus == null) {
                publish(transport.currentAdaptiveLimits(), "awaiting baseline")
            }
            source.publish(requireNotNull(standaloneStatus))
            statusSource = source
            standaloneStatus = null
        }
    }

    override fun close() = stop()

    private fun sampleLoop() {
        while (running.get()) {
            sampleOnce()
            try {
                Thread.sleep(SAMPLE_INTERVAL_MILLIS)
            } catch (_: InterruptedException) {
                if (!running.get()) return
            }
        }
    }

    private fun applyResize(
        decision: AdaptiveDecision.Resize,
        current: AdaptiveMetrics,
        now: Long,
        windowRps: Double,
    ): Boolean {
        if (stopped.get()) return false
        beforeResizeApplication()
        if (!resizeGate.compareAndSet(ResizeGate.IDLE, ResizeGate.APPLYING)) return false

        try {
            val resize: () -> Unit = {
                if (decision.limits.concurrency != current.limits.concurrency) {
                    transport.resizeConcurrency(decision.limits.concurrency)
                }
                decision.limits.requestsPerConnection?.let { requestLimit ->
                    if (requestLimit != current.limits.requestsPerConnection) {
                        transport.resizeRequestsPerConnection(requestLimit)
                    }
                }
                Unit
            }
            val applied = (transport as? RequestEngine)?.tryApplyAdaptiveResize(current, resize)
                ?: run {
                    resize()
                    true
                }
            if (!applied) return false

            val appliedLimits = transport.currentAdaptiveLimits()
            transitionNextWindow = appliedLimits != current.limits
            startBaseline(current.copy(limits = appliedLimits), now)
            publish(appliedLimits, decision.reason, windowRps)
            return true
        } finally {
            resizeGate.compareAndSet(ResizeGate.APPLYING, ResizeGate.IDLE)
        }
    }

    private fun observeWindow(
        window: AdaptiveWindow,
        current: AdaptiveMetrics,
        now: Long,
        windowRps: Double,
    ) {
        val decision = policy.observeWithResizeApplication(window) { resize ->
            applyResize(resize, current, now, windowRps)
        }
        if (decision == null) {
            if (!stopped.get()) {
                // A gate can win admission after a partial resize has reported a capacity
                // failure. Keep that failure relative to the pre-resize baseline so the next
                // sample retries the rejected rollback after the gate lifecycle ends.
                if (current.safeToMeasure) resetBaseline()
                val reason = if ((transport as? RequestEngine)?.activeGateLifecycleCount() != 0) {
                    "gate in progress"
                } else {
                    "resize snapshot invalidated"
                }
                publish(current.limits, reason, windowRps)
            }
            return
        }
        if (decision is AdaptiveDecision.Hold) {
            startBaseline(current, now)
            publish(current.limits, decision.reason, windowRps)
        }
    }

    private fun observeUnconverged(current: AdaptiveMetrics, now: Long) {
        val windowBaseline = baseline
        val failures = windowBaseline?.let {
            counterDelta(current.transportFailures, it.transportFailures)
        } ?: 0
        if (windowBaseline != null && failures > 0) {
            val elapsedNanos = (now - baselineNanos).coerceAtLeast(0L)
            val failureOnlyWindow = AdaptiveWindow(
                limits = current.limits,
                successfulRps = 0.0,
                transportFailures = failures,
                eligible = false,
                transition = true,
                elapsedNanos = elapsedNanos,
            )
            observeWindow(failureOnlyWindow, current, now, 0.0)
            return
        }

        startBaseline(current, now)
        transitionNextWindow = true
        publish(current.limits, "capacity converging")
    }

    private fun startBaseline(metrics: AdaptiveMetrics, now: Long) {
        baseline = metrics
        baselineNanos = now
        previousSampleNanos = now
        saturatedNanos = 0L
    }

    private fun resetBaseline() {
        baseline = null
        saturatedNanos = 0L
    }

    private fun publish(limits: AdaptiveLimits, reason: String, windowRps: Double? = null) {
        val policySnapshot = policy.snapshot()
        val next = AdaptiveStatus(
            protocol = transport.autoProtocol,
            phase = policySnapshot.phase,
            limits = limits,
            bestRps = policySnapshot.bestRps,
            reason = reason,
            backoffReason = policySnapshot.latestBackoffReason,
        )
        val source = statusSource
        val previous = if (source != null) {
            source.publish(next)
        } else {
            standaloneStatus.also { standaloneStatus = next }
        }
        if (previous != null &&
            (previous.phase != next.phase || previous.limits != next.limits)
        ) {
            val measured = windowRps?.let {
                String.format(java.util.Locale.ROOT, "%.0f", it)
            } ?: "n/a"
            runCatching {
                transitionLogger(
                    "AUTO tuning ${protocolName(next.protocol)} " +
                        "phase=${previous.phase}->${next.phase} " +
                        "limits=${formatLimits(previous.limits)} -> ${formatLimits(next.limits)} " +
                        "windowRps=$measured reason=$reason",
                )
            }
        }
    }

    private fun protocolName(protocol: AutoProtocol): String = when (protocol) {
        AutoProtocol.HTTP1 -> "HTTP/1.1"
        AutoProtocol.HTTP2 -> "HTTP/2"
        AutoProtocol.HTTP3 -> "HTTP/3"
    }

    private fun formatLimits(limits: AdaptiveLimits): String = buildString {
        append("concurrency=${limits.concurrency}")
        limits.requestsPerConnection?.let { append(" requestsPerConnection=$it") }
    }

    private fun counterDelta(current: Int, previous: Int): Int =
        (current.toLong() - previous.toLong()).coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()

    private fun saturatedAdd(left: Long, right: Long): Long =
        if (right > 0L && Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right

    private fun requiredSaturatedNanos(elapsedNanos: Long): Long =
        elapsedNanos - elapsedNanos / REQUIRED_SATURATION_DENOMINATOR
}
