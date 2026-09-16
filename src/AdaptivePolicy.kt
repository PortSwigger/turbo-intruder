package burp

enum class AdaptivePhase { BASELINE, RAMP, REFINE, REQUEST_LIFETIME, COOLDOWN, STEADY }

enum class AdaptiveAxis { CONCURRENCY, REQUESTS_PER_CONNECTION }

data class AdaptiveWindow(
    val limits: AdaptiveLimits,
    val successfulRps: Double,
    val transportFailures: Int,
    val eligible: Boolean,
    val transition: Boolean,
    val elapsedNanos: Long,
)

sealed interface AdaptiveDecision {
    data class Hold(val reason: String) : AdaptiveDecision

    data class Resize(val limits: AdaptiveLimits, val reason: String) : AdaptiveDecision
}

data class AdaptivePolicySnapshot(
    val phase: AdaptivePhase,
    val axis: AdaptiveAxis,
    val bestLimits: AdaptiveLimits,
    val bestRps: Double,
    val lastReason: String,
    val latestBackoffReason: String?,
)

class AdaptivePolicy(
    private val protocol: AutoProtocol,
    defaults: AdaptiveLimits,
) {
    companion object {
        const val MIN_CONCURRENCY = 1
        const val MAX_CONCURRENCY = Int.MAX_VALUE
        const val MIN_REQUESTS_PER_CONNECTION = 1
        const val MAX_REQUESTS_PER_CONNECTION = 1_000_000
        const val IMPROVEMENT_RATIO = 1.03
        const val STEADY_PROBE_NANOS = 30_000_000_000L
    }

    private var phase = AdaptivePhase.BASELINE
    private var axis = AdaptiveAxis.CONCURRENCY
    private var bestLimits = clamp(defaults)
    private var bestRps = 0.0
    private var hasBestCandidate = false
    private var upperBoundary: Int? = null
    private var pendingRefinementProbe: Int? = null
    private var cooldownAxis = AdaptiveAxis.CONCURRENCY
    private var cooldownCleanWindows = 0
    private var steadyEligibleNanos = 0L
    private var steadyProbeBase: AdaptiveLimits? = null
    private var lastReason = "awaiting baseline"
    private var latestBackoffReason: String? = null

    private data class State(
        val phase: AdaptivePhase,
        val axis: AdaptiveAxis,
        val bestLimits: AdaptiveLimits,
        val bestRps: Double,
        val hasBestCandidate: Boolean,
        val upperBoundary: Int?,
        val pendingRefinementProbe: Int?,
        val cooldownAxis: AdaptiveAxis,
        val cooldownCleanWindows: Int,
        val steadyEligibleNanos: Long,
        val steadyProbeBase: AdaptiveLimits?,
        val lastReason: String,
        val latestBackoffReason: String?,
    )

    fun observe(window: AdaptiveWindow): AdaptiveDecision {
        if (window.transportFailures > 0) {
            return handleFailure(window)
        }
        if (!window.eligible) {
            if (phase == AdaptivePhase.COOLDOWN) cooldownCleanWindows = 0
            return hold("measurement frozen")
        }
        if (window.transition) {
            return hold("transition window")
        }

        return when (phase) {
            AdaptivePhase.BASELINE -> observeBaseline(window)
            AdaptivePhase.RAMP -> observeRamp(window)
            AdaptivePhase.REFINE -> observeRefinement(window)
            AdaptivePhase.REQUEST_LIFETIME -> observeRequestLifetime(window)
            AdaptivePhase.COOLDOWN -> observeCooldown(window)
            AdaptivePhase.STEADY -> observeSteady(window)
        }
    }

    internal fun observeWithResizeApplication(
        window: AdaptiveWindow,
        applyResize: (AdaptiveDecision.Resize) -> Boolean,
    ): AdaptiveDecision? {
        val previous = state()
        val decision = observe(window)
        if (decision is AdaptiveDecision.Resize && !applyResize(decision)) {
            restore(previous)
            return null
        }
        return decision
    }

    fun snapshot() = AdaptivePolicySnapshot(
        phase,
        axis,
        bestLimits,
        bestRps,
        lastReason,
        latestBackoffReason,
    )

    private fun state() = State(
        phase,
        axis,
        bestLimits,
        bestRps,
        hasBestCandidate,
        upperBoundary,
        pendingRefinementProbe,
        cooldownAxis,
        cooldownCleanWindows,
        steadyEligibleNanos,
        steadyProbeBase,
        lastReason,
        latestBackoffReason,
    )

    private fun restore(state: State) {
        phase = state.phase
        axis = state.axis
        bestLimits = state.bestLimits
        bestRps = state.bestRps
        hasBestCandidate = state.hasBestCandidate
        upperBoundary = state.upperBoundary
        pendingRefinementProbe = state.pendingRefinementProbe
        cooldownAxis = state.cooldownAxis
        cooldownCleanWindows = state.cooldownCleanWindows
        steadyEligibleNanos = state.steadyEligibleNanos
        steadyProbeBase = state.steadyProbeBase
        lastReason = state.lastReason
        latestBackoffReason = state.latestBackoffReason
    }

    private fun observeBaseline(window: AdaptiveWindow): AdaptiveDecision {
        recordBest(window)
        return if (axis == AdaptiveAxis.CONCURRENCY && axisValue(window.limits) >= axisMaximum()) {
            completeActiveAxis(window)
        } else {
            phase = AdaptivePhase.RAMP
            resize(withAxis(window.limits, doubled(axisValue(window.limits))), "baseline complete")
        }
    }

    private fun observeRamp(window: AdaptiveWindow): AdaptiveDecision {
        if (!isImprovement(window.successfulRps)) {
            upperBoundary = nearestUpper(axisValue(window.limits))
            phase = AdaptivePhase.REFINE
            return refinementOrCompletion(window)
        }

        recordBest(window)
        if (axisValue(bestLimits) >= axisMaximum()) {
            return completeActiveAxis(window)
        }
        return resize(withAxis(bestLimits, doubled(axisValue(bestLimits))), "clean ramp")
    }

    private fun observeRefinement(window: AdaptiveWindow): AdaptiveDecision {
        val candidate = axisValue(window.limits)
        if (pendingRefinementProbe == null) {
            return refinementOrCompletion(window)
        }
        pendingRefinementProbe = null
        if (candidate <= axisValue(bestLimits)) {
            return completeActiveAxis(window)
        }

        if (isImprovement(window.successfulRps)) {
            recordBest(window)
        } else {
            upperBoundary = nearestUpper(candidate)
        }
        return refinementOrCompletion(window)
    }

    private fun observeRequestLifetime(window: AdaptiveWindow): AdaptiveDecision {
        val candidate = axisValue(window.limits)
        val best = axisValue(bestLimits)
        if (pendingRefinementProbe == candidate) pendingRefinementProbe = null

        if (candidate > best) {
            if (isImprovement(window.successfulRps)) {
                recordBest(window)
            } else {
                upperBoundary = nearestUpper(candidate)
            }
        }

        if (upperBoundary != null) {
            return refinementOrCompletion(window)
        }
        if (axisValue(bestLimits) >= axisMaximum()) {
            return enterSteady("request lifetime ceiling")
        }
        return resize(
            withAxis(bestLimits, doubled(axisValue(bestLimits))),
            "request lifetime probe",
        )
    }

    private fun observeCooldown(window: AdaptiveWindow): AdaptiveDecision {
        cooldownCleanWindows++
        if (!hasBestCandidate) {
            recordBest(window)
        }
        if (cooldownCleanWindows < 2) {
            return hold("cooldown")
        }

        cooldownCleanWindows = 0
        pendingRefinementProbe = null
        phase = if (upperBoundary != null && upperBoundary!! - axisValue(bestLimits) > 1) {
            AdaptivePhase.REFINE
        } else if (axis == AdaptiveAxis.CONCURRENCY && protocol == AutoProtocol.HTTP1 &&
            bestLimits.requestsPerConnection != null
        ) {
            AdaptivePhase.REQUEST_LIFETIME
        } else {
            AdaptivePhase.STEADY
        }
        if (phase != AdaptivePhase.REFINE) upperBoundary = null
        if (phase == AdaptivePhase.REQUEST_LIFETIME) axis = AdaptiveAxis.REQUESTS_PER_CONNECTION
        return hold("cooldown complete")
    }

    private fun observeSteady(window: AdaptiveWindow): AdaptiveDecision {
        val probeBase = steadyProbeBase
        if (probeBase != null && axisValue(window.limits) != axisValue(probeBase)) {
            steadyProbeBase = null
            steadyEligibleNanos = 0L
            return if (isImprovement(window.successfulRps)) {
                recordBest(window)
                hold("steady reprobe accepted")
            } else {
                resize(probeBase, "steady reprobe rejected")
            }
        }

        steadyEligibleNanos = saturatedAdd(
            steadyEligibleNanos,
            window.elapsedNanos.coerceAtLeast(0L),
        )
        if (steadyEligibleNanos < STEADY_PROBE_NANOS) {
            return hold("steady")
        }

        steadyEligibleNanos = 0L
        val current = axisValue(bestLimits)
        val candidate = tenPercentHigher(current).coerceAtMost(axisMaximum())
        if (candidate == current) {
            return hold("steady ceiling")
        }
        steadyProbeBase = bestLimits
        return resize(withAxis(bestLimits, candidate), "steady reprobe")
    }

    private fun handleFailure(window: AdaptiveWindow): AdaptiveDecision {
        if (phase == AdaptivePhase.COOLDOWN) {
            latestBackoffReason = "repeated transport failure"
            cooldownCleanWindows = 0
            pendingRefinementProbe = null
            val failedValue = axisValue(window.limits, cooldownAxis)
            upperBoundary = nearestUpper(failedValue)
            val backedOff = (failedValue.toLong() / 2L)
                .coerceAtLeast(axisMinimum(cooldownAxis).toLong())
                .toInt()
            if (!hasBestCandidate || failedValue <= axisValue(bestLimits, cooldownAxis)) {
                bestLimits = withAxis(window.limits, backedOff, cooldownAxis)
                bestRps = 0.0
                hasBestCandidate = false
            }
            return resize(
                withAxis(window.limits, backedOff, cooldownAxis),
                "repeated transport failure",
            )
        }

        cooldownAxis = failureAxis(window)
        latestBackoffReason = "transport failure"
        axis = cooldownAxis
        val failedValue = axisValue(window.limits, cooldownAxis)
        val safeValue = axisValue(bestLimits, cooldownAxis)
        val hasLowerSafeCandidate = hasBestCandidate && safeValue < failedValue
        val backedOff = if (hasLowerSafeCandidate) {
            safeValue
        } else {
            ((failedValue.toLong() * 3L) / 4L)
                .coerceAtLeast(axisMinimum(cooldownAxis).toLong())
                .toInt()
        }

        upperBoundary = failedValue
        if (!hasLowerSafeCandidate) {
            bestLimits = withAxis(window.limits, backedOff, cooldownAxis)
            bestRps = 0.0
            hasBestCandidate = false
        }
        phase = AdaptivePhase.COOLDOWN
        cooldownCleanWindows = 0
        pendingRefinementProbe = null
        steadyProbeBase = null
        steadyEligibleNanos = 0L
        return resize(withAxis(window.limits, backedOff, cooldownAxis), "transport failure")
    }

    private fun failureAxis(window: AdaptiveWindow): AdaptiveAxis {
        val probingRequestLifetime = axis == AdaptiveAxis.REQUESTS_PER_CONNECTION &&
            window.limits.requestsPerConnection != bestLimits.requestsPerConnection
        return if (protocol == AutoProtocol.HTTP1 && probingRequestLifetime) {
            AdaptiveAxis.REQUESTS_PER_CONNECTION
        } else {
            AdaptiveAxis.CONCURRENCY
        }
    }

    private fun refinementOrCompletion(window: AdaptiveWindow): AdaptiveDecision {
        val lower = axisValue(bestLimits)
        val upper = upperBoundary ?: return completeActiveAxis(window)
        if (upper - lower <= 1) {
            return completeActiveAxis(window, restoreBest = true)
        }

        val midpoint = lower + (upper - lower) / 2
        pendingRefinementProbe = midpoint
        val reason = if (axis == AdaptiveAxis.CONCURRENCY) {
            "concurrency refinement"
        } else {
            "request lifetime refinement"
        }
        return resize(withAxis(bestLimits, midpoint), reason)
    }

    private fun completeActiveAxis(
        window: AdaptiveWindow,
        restoreBest: Boolean = false,
    ): AdaptiveDecision {
        val requestLifetimeFollows = axis == AdaptiveAxis.CONCURRENCY &&
            protocol == AutoProtocol.HTTP1 &&
            bestLimits.requestsPerConnection != null

        if (restoreBest && window.limits != bestLimits) {
            if (requestLifetimeFollows) {
                axis = AdaptiveAxis.REQUESTS_PER_CONNECTION
                phase = AdaptivePhase.REQUEST_LIFETIME
            } else {
                phase = AdaptivePhase.STEADY
            }
            upperBoundary = null
            pendingRefinementProbe = null
            steadyEligibleNanos = 0L
            steadyProbeBase = null
            return resize(bestLimits, "axis converged")
        }

        if (requestLifetimeFollows) {
            axis = AdaptiveAxis.REQUESTS_PER_CONNECTION
            phase = AdaptivePhase.REQUEST_LIFETIME
            upperBoundary = null
            pendingRefinementProbe = null
            return resize(
                withAxis(bestLimits, doubled(axisValue(bestLimits))),
                "request lifetime probe",
            )
        }

        phase = AdaptivePhase.STEADY
        upperBoundary = null
        pendingRefinementProbe = null
        steadyEligibleNanos = 0L
        steadyProbeBase = null
        return hold("axis converged")
    }

    private fun enterSteady(reason: String): AdaptiveDecision {
        phase = AdaptivePhase.STEADY
        upperBoundary = null
        pendingRefinementProbe = null
        steadyEligibleNanos = 0L
        steadyProbeBase = null
        return hold(reason)
    }

    private fun recordBest(window: AdaptiveWindow) {
        bestLimits = clamp(window.limits)
        bestRps = window.successfulRps
        hasBestCandidate = true
    }

    private fun isImprovement(candidateRps: Double): Boolean =
        !hasBestCandidate ||
            (candidateRps > bestRps && candidateRps >= bestRps * IMPROVEMENT_RATIO)

    private fun nearestUpper(candidate: Int): Int =
        upperBoundary?.let { minOf(it, candidate) } ?: candidate

    private fun axisValue(
        limits: AdaptiveLimits,
        selectedAxis: AdaptiveAxis = axis,
    ): Int = when (selectedAxis) {
        AdaptiveAxis.CONCURRENCY -> limits.concurrency
        AdaptiveAxis.REQUESTS_PER_CONNECTION ->
            requireNotNull(limits.requestsPerConnection) { "request lifetime axis requires a limit" }
    }

    private fun withAxis(
        limits: AdaptiveLimits,
        value: Int,
        selectedAxis: AdaptiveAxis = axis,
    ): AdaptiveLimits {
        val boundedValue = value.coerceIn(
            axisMinimum(selectedAxis),
            axisMaximum(selectedAxis),
        )
        return clamp(
            when (selectedAxis) {
                AdaptiveAxis.CONCURRENCY -> limits.copy(concurrency = boundedValue)
                AdaptiveAxis.REQUESTS_PER_CONNECTION ->
                    limits.copy(requestsPerConnection = boundedValue)
            },
        )
    }

    private fun doubled(value: Int): Int =
        (value.toLong() * 2L).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

    private fun tenPercentHigher(value: Int): Int {
        val increment = maxOf(1L, value.toLong() / 10L)
        return (value.toLong() + increment).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }

    private fun axisMinimum(selectedAxis: AdaptiveAxis = axis): Int = when (selectedAxis) {
        AdaptiveAxis.CONCURRENCY -> MIN_CONCURRENCY
        AdaptiveAxis.REQUESTS_PER_CONNECTION -> MIN_REQUESTS_PER_CONNECTION
    }

    private fun axisMaximum(selectedAxis: AdaptiveAxis = axis): Int = when (selectedAxis) {
        AdaptiveAxis.CONCURRENCY -> MAX_CONCURRENCY
        AdaptiveAxis.REQUESTS_PER_CONNECTION -> MAX_REQUESTS_PER_CONNECTION
    }

    private fun clamp(limits: AdaptiveLimits) = AdaptiveLimits(
        limits.concurrency.coerceIn(MIN_CONCURRENCY, MAX_CONCURRENCY),
        limits.requestsPerConnection?.coerceIn(
            MIN_REQUESTS_PER_CONNECTION,
            MAX_REQUESTS_PER_CONNECTION,
        ),
    )

    private fun saturatedAdd(left: Long, right: Long): Long =
        if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right

    private fun hold(reason: String): AdaptiveDecision.Hold {
        lastReason = reason
        return AdaptiveDecision.Hold(reason)
    }

    private fun resize(limits: AdaptiveLimits, reason: String): AdaptiveDecision.Resize {
        lastReason = reason
        return AdaptiveDecision.Resize(clamp(limits), reason)
    }
}
