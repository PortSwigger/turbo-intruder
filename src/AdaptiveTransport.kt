package burp

enum class AutoProtocol { HTTP1, HTTP2, HTTP3 }

data class AdaptiveLimits(
    val concurrency: Int,
    val requestsPerConnection: Int?,
) {
    init {
        require(concurrency >= 1) { "concurrency must be positive" }
        requestsPerConnection?.let { require(it in 1..1_000_000) }
    }
}

data class AdaptiveMetrics(
    val capturedAtNanos: Long,
    val successfulResponses: Int,
    val transportFailures: Int,
    val retryAttempts: Int,
    val permanentFailures: Int,
    val activeRequests: Int,
    val queuedRequests: Int,
    val openedConnections: Int,
    val retiredConnections: Int,
    val limits: AdaptiveLimits,
    val saturated: Boolean,
    val freezeReason: String?,
    val safeToMeasure: Boolean = true,
) {
    val frozen: Boolean get() = freezeReason != null
}

interface AdaptiveTransport {
    val autoProtocol: AutoProtocol
    fun defaultAdaptiveLimits(): AdaptiveLimits
    fun currentAdaptiveLimits(): AdaptiveLimits
    fun adaptiveMetrics(): AdaptiveMetrics
    fun resizeConcurrency(newLimit: Int)
    fun resizeRequestsPerConnection(newLimit: Int): Boolean
}
