package burp

import hp3.quic.ControlledKwikQuicTransport
import hp3.quic.QuicConfig
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class AutoProbeResult(
    val protocol: AutoProtocol,
    val succeeded: Boolean,
    val elapsedMillis: Long,
    val failure: String?,
) {
    companion object {
        fun success(protocol: AutoProtocol, elapsedMillis: Long) =
            AutoProbeResult(protocol, true, elapsedMillis, null)

        fun failure(protocol: AutoProtocol, failure: String) =
            AutoProbeResult(protocol, false, 0, failure)
    }
}

fun interface AutoHandshakeProbe {
    fun probe(endpoint: URL, verifyCertificates: Boolean, timeout: Duration): AutoProbeResult

    /** Releases a resource an injected probe owns when its shared deadline expires. */
    fun cancel() = Unit
}

/** Establishes protocol handshakes without sending an HTTP request. */
class AutoProtocolProber(
    private val probes: Map<AutoProtocol, AutoHandshakeProbe> = productionProbes(),
    private val timeout: Duration = Duration.ofSeconds(12),
) {
    init {
        require(!timeout.isZero && !timeout.isNegative) { "probe timeout must be positive" }
    }

    companion object {
        private val currentExecution = ThreadLocal<ProbeExecution?>()
        private val cleanupExecutor = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "auto-protocol-probe-cleanup").apply { isDaemon = true }
        }

        fun fake(vararg results: AutoProbeResult): AutoProtocolProber =
            AutoProtocolProber(
                results.associate { result ->
                    result.protocol to AutoHandshakeProbe { _, _, _ -> result }
                },
            )

        private fun productionProbes(): Map<AutoProtocol, AutoHandshakeProbe> = mapOf(
            AutoProtocol.HTTP1 to AutoHandshakeProbe(::probeHttp1),
            AutoProtocol.HTTP2 to AutoHandshakeProbe(::probeHttp2),
            AutoProtocol.HTTP3 to AutoHandshakeProbe(::probeHttp3),
        )

        private fun probeHttp1(
            endpoint: URL,
            verifyCertificates: Boolean,
            timeout: Duration,
        ): AutoProbeResult = timed(AutoProtocol.HTTP1) {
            val address = InetSocketAddress(endpoint.host, endpoint.portOrDefault())
            if (endpoint.protocol.equals("https", ignoreCase = true)) {
                openTlsSocket(address, verifyCertificates, timeout).use { socket ->
                    socket.startHandshake()
                }
            } else {
                Socket().use { socket ->
                    track(socket)
                    socket.connect(address, timeout.socketTimeoutMillis())
                }
            }
        }

        private fun probeHttp2(
            endpoint: URL,
            verifyCertificates: Boolean,
            timeout: Duration,
        ): AutoProbeResult = timed(AutoProtocol.HTTP2) {
            val address = InetSocketAddress(endpoint.host, endpoint.portOrDefault())
            openTlsSocket(address, verifyCertificates, timeout).use { socket ->
                val parameters = socket.sslParameters
                parameters.applicationProtocols = arrayOf("h2")
                socket.sslParameters = parameters
                socket.startHandshake()
                check(socket.applicationProtocol == "h2") {
                    "server did not negotiate h2"
                }
            }
        }

        private fun probeHttp3(
            endpoint: URL,
            verifyCertificates: Boolean,
            timeout: Duration,
        ): AutoProbeResult = timed(AutoProtocol.HTTP3) {
            val transport = ControlledKwikQuicTransport.connect(
                endpoint.host,
                endpoint.portOrDefault(),
                QuicConfig(timeout, timeout, verifyCertificates),
            )
            track(transport)
            try {
                val session = H3Connection.open(transport)
                track(session)
                session.use { }
            } finally {
                transport.close()
            }
        }

        private fun timed(protocol: AutoProtocol, block: () -> Unit): AutoProbeResult {
            val startedAt = System.nanoTime()
            return try {
                block()
                AutoProbeResult.success(
                    protocol,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt),
                )
            } catch (failure: Throwable) {
                AutoProbeResult.failure(protocol, failure.message ?: failure.javaClass.simpleName)
            }
        }

        private fun openTlsSocket(
            address: InetSocketAddress,
            verifyCertificates: Boolean,
            timeout: Duration,
        ): SSLSocket {
            val socket = sslSocketFactory(verifyCertificates).createSocket() as SSLSocket
            track(socket)
            try {
                socket.soTimeout = timeout.socketTimeoutMillis()
                socket.connect(address, timeout.socketTimeoutMillis())
                return socket
            } catch (failure: Throwable) {
                socket.close()
                throw failure
            }
        }

        private fun sslSocketFactory(verifyCertificates: Boolean): SSLSocketFactory =
            if (verifyCertificates) {
                SSLContext.getDefault().socketFactory
            } else {
                SSLContext.getInstance("TLS").apply {
                    init(null, arrayOf<TrustManager>(TrustAllCertificates), SecureRandom())
                }.socketFactory
            }

        private fun URL.portOrDefault(): Int = if (port == -1) defaultPort else port

        private fun Duration.socketTimeoutMillis(): Int =
            toMillis().coerceIn(1, Int.MAX_VALUE.toLong()).toInt()

        private fun <T : AutoCloseable> track(resource: T): T {
            currentExecution.get()?.track(resource)
            return resource
        }

        internal fun <T : AutoCloseable> trackForTest(resource: T): T = track(resource)
    }

    fun probe(
        endpoint: URL,
        verifyCertificates: Boolean,
        eligible: Set<AutoProtocol>,
    ): List<AutoProbeResult> {
        val protocols = admittedProtocols(endpoint, eligible)
        val deadlineNanos = System.nanoTime() + timeout.toNanos()
        val executions = protocols.associateWith { ProbeExecution() }
        val executor = Executors.newFixedThreadPool(protocols.size.coerceAtLeast(1)) { runnable ->
            Thread(runnable, "auto-protocol-probe").apply { isDaemon = true }
        }
        return try {
            protocols.forEach { protocol ->
                val execution = executions.getValue(protocol)
                val handshakeProbe = probes[protocol]
                executor.execute {
                    val result = if (!execution.start()) {
                        unavailable(protocol)
                    } else {
                        currentExecution.set(execution)
                        try {
                            handshakeProbe?.probe(endpoint, verifyCertificates, timeout) ?: unavailable(protocol)
                        } catch (failure: Throwable) {
                            AutoProbeResult.failure(
                                protocol,
                                failure.message ?: failure.javaClass.simpleName,
                            )
                        } finally {
                            currentExecution.remove()
                        }
                    }
                    execution.complete(result, deadlineNanos, handshakeProbe)
                }
            }
            protocols.map { protocol ->
                completedResult(protocol, probes[protocol], executions.getValue(protocol), deadlineNanos)
            }
        } finally {
            executor.shutdownNow()
        }
    }

    fun preferredStartable(results: List<AutoProbeResult>): List<AutoProtocol> =
        results.asSequence()
            .filter { it.succeeded }
            .map { it.protocol }
            .sortedBy { PREFERENCE.indexOf(it) }
            .toList()

    private fun admittedProtocols(endpoint: URL, eligible: Set<AutoProtocol>): List<AutoProtocol> =
        when (endpoint.protocol.lowercase()) {
            "https" -> AutoProtocol.entries.filter { it in eligible }
            "http" -> listOf(AutoProtocol.HTTP1).filter { it in eligible }
            else -> emptyList()
        }

    private fun completedResult(
        protocol: AutoProtocol,
        handshakeProbe: AutoHandshakeProbe?,
        execution: ProbeExecution,
        deadlineNanos: Long,
    ): AutoProbeResult = execution.resultCompletedBy(deadlineNanos)
        ?: timeout(protocol, handshakeProbe, execution)

    private fun timeout(
        protocol: AutoProtocol,
        handshakeProbe: AutoHandshakeProbe?,
        execution: ProbeExecution,
    ): AutoProbeResult {
        execution.cancel(handshakeProbe)
        return AutoProbeResult.failure(protocol, "probe timed out after ${timeout.toMillis()}ms")
    }

    private fun unavailable(protocol: AutoProtocol): AutoProbeResult =
        AutoProbeResult.failure(protocol, "no probe configured")

    private object TrustAllCertificates : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private class ProbeExecution {
        private data class Completion(val result: AutoProbeResult, val completedAtNanos: Long)

        private val cancelled = AtomicBoolean(false)
        private val cleanupHookScheduled = AtomicBoolean(false)
        private val resources = ConcurrentHashMap.newKeySet<AutoCloseable>()
        private val worker = AtomicReference<Thread?>()
        private val completion = AtomicReference<Completion?>()
        private val completionReady = CompletableFuture<Completion>()

        fun start(): Boolean {
            worker.set(Thread.currentThread())
            if (cancelled.get()) {
                Thread.currentThread().interrupt()
                return false
            }
            return true
        }

        fun track(resource: AutoCloseable) {
            resources += resource
            if (cancelled.get()) scheduleClose(resource)
        }

        fun cancel(handshakeProbe: AutoHandshakeProbe?) {
            cancelled.set(true)
            worker.get()?.interrupt()
            if (cleanupHookScheduled.compareAndSet(false, true)) {
                cleanupExecutor.execute { runCatching { handshakeProbe?.cancel() } }
            }
            resources.forEach(::scheduleClose)
        }

        fun complete(
            result: AutoProbeResult,
            deadlineNanos: Long,
            handshakeProbe: AutoHandshakeProbe?,
        ) {
            val completed = Completion(result, System.nanoTime())
            completion.compareAndSet(null, completed)
            completionReady.complete(completed)
            worker.set(null)
            if (cancelled.get() || completed.completedAtNanos > deadlineNanos) {
                cancel(handshakeProbe)
            } else {
                resources.clear()
            }
        }

        fun resultCompletedBy(deadlineNanos: Long): AutoProbeResult? {
            completion.get()?.let { completed ->
                return completed.result.takeIf { completed.completedAtNanos <= deadlineNanos }
            }
            val remainingNanos = deadlineNanos - System.nanoTime()
            if (remainingNanos > 0) {
                runCatching { completionReady.get(remainingNanos, TimeUnit.NANOSECONDS) }
            }
            val completed = completion.get() ?: return null
            return completed.result.takeIf { completed.completedAtNanos <= deadlineNanos }
        }

        private fun scheduleClose(resource: AutoCloseable) {
            if (!resources.remove(resource)) return
            cleanupExecutor.execute { runCatching { resource.close() } }
        }
    }

    private val PREFERENCE = listOf(AutoProtocol.HTTP3, AutoProtocol.HTTP2, AutoProtocol.HTTP1)
}
