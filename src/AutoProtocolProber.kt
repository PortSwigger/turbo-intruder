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
import java.util.concurrent.atomic.AtomicLong
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
    internal val timeout: Duration = Duration.ofSeconds(12),
) {
    init {
        require(!timeout.isZero && !timeout.isNegative) { "probe timeout must be positive" }
    }

    companion object {
        private val currentExecution = ThreadLocal<ProbeExecution?>()
        private val cleanupExecutor = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "auto-protocol-probe-cleanup").apply { isDaemon = true }
        }
        private val sharedCache = AutoProtocolProbeCache(Duration.ofSeconds(60))

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

    /**
     * Reuses recent handshake outcomes across AUTO engines in this extension classloader. The
     * cache contains only protocol availability; every fuzz still creates a fresh request engine
     * and fresh transport connections.
     */
    fun probeCached(
        endpoint: URL,
        verifyCertificates: Boolean,
        eligible: Set<AutoProtocol>,
    ): List<AutoProbeResult> = sharedCache.probe(this, endpoint, verifyCertificates, eligible)

    fun preferredStartable(results: List<AutoProbeResult>): List<AutoProtocol> =
        results.asSequence()
            .filter { it.succeeded }
            .map { it.protocol }
            .sortedBy { PREFERENCE.indexOf(it) }
            .toList()

    internal fun admittedProtocols(endpoint: URL, eligible: Set<AutoProtocol>): List<AutoProtocol> =
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

/**
 * A per-protocol, single-flight TTL cache. The production instance is static on
 * [AutoProtocolProber], so separate Jython interpreters and RequestEngine instances reuse it while
 * the extension remains loaded. Tests can construct an isolated cache with a controlled clock.
 */
internal class AutoProtocolProbeCache(
    private val ttl: Duration,
    private val nanoTime: () -> Long = System::nanoTime,
    private val maxEntries: Int = 1024,
) {
    private data class Key(
        val scheme: String,
        val host: String,
        val port: Int,
        val verifyCertificates: Boolean,
        val timeoutNanos: Long,
        val protocol: AutoProtocol,
    )

    private class Entry {
        val result = CompletableFuture<AutoProbeResult>()

        @Volatile
        var expiresAtNanos: Long = Long.MAX_VALUE

        fun reusableAt(nowNanos: Long): Boolean = !result.isDone || nowNanos < expiresAtNanos

        fun expiredAt(nowNanos: Long): Boolean = result.isDone && nowNanos >= expiresAtNanos

    }

    /** Completed TTL entries are bounded; live flights are transient and coalesced separately. */
    private val entries = ConcurrentHashMap<Key, Entry>()
    private val inFlight = HashMap<Key, Entry>()
    private val admissionLock = Object()
    private val nextSweepNanos = AtomicLong(Long.MIN_VALUE)
    private val ttlNanos: Long

    init {
        require(!ttl.isZero && !ttl.isNegative) { "probe cache TTL must be positive" }
        require(maxEntries > 0) { "probe cache capacity must be positive" }
        ttlNanos = ttl.toNanos()
    }

    fun probe(
        prober: AutoProtocolProber,
        endpoint: URL,
        verifyCertificates: Boolean,
        eligible: Set<AutoProtocol>,
    ): List<AutoProbeResult> {
        val protocols = prober.admittedProtocols(endpoint, eligible)
        if (protocols.isEmpty()) return emptyList()

        val now = nanoTime()
        sweepExpired(now)
        val selected = LinkedHashMap<AutoProtocol, Pair<Key, Entry>>(protocols.size)
        val claimed = LinkedHashMap<AutoProtocol, Pair<Key, Entry>>()

        protocols.forEach { protocol ->
            val key = Key(
                endpoint.protocol.lowercase(),
                endpoint.host.lowercase(),
                if (endpoint.port == -1) endpoint.defaultPort else endpoint.port,
                verifyCertificates,
                prober.timeout.toNanos(),
                protocol,
            )
            val (entry, owner) = selectEntry(key, now)
            selected[protocol] = key to entry
            if (owner) {
                claimed[protocol] = key to entry
            }
        }

        if (claimed.isNotEmpty()) {
            try {
                val fresh = prober.probe(endpoint, verifyCertificates, claimed.keys)
                    .associateBy { it.protocol }
                val expiresAt = deadlineAfter(nanoTime(), ttlNanos)
                claimed.forEach { (protocol, keyedEntry) ->
                    val result = fresh[protocol]
                        ?: AutoProbeResult.failure(protocol, "probe returned no result")
                    publish(keyedEntry.first, keyedEntry.second, result, expiresAt)
                }
            } catch (failure: Throwable) {
                claimed.values.forEach { (key, entry) ->
                    failFlight(key, entry, failure)
                }
                throw failure
            }
        }

        return protocols.map { protocol -> selected.getValue(protocol).second.result.join() }
    }

    /**
     * Reuses or atomically claims one key. In-progress entries live in a separate transient map,
     * so cache-capacity pressure can neither evict nor duplicate a live handshake.
     */
    private fun selectEntry(key: Key, nowNanos: Long): Pair<Entry, Boolean> =
        synchronized(admissionLock) {
            entries[key]?.let { current ->
                if (current.reusableAt(nowNanos)) return@synchronized current to false
                entries.remove(key, current)
            }

            inFlight[key]?.let { return@synchronized it to false }

            Entry().let { replacement ->
                inFlight[key] = replacement
                replacement to true
            }
        }

    private fun publish(
        key: Key,
        entry: Entry,
        value: AutoProbeResult,
        expiresAtNanos: Long,
    ) = synchronized(admissionLock) {
        if (!inFlight.remove(key, entry)) return@synchronized
        if (entries.size >= maxEntries) {
            val victim = entries.entries.minByOrNull { it.value.expiresAtNanos }
            if (victim != null) entries.remove(victim.key, victim.value)
        }
        entry.expiresAtNanos = expiresAtNanos
        entries[key] = entry
        // Complete only after the entry is visible in the TTL map. A released waiter that starts
        // another fuzz immediately therefore cannot fall through the gap and claim a new flight.
        entry.result.complete(value)
    }

    private fun failFlight(key: Key, entry: Entry, failure: Throwable) =
        synchronized(admissionLock) {
            if (inFlight.remove(key, entry)) entry.result.completeExceptionally(failure)
        }

    private fun sweepExpired(nowNanos: Long) {
        while (true) {
            val scheduled = nextSweepNanos.get()
            if (scheduled != Long.MIN_VALUE && nowNanos < scheduled) return
            if (nextSweepNanos.compareAndSet(scheduled, deadlineAfter(nowNanos, ttlNanos))) break
        }
        synchronized(admissionLock) {
            entries.forEach { (key, entry) ->
                if (entry.expiredAt(nowNanos)) entries.remove(key, entry)
            }
        }
    }

    private fun deadlineAfter(nowNanos: Long, durationNanos: Long): Long =
        if (nowNanos > Long.MAX_VALUE - durationNanos) Long.MAX_VALUE else nowNanos + durationNanos
}
