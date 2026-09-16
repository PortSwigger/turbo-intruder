package http3

import burp.PreparedGateRelease
import burp.Request
import burp.StagedExchange
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * One gate's batch, staged on the one connection that gate holds.
 *
 * A gate claims a connection for its exclusive use, so the whole batch shares a single release and
 * a single edge. What that edge reaches is the server's own turnaround: it answers one
 * connection's requests in order, so the closest two it will put together is what it costs to
 * finish one and start the next, with the client nowhere in that loop.
 */
class SdaBatch(
    val gateName: String,
    /**
     * The connection this gate holds. Null for a gate that failed before it claimed one, which
     * still has to be answerable while its failure is reported.
     */
    val connection: GateConnection?,
) {
    /** How this batch will be released, resolved once when the gate claimed its connection. */
    val mode: GateMode = connection?.mode ?: GateMode.SDA

    private val staged = CopyOnWriteArrayList<StagedRequest>()
    private val failure = AtomicReference<Throwable?>(null)
    private val released = AtomicBoolean(false)

    /** The connection to stage on, which a gate that never claimed one does not have. */
    fun requireConnection(): GateConnection = checkNotNull(connection) { "Gate $gateName has no QUIC connection" }

    fun add(request: Request, exchange: StagedExchange) {
        check(!released.get()) { "Gate $gateName is already released" }
        staged.add(requireConnection().add(request, exchange))
    }

    /**
     * Gets the release ready and hands back the send. Null for a gate with nothing staged on it:
     * an empty release is a datagram of nothing, and firing it would still count as the race.
     *
     * Prepared here rather than at the release, because whatever the send needs building is time
     * the gate spends holding a batch the target already has.
     */
    fun release(options: SdaOptions): PreparedGateRelease? =
        connection?.takeIf { it.staged().isNotEmpty() }?.prepareRelease(options)

    fun fail(cause: Throwable) {
        failure.compareAndSet(null, cause)
    }

    fun throwIfFailed() {
        failure.get()?.let { cause ->
            throw IllegalStateException("HTTP/3 gate $gateName failed: ${cause.message}", cause)
        }
    }

    /**
     * Waits for the connection this gate staged on to put the batch on the wire.
     *
     * Staging only queues the bytes with the connection's sender. A release fired before that has
     * drained can reach the server ahead of the requests it completes, which are then answered as
     * their own prefixes land rather than all at once.
     */
    fun awaitStagedRequestsSent(drain: StageDrain) {
        connection?.takeIf { it.staged().isNotEmpty() }
            ?.let { staged -> drain.await { staged.session?.unackedBytes() } }
    }

    fun stagedExchanges(): List<StagedRequest> = staged.toList()

    fun markReleased() {
        check(released.compareAndSet(false, true)) { "Gate $gateName has already been opened" }
    }

    /**
     * Whether the batch got its release out without incident. Any other outcome leaves staged
     * request streams half-written on the connection, so it may not be reused.
     */
    fun releasedCleanly(): Boolean = released.get() && failure.get() == null
}
