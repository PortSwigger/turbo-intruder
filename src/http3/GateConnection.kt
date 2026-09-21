package http3

import burp.H3Session
import burp.PreparedGateRelease
import burp.Request
import burp.StagedExchange
import hp3.quic.AtomicStreamFrameBundle
import hp3.quic.StreamFragment
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * One of a gate's requests, the exchange that will answer it, and the connection it went out on.
 *
 * The connection travels with the request because every response is tabled against the one that
 * carried it, and the flat batch order says nothing about that.
 */
class StagedRequest(val request: Request, val exchange: StagedExchange, val connection: GateConnection)

/**
 * The connection a gate holds: what it may stage, what it has staged, and how it releases.
 *
 * Everything here belongs to that one connection because every bound here does. The datagram a
 * release fits in belongs to one path; the blocked streams a peer tolerates are counted per
 * connection; and the withheld bytes a release carries are frames for streams only that
 * connection has. A batch is therefore bounded by the connection it is staged on, and nothing
 * else.
 */
class GateConnection(
    val gateName: String,
    val session: H3Session?,
    /**
     * Identifies the QUIC connection the batch is staged on, so every request released on it
     * tables the same ID. Carried here rather than minted on the way out: a gate can inherit a
     * pooled connection and hand it back, and the ID has to survive that round trip or the same
     * connection would table under two different IDs.
     */
    val connectionId: String? = null,
    /** How the batch will be released, resolved once when the gate claimed this connection. */
    val mode: GateMode = GateMode.SDA,
    /**
     * The peer's QPACK limits, for a connection that will release on the encoder stream.
     *
     * Carried here rather than re-read at release time: the gate settled on these exact numbers
     * when it claimed the connection, and whatever bounds the batch has to be the same values
     * that chose the mode.
     */
    val qpackLimits: QpackGateLimits? = null,
    /**
     * How many requests this connection had already carried when the gate claimed it, so the
     * batch can be counted against requestsPerConnection along with everything before it.
     */
    val requestsCarried: Int = 0,
    /**
     * The most stream-frame bytes the release datagram will carry, read off the connection when
     * the gate claimed it. [Int.MAX_VALUE] where the session could not say, which bounds nothing
     * and leaves the release itself as the only check.
     */
    val releaseBudgetBytes: Int = Int.MAX_VALUE,
) {
    init {
        require(releaseBudgetBytes > 0) {
            "A release datagram that carries nothing cannot hold a gate, not $releaseBudgetBytes"
        }
        if (mode == GateMode.QPACK) {
            requireNotNull(qpackLimits) {
                "A QPACK gate is not resolved until the peer's limits are known"
            }
        } else {
            require(qpackLimits == null) {
                "Only a QPACK gate is bounded by the peer's QPACK limits, not $mode"
            }
        }
    }

    private val exchanges = CopyOnWriteArrayList<StagedRequest>()
    private val blockedStreamsReserved = AtomicLong()
    private val releaseBytesReserved = AtomicLong()
    private val releaseBudgetHolds = AtomicLong()

    /**
     * Takes one of the peer's blocked-stream allowances for a request that is about to be staged.
     *
     * RFC 9204 section 2.1.2: an encoder must not create more potentially blocked streams than
     * `SETTINGS_QPACK_BLOCKED_STREAMS`. Past that the peer is entitled to treat the next field
     * section it cannot decode as a connection error rather than something to wait on, which takes
     * the whole batch down with it. Reserved before the request is written rather than counted
     * after, because by then the stream exists and the overrun has already happened.
     *
     * An oversized gate fails here. It is deliberately not split across several releases and not
     * downgraded to a datagram: either would quietly change the race the run asked for — a split
     * batch no longer shares one edge, and a downgrade only holds if the server reads the body. A
     * batch this connection cannot hold is refused rather than reshaped.
     *
     * The count is per connection. SDA requests do not blocked-stream, and neither do ordinary
     * compression references to entries the peer has already acknowledged.
     */
    fun reserveBlockedStream() {
        val limits = checkNotNull(qpackLimits) { "Gate $gateName has no QPACK limits to reserve against" }
        val reserved = blockedStreamsReserved.incrementAndGet()
        check(reserved <= limits.maxBlockedStreams) {
            "HTTP/3 gate $gateName race requested $reserved QPACK-blocked streams on one " +
                "connection, but the peer advertised " +
                "SETTINGS_QPACK_BLOCKED_STREAMS=${limits.maxBlockedStreams}. The gate was not " +
                "released. Queue at most ${limits.maxBlockedStreams} requests in one gate."
        }
    }

    /**
     * Takes release-datagram budget for a request that has just been staged.
     *
     * The mirror of [reserveBlockedStream] for the mode whose ceiling is a datagram rather than
     * the peer's SETTINGS. Charged against the fragment the stage actually produced, because what
     * a request costs the release depends on its stream ID and offset, and both are only settled
     * once the stream exists.
     *
     * An oversized gate fails here rather than at the release, and for the same reason the QPACK
     * gate fails closed: a batch split across two datagrams on one connection no longer shares one
     * edge, so it is not the race the run asked for. Failing at the first request that will not fit
     * is what stops the rest of the batch being written to a target for a release that is never
     * sent — which costs nothing on an idle server and costs the next race as well as this one on
     * a server that throttles a burst.
     */
    fun reserveReleaseBytes(fragment: StreamFragment?) {
        check(mode != GateMode.QPACK) {
            "Gate $gateName releases on the QPACK encoder stream, so its batch is bounded by " +
                "blocked streams rather than by a datagram"
        }
        val fitted = releaseBudgetHolds.get()
        val used = releaseBytesReserved.addAndGet(
            (fragment?.let { AtomicStreamFrameBundle.frameLengthOf(it) } ?: 0).toLong(),
        )
        check(used <= releaseBudgetBytes) {
            "HTTP/3 gate $gateName asked for more requests than one release datagram carries: " +
                "the release needs $used bytes of stream frames and this connection's datagram " +
                "holds $releaseBudgetBytes, so this connection stops at $fitted requests. The " +
                "gate was not released. Queue a batch of $fitted, or use " +
                "gateMode='qpack' where the server advertises QPACK_MAX_TABLE_CAPACITY and " +
                "QPACK_BLOCKED_STREAMS — that gate is bounded by the blocked-stream count the " +
                "peer states rather than by a datagram, so it carries far more racers."
        }
        releaseBudgetHolds.incrementAndGet()
    }

    /** How many requests this connection's release datagram is currently holding budget for. */
    fun requestsReleaseBudgetHolds(): Int = releaseBudgetHolds.get().toInt()

    fun add(request: Request, exchange: StagedExchange): StagedRequest =
        StagedRequest(request, exchange, this).also(exchanges::add)

    fun staged(): List<StagedRequest> = exchanges.toList()

    /** The bytes this connection withheld, which its release puts on the wire in one datagram. */
    fun fragments(): List<StreamFragment> = exchanges.mapNotNull { it.exchange.fragment }

    /**
     * Gets this connection's release ready, and hands back the send.
     *
     * Everything the release needs building is time the gate spends holding a batch the target
     * already has, so preparing is separate from firing and only the send is left for the instant
     * itself.
     */
    fun prepareRelease(options: SdaOptions): PreparedGateRelease {
        val connection = checkNotNull(session) { "Gate $gateName has no QUIC connection to release" }
        return if (mode == GateMode.QPACK) {
            connection.prepareBlockedRelease()
        } else {
            connection.prepareRelease(fragments(), options)
        }
    }
}
