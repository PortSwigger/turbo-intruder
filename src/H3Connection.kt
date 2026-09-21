package burp

import hp3.h3.Http3ClientConnection
import hp3.h3.Http3Exception
import hp3.h3.Http3Settings
import hp3.quic.QuicStream
import hp3.quic.SdaCapableQuicTransport
import hp3.quic.StreamFragment
import http3.FirstByteTimingInputStream
import http3.QpackGateLimits
import http3.SdaOptions
import http3.SdaStagingPlanner
import http3.TurboHttp3Request
import http3.TurboHttp3ResponseRenderer
import java.io.BufferedInputStream
import java.io.IOException
import java.net.URL
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * A rendered response together with the moment its first byte arrived. The two timings are
 * separate measurements, so they are carried separately rather than recomputed from the point the
 * response finished assembling.
 */
class H3Exchange(
    val response: ByteArray,
    val firstByteNanos: Long,
    val lastByteNanos: Long,
)

/** A gate release with all preparation complete; [send] returns its confirmed send time. */
fun interface PreparedGateRelease {
    @Throws(IOException::class)
    fun send(): Long

    operator fun invoke(): Long = send()
}

interface H3Session : AutoCloseable {
    fun send(request: TurboHttp3Request): H3Exchange
    fun stage(request: TurboHttp3Request, finalBytes: Int): StagedExchange
    fun release(fragments: List<StreamFragment>, options: SdaOptions)
    fun isConnected(): Boolean

    /**
     * Sends a complete request whose field section the peer cannot decode until
     * [releaseBlocked]. Unlike [stage], nothing is withheld from the wire: the request arrives
     * whole and waits in the peer's decoder, so a batch is not bounded by a datagram.
     */
    fun stageBlocked(request: TurboHttp3Request): StagedExchange =
        throw UnsupportedOperationException("this session cannot hold its QPACK encoder stream")

    /** Unblocks every request staged by [stageBlocked] on this session, in one write. */
    fun releaseBlocked(): Unit =
        throw UnsupportedOperationException("this session cannot hold its QPACK encoder stream")

    /**
     * Works out everything [release] can work out in advance, and hands back what is left.
     *
     * <p>Whatever a release does before its send is time the gate spends holding a batch the
     * target already has, and the window being aimed at is far finer than that work. So a release
     * that can be built beforehand should be, leaving only the send for the instant itself.
     *
     * <p>The default defers the whole thing, which is right for a session with nothing to hoist.
     */
    fun prepareRelease(fragments: List<StreamFragment>, options: SdaOptions): PreparedGateRelease =
        PreparedGateRelease {
            release(fragments, options)
            System.nanoTime()
        }

    /** The same for [releaseBlocked], whose release is one already-encoded instruction. */
    fun prepareBlockedRelease(): PreparedGateRelease = PreparedGateRelease {
        releaseBlocked()
        System.nanoTime()
    }

    /**
     * The QPACK limits the peer advertised, waiting up to [timeoutMillis] for its SETTINGS to
     * arrive, or null if it did not advertise usable ones.
     *
     * <p>Both halves are required. Without dynamic table capacity there is no entry to reference,
     * and a peer that tolerates zero blocked streams treats a field section it cannot decode as a
     * connection error rather than something to wait on.
     *
     * <p>The exact values come back rather than a verdict, because both of them bound the gate
     * later: the capacity decides whether the chosen entry fits, and the blocked-stream count caps
     * how many requests one gate may stage.
     */
    fun awaitQpackGateLimits(timeoutMillis: Long): QpackGateLimits? = null

    /**
     * The most stream-frame bytes one [release] will carry on this connection, given the caller's
     * own ceiling.
     *
     * <p>The datagram gate's batch is bounded by this and nothing else, and a batch races as
     * tightly as the number of requests it releases together — so the bound has to be readable
     * while the batch is being built, not discovered when the release is refused. By then every
     * request is already on the wire for a race that will never be sent.
     *
     * <p>[Int.MAX_VALUE] from a session that cannot say, which bounds nothing.
     */
    fun releaseDatagramBudget(maxDatagramSize: Int): Int = Int.MAX_VALUE

    /**
     * Bytes sent on this connection that the peer has not acknowledged, or null from a session
     * that cannot tell.
     *
     * <p>A gate waits for this to reach zero between staging its batch and releasing it. Staging
     * only queues the bytes with the sender, so a release fired the instant the last request is
     * staged can reach the server ahead of the requests it completes.
     */
    fun unackedBytes(): Long? = null

    /**
     * Fails every response read on this session whose deadline has passed as of [nowNanos],
     * returning how many were failed. Zero from a session that does not bound its reads.
     */
    fun failOverdueReads(nowNanos: Long): Int = 0
}

fun interface H3ConnectionFactory {
    fun open(target: URL, verifyCertificates: Boolean): H3Session
}

class H3Connection private constructor(
    private val transport: SdaCapableQuicTransport,
    private val client: Http3ClientConnection,
    private val responseTimeoutMillis: Long,
) : H3Session {
    companion object {
        /** One QUIC stream's worth of response in a single bulk read, in the common case. */
        private const val RESPONSE_BUFFER_BYTES = 8192

        /** How long a blocked stage waits for the settings that decide whether it can block. */
        private const val SETTINGS_WAIT_MILLIS = 1000L

        /** Sentinel for a staged read whose gate has not released it yet. */
        private const val UNARMED_RESPONSE_DEADLINE = Long.MIN_VALUE

        /**
         * How long one request waits for its whole response before the read is failed. Kwik's own
         * per-read bound is Long.MAX_VALUE with no setter, so without this a lost response parks
         * its thread forever.
         */
        const val DEFAULT_RESPONSE_TIMEOUT_MILLIS = 30_000L

        @JvmStatic
        @JvmOverloads
        fun open(
            transport: SdaCapableQuicTransport,
            responseTimeoutMillis: Long = DEFAULT_RESPONSE_TIMEOUT_MILLIS,
        ): H3Connection =
            H3Connection(transport, Http3ClientConnection.open(transport), responseTimeoutMillis)
    }

    /** Response reads in progress, and the moment each one stops being worth waiting for. */
    private val pendingReads = ConcurrentHashMap.newKeySet<PendingRead>()

    override fun unackedBytes(): Long? = transport.unackedBytes()

    override fun send(request: TurboHttp3Request): H3Exchange {
        val stream = client.openRequestStream()
        client.writeRequest(stream, request.request)
        return readWithinDeadline(stream, request.authoredVersion)
    }

    /**
     * Reads a response, giving up on it once [responseTimeoutMillis] has passed.
     *
     * <p>An ordinary request starts its deadline here. A staged request is read by a thread
     * started before its gate is opened, so it is registered here without a deadline and armed
     * from the confirmed release time by [StagedExchange.startResponseDeadline].
     *
     * <p>The deadline is enforced by whoever calls [failOverdueReads], not by a timer armed per
     * request. This is the path every request takes, and a scheduled task each would put all of
     * them through the one lock inside a scheduler's delay queue; registering costs a hash insert
     * and a removal instead.
     */
    private fun readWithinDeadline(stream: QuicStream, authoredVersion: String): H3Exchange {
        if (responseTimeoutMillis <= 0) {
            return readExchange(stream.input(), stream.id(), authoredVersion)
        }
        val pending = PendingRead(
            stream,
            System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(responseTimeoutMillis),
        )
        pendingReads.add(pending)
        try {
            return readExchange(stream.input(), stream.id(), authoredVersion)
        } finally {
            pendingReads.remove(pending)
        }
    }

    override fun failOverdueReads(nowNanos: Long): Int {
        var failed = 0
        pendingReads.forEach { pending ->
            val deadlineNanos = pending.deadlineNanos.get()
            // A subtraction rather than a comparison, so that a nanoTime origin which has wrapped
            // does not read as every deadline being in the past.
            if (
                deadlineNanos != UNARMED_RESPONSE_DEADLINE &&
                nowNanos - deadlineNanos >= 0 &&
                pendingReads.remove(pending)
            ) {
                // STOP_SENDING. Kwik marks the stream closed and interrupts its blocked reader,
                // which loops back to the top of read() and throws, so the request fails and the
                // thread carrying it is let go. Guarded because a stream on a connection that has
                // already gone will refuse this, and the read is dead either way.
                runCatching { pending.stream.stopSending(Http3Exception.H3_REQUEST_CANCELLED) }
                failed += 1
            }
        }
        return failed
    }

    override fun stage(request: TurboHttp3Request, finalBytes: Int): StagedExchange {
        val stream = client.openRequestStream()
        val plan = SdaStagingPlanner.plan(request.request, finalBytes)
        stream.output().write(plan.stagedBytes)
        stream.output().flush()
        val streamId = stream.id()
        require(streamId in 0..Int.MAX_VALUE.toLong()) { "Kwik stream ID is outside the supported range: $streamId" }
        val fragment = StreamFragment(
            streamId.toInt(),
            plan.releaseOffset,
            plan.releaseBytes,
            plan.fin,
        )
        val response = CompletableFuture<H3Exchange>()
        val pending = PendingRead(stream, UNARMED_RESPONSE_DEADLINE)
        pendingReads.add(pending)
        // This reader blocks in Kwik's stream input stream, which reads inside a synchronized
        // block. A gate stages every request before releasing, so all of a batch's readers are
        // blocked at once, and on a JDK that pins them a batch larger than the carrier pool would
        // leave most of its responses unread.
        kwikBlockingThread("h3-response-$streamId").start {
            try {
                response.complete(readExchange(stream.input(), streamId, request.authoredVersion))
            } catch (exception: Throwable) {
                response.completeExceptionally(exception)
            } finally {
                pendingReads.remove(pending)
            }
        }
        return StagedExchange(stream, fragment, response) { releasedAtNanos ->
            armStagedDeadline(pending, releasedAtNanos)
        }
    }

    override fun stageBlocked(request: TurboHttp3Request): StagedExchange {
        // Held before a single byte of the request is written: an instruction that leaves ahead of
        // the field section referencing it would decode on arrival and gate nothing.
        client.holdEncoderStream()
        // The encoder can only reference an entry once the peer has said it offers a table, so a
        // request staged ahead of its SETTINGS goes out plainly decodable and is answered at once.
        // Nearly always already satisfied: the engine settles the gate mode on these same settings
        // before staging anything, and this is a latch read once they have landed.
        val settings = client.awaitPeerSettings(SETTINGS_WAIT_MILLIS, TimeUnit.MILLISECONDS)
        // Verified rather than assumed. A peer whose SETTINGS never arrived looks identical here to
        // one that offers no table, and in both cases the encoder silently falls back to spelling
        // every field out — which sends the batch ungated and reports an untested race as safe.
        //
        // Deliberately not "capacity >= 32": whether this request's entry fits is a question about
        // the request, and encodeBlockedRequest answers it exactly.
        check(
            settings.get(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 0) > 0 &&
                settings.get(Http3Settings.QPACK_BLOCKED_STREAMS, 0) > 0,
        ) {
            "Cannot hold a QPACK gate on this connection: the peer offered no dynamic table " +
                "capacity (QPACK_MAX_TABLE_CAPACITY) or tolerates no blocked streams " +
                "(QPACK_BLOCKED_STREAMS), so there is no insertion to block a field section on " +
                "and the batch would be sent ungated."
        }
        // Encoded before the stream exists, so a request the gate cannot block leaves nothing
        // half-open behind it. Everything that can fail is settled by this call.
        val message = client.encodeBlockedRequest(request.request)
        val stream = client.openRequestStream()
        try {
            client.writeBlockedRequest(stream, message)
        } catch (exception: Throwable) {
            // The stream carries a partial request or none at all; either way the peer must not be
            // left waiting on it while the rest of the batch is released.
            runCatching { stream.resetStream(Http3Exception.H3_REQUEST_CANCELLED) }
            throw exception
        }
        val streamId = stream.id()
        val response = CompletableFuture<H3Exchange>()
        val pending = PendingRead(stream, UNARMED_RESPONSE_DEADLINE)
        pendingReads.add(pending)
        // Same thread choice and reasoning as stage(): every reader in a batch blocks at once.
        kwikBlockingThread("h3-response-$streamId").start {
            try {
                response.complete(readExchange(stream.input(), streamId, request.authoredVersion))
            } catch (exception: Throwable) {
                response.completeExceptionally(exception)
            } finally {
                pendingReads.remove(pending)
            }
        }
        return StagedExchange(stream, null, response) { releasedAtNanos ->
            armStagedDeadline(pending, releasedAtNanos)
        }
    }

    override fun releaseBlocked() {
        prepareBlockedRelease().send()
    }

    override fun prepareBlockedRelease(): PreparedGateRelease {
        // Checked and snapshotted here, so the gate's instant holds the encoder-stream write and
        // nothing else — and a gate that withheld the wrong thing fails while its release is being
        // built rather than at the instant it is fired.
        val prepared = client.prepareEncoderStreamRelease()
        return PreparedGateRelease {
            prepared.send()
            System.nanoTime()
        }
    }

    override fun awaitQpackGateLimits(timeoutMillis: Long): QpackGateLimits? {
        val settings = client.awaitPeerSettings(timeoutMillis, TimeUnit.MILLISECONDS)
        val capacity = settings.get(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 0)
        val blockedStreams = settings.get(Http3Settings.QPACK_BLOCKED_STREAMS, 0)
        // Deliberately not "capacity >= 32": the smallest useful entry is 32 octets plus a name
        // and a value, so whether the gate's entry fits depends on the request. That is checked
        // per request, against the capacity carried here.
        if (capacity <= 0 || blockedStreams <= 0) {
            return null
        }
        return QpackGateLimits(capacity, blockedStreams)
    }

    override fun release(fragments: List<StreamFragment>, options: SdaOptions) {
        prepareRelease(fragments, options).send()
    }

    override fun prepareRelease(
        fragments: List<StreamFragment>,
        options: SdaOptions,
    ): PreparedGateRelease {
        // Built, sized against the path and checked here, so the gate's instant holds the send and
        // nothing else. A batch too large for one datagram also fails here rather than at the
        // release, where the throw would land with the batch already staged against the target.
        val prepared = transport.prepareSingleDatagram(
            fragments,
            options.maxDatagramSize,
            options.retransmissions,
        )
        return PreparedGateRelease { prepared.send() }
    }

    override fun releaseDatagramBudget(maxDatagramSize: Int): Int =
        transport.singleDatagramFrameBudget(maxDatagramSize)

    private fun armStagedDeadline(pending: PendingRead, releasedAtNanos: Long) {
        if (responseTimeoutMillis > 0) {
            pending.deadlineNanos.set(
                releasedAtNanos + TimeUnit.MILLISECONDS.toNanos(responseTimeoutMillis),
            )
        }
    }

    private fun readExchange(input: java.io.InputStream, streamId: Long, authoredVersion: String): H3Exchange {
        val timed = FirstByteTimingInputStream(input)
        // Buffered above the timer, not below it. Every HTTP/3 frame type and length is a varint,
        // which VarInt.read pulls a byte at a time, and a single-byte read on a Kwik stream
        // allocates a byte[1], takes an Instant and enters the monitor the packet-processing thread
        // is notifying on. Kwik returns whatever bytes have arrived rather than filling the buffer,
        // so the timer still sees the first byte the moment it lands.
        val response = client.readResponse(BufferedInputStream(timed, RESPONSE_BUFFER_BYTES), streamId)
        val lastByteNanos = System.nanoTime()
        return H3Exchange(
            TurboHttp3ResponseRenderer.render(response, authoredVersion),
            timed.firstByteNanos,
            lastByteNanos,
        )
    }

    override fun isConnected(): Boolean = client.isConnected()

    override fun close() {
        client.close()
    }

    /** One response read in progress. Identity is the key, so no equals or hashCode of its own. */
    private class PendingRead(val stream: QuicStream, deadlineNanos: Long) {
        val deadlineNanos = AtomicLong(deadlineNanos)
    }
}

class StagedExchange internal constructor(
    val stream: QuicStream,
    /** The bytes withheld for a single-datagram release, or null for a QPACK-blocked stage. */
    val fragment: StreamFragment?,
    private val response: CompletableFuture<H3Exchange>,
    private val deadlineStarter: (Long) -> Unit = {},
) {
    /** Starts this staged response's timeout from the instant its gate release reached the wire. */
    fun startResponseDeadline(releasedAtNanos: Long) {
        deadlineStarter(releasedAtNanos)
    }

    /**
     * Fails a response read that has not completed, releasing a collector parked in
     * [awaitResponse], then sends STOP_SENDING so the producer parked inside Kwik exits too.
     * Closing the connection does not reliably release that read. A no-op once the response has
     * arrived.
     */
    fun fail(cause: Throwable) {
        if (response.completeExceptionally(cause)) {
            runCatching { stream.stopSending(Http3Exception.H3_REQUEST_CANCELLED) }
        }
    }

    @Throws(IOException::class)
    fun awaitResponse(): H3Exchange {
        return try {
            response.join()
        } catch (exception: CompletionException) {
            val cause = exception.cause
            if (cause is IOException) {
                throw cause
            }
            throw exception
        }
    }
}
