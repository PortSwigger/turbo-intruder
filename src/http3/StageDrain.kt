package http3

/**
 * Waits for the peer to acknowledge a staged batch, so a release goes out behind the requests it
 * completes rather than past them.
 *
 * Staging a request writes it into Kwik's send buffer and returns — the stream's own `flush()` is
 * a no-op — so when the last request has been staged the batch may not have reached the server at
 * all. A release fired then can arrive ahead of the requests it completes, and each one is
 * answered when its own prefix lands instead of at the release. Measured against a real server,
 * releasing with no wait cost a gate of ten requests three times its arrival spread.
 *
 * What is waited on is the count of bytes sent and not yet acknowledged reaching zero, which is
 * the only signal that actually says the batch arrived. Two nearer-looking signals do not:
 * `dataBytesSent` is already at the full staged total by the time the last stage() returns, since
 * Kwik counts a byte when it packs it rather than when the peer has it; and a sender that has gone
 * quiet is indistinguishable from one that has not started. Measured on a 100-request batch, the
 * unacknowledged count held at its staged value for 17ms and then dropped to zero in one step.
 *
 * Waiting for the acknowledgement also means the wait sizes itself. It is a round trip plus the
 * peer's ack delay after the last packet leaves, so a bigger batch and a longer path each extend
 * it without anyone choosing a number.
 */
class StageDrain(
    /**
     * The longest this will ever wait. A safety net rather than a tuned number: it only binds when
     * a peer never acknowledges, and a batch on a connection that far gone has already lost the
     * race it was staged for.
     */
    private val capMillis: Long,
    /**
     * Given to a connection that cannot report unacknowledged bytes at all — an in-memory session,
     * or a transport that is not Kwik.
     *
     * This is the fixed delay the gate used to always take. It is kept for exactly the case the
     * signal cannot serve, rather than as a number anyone is expected to pick.
     */
    private val noSignalWaitMillis: Long,
    private val clock: () -> Long = System::nanoTime,
    private val sleep: (Long) -> Unit = { Thread.sleep(it) },
) {
    /**
     * Blocks until [unackedBytes] reports nothing outstanding, or the cap is reached. Returns how
     * long that took, in milliseconds.
     */
    fun await(unackedBytes: () -> Long?): Long {
        if (unackedBytes() == null) {
            sleep(noSignalWaitMillis)
            return noSignalWaitMillis
        }

        val startNanos = clock()
        var everOutstanding = false
        while (true) {
            val elapsedMillis = millisSince(startNanos)
            if (elapsedMillis >= capMillis) {
                return elapsedMillis
            }
            // A connection that stops answering mid-wait is one the release is about to fail on
            // anyway, so this stops waiting rather than holding the batch for the whole cap.
            val outstanding = unackedBytes() ?: return elapsedMillis
            if (outstanding > 0L) {
                everOutstanding = true
            } else if (everOutstanding || elapsedMillis >= START_GRACE_MILLIS) {
                return elapsedMillis
            }
            sleep(POLL_MILLIS)
        }
    }

    private fun millisSince(nanos: Long): Long = (clock() - nanos) / 1_000_000

    companion object {
        private const val POLL_MILLIS = 1L

        /**
         * How long nothing outstanding is treated as the sender not having started rather than the
         * peer having everything.
         *
         * Zero in flight has both meanings and no way to tell them apart from the count alone.
         * Measured, a 100-request batch read as zero on the first poll — Kwik had not packed the
         * staged frames yet — and releasing on that answer cost the gate a third of its tightness.
         * So a zero is only believed once something has been seen in flight, or once this has
         * passed without anything appearing, which is the case of a batch small enough to have
         * been acknowledged already.
         */
        private const val START_GRACE_MILLIS = 5L
    }
}
