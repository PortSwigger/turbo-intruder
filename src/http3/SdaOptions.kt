package http3

/**
 * How a gate holds its batch and how it lets go of it.
 *
 * Only [stageDelayMillis] is reachable from a script. The other two are settings in the sense that
 * the code can vary them, not in the sense that a run has anything to gain by it, so they are
 * fixed here rather than offered on `RequestEngine()`.
 */
data class SdaOptions(
    /**
     * The largest release datagram to build. Clamped on the way out to the connection's own packet
     * size, so [PATH_MAXIMUM] resolves to whatever that connection carries.
     *
     * Fixed at that maximum. The clamp means the connection's number governs whatever is asked
     * for, so the only reachable direction was smaller — which buys nothing and costs racers.
     */
    val maxDatagramSize: Int = PATH_MAXIMUM,
    /**
     * The longest a gate will wait for its staged batch to leave before releasing anyway.
     *
     * A safety net, not a tuned number. It only binds on a connection whose sender never goes
     * quiet, and a batch sharing its connection with that much other traffic has already lost the
     * race it was staged for.
     */
    val stageWaitCapMillis: Long = 2000,
    /**
     * What a gate waits when its connection cannot report progress at all — an in-memory session,
     * or a transport that is not Kwik.
     *
     * The old fixed delay, kept for exactly the case the adaptive wait cannot serve. Measured
     * against a server 19ms away it was generous for a batch of 10 by a factor of twenty, and
     * about right for a batch of 100.
     */
    val stageFallbackMillis: Long = 100,
    /**
     * Bytes withheld from the end of each staged request, which the release puts on the wire.
     *
     * Fixed at one. Zero is the only other value with a use — it withholds the FIN alone — and a
     * request missing only its FIN is a complete request, which nearly every HTTP/3 server answers
     * without waiting. Measured, it buys exactly one byte of release datagram per request, about
     * 15% more racers, in exchange for the gate not holding at all on any server that does not
     * wait for the FIN. More than one byte withholds more of the same tail for no further gain.
     */
    val finalBytes: Int = 1,
    /**
     * Retransmissions of the release if the peer reports it lost.
     *
     * Fixed at none. A retransmission goes out a PTO after the loss is detected, by which point
     * the window the batch was aimed at has closed: the requests still get answered, but as
     * ordinary traffic rather than as a race, and the run would be told it raced. Losing the batch
     * and saying so is the more honest outcome. The staged response deadline starts once the
     * original release is confirmed sent, so a lost release fails the batch instead of leaving
     * its readers parked. The transport keeps the capability, which its own tests cover.
     */
    val retransmissions: Int = 0,
) {
    companion object {
        /**
         * Ask for as much as the path will carry.
         *
         * The cap exists to stop a release being split across datagrams, and what would split it
         * is the connection's own packet size — measured against a real path, Kwik put that at
         * 1252 bytes and sends every other packet on the connection at it. Capping the release
         * below that number is conservative against nothing and costs about eight requests out of
         * a batch of two hundred, which is eight fewer racers in the batch.
         */
        const val PATH_MAXIMUM = 65527
    }

    init {
        require(maxDatagramSize in 1..PATH_MAXIMUM) { "maxDatagramSize must be between 1 and $PATH_MAXIMUM" }
        require(stageWaitCapMillis >= 0) { "stageWaitCapMillis must be non-negative" }
        require(stageFallbackMillis >= 0) { "stageFallbackMillis must be non-negative" }
        require(retransmissions >= 0) { "retransmissions must be non-negative" }
        require(finalBytes >= 0) { "finalBytes must be non-negative" }
    }
}
