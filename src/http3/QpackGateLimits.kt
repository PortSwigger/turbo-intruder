package http3

/**
 * What the peer's QPACK decoder said it will accept, RFC 9204 section 3.2.3 and section 2.1.2.
 *
 * Both numbers bound a gate, and neither is a yes-or-no. [maxTableCapacity] decides whether the
 * entry a gate wants to withhold fits at all — an entry costs 32 octets plus its name and value,
 * so the answer depends on the request, not just the connection. [maxBlockedStreams] is the hard
 * ceiling on how many requests one gate may hold: an encoder that exceeds it has broken the
 * protocol, and the peer is entitled to close the connection rather than wait.
 *
 * Absent limits are represented by a null [QpackGateLimits] rather than by zeroes, so nothing
 * downstream can mistake "the peer declined" for "a bound of zero".
 */
data class QpackGateLimits(
    val maxTableCapacity: Long,
    val maxBlockedStreams: Long,
) {
    init {
        require(maxTableCapacity > 0) {
            "QPACK gate limits need dynamic table capacity above zero, not $maxTableCapacity"
        }
        require(maxBlockedStreams > 0) {
            "QPACK gate limits need a blocked-stream allowance above zero, not $maxBlockedStreams"
        }
    }
}
