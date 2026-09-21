package http3

/**
 * How a gate releases its batch.
 *
 * Both modes stage first and release on one signal; they differ in what the peer is waiting for.
 * [SDA] withholds the tail of every request and releases them in a single UDP datagram, which
 * eliminates release jitter but bounds a batch by the datagram size. [QPACK] sends every request
 * whole but referencing a QPACK dynamic table insertion it withholds, so the peer holds complete
 * requests it cannot decode; releasing the insertion unblocks all of them at once. Its batch is
 * bounded by the peer's `SETTINGS_QPACK_BLOCKED_STREAMS` rather than by a datagram, which is
 * usually the larger of the two. [QPACK] needs the peer to have advertised both dynamic table
 * capacity and a tolerance for blocked streams, so it is not always available.
 */
enum class GateMode {
    /** Pick per connection: [QPACK] where the peer allows it, [SDA] otherwise. */
    AUTO,

    /** Always release in a single datagram. Works against any HTTP/3 peer. */
    SDA,

    /** Always release on the QPACK encoder stream. Fails if the peer has not opted in. */
    QPACK,
    ;

    companion object {
        /** Resolves the lower-case name a script writes, rejecting anything else by name. */
        @JvmStatic
        fun fromScriptName(name: String): GateMode =
            entries.firstOrNull { it.name.equals(name, ignoreCase = true) }
                ?: throw IllegalArgumentException(
                    "Unrecognised gateMode '$name'. Valid modes are " +
                        entries.joinToString(", ") { "'" + it.name.lowercase() + "'" } + ".",
                )
    }
}
