package http3

import java.io.FilterInputStream
import java.io.InputStream

/**
 * Records the moment the first response byte arrives.
 *
 * Time to first byte and time to last byte are different measurements, and on a race-condition run
 * the gap between them is often the signal. Reading it off the stream is the only honest source:
 * anything derived after the response is fully assembled is just time to last byte wearing a
 * different name.
 */
class FirstByteTimingInputStream(delegate: InputStream) : FilterInputStream(delegate) {

    /** [UNREAD] until a byte actually arrives. */
    @Volatile
    var firstByteNanos: Long = UNREAD
        private set

    override fun read(): Int {
        val value = super.read()
        if (value >= 0) {
            stamp()
        }
        return value
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val count = super.read(b, off, len)
        if (count > 0) {
            stamp()
        }
        return count
    }

    private fun stamp() {
        if (firstByteNanos == UNREAD) {
            firstByteNanos = System.nanoTime()
        }
    }

    companion object {
        /** No byte has arrived yet. Distinct from any real [System.nanoTime] reading. */
        const val UNREAD: Long = Long.MIN_VALUE
    }
}
