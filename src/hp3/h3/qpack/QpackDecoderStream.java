package hp3.h3.qpack;

import java.io.IOException;
import java.io.InputStream;

/**
 * Reads the instructions a peer sends on its QPACK decoder stream, RFC 9204 section 4.4.
 *
 * <p>Only one of the three matters to an encoder that inserts a single entry and then reuses it:
 * Insert Count Increment, which is how the peer says it has taken an insertion in and so how we
 * learn that referencing it will not block anything. The other two are consumed and discarded,
 * because skipping them would leave the stream misaligned for every instruction after.
 */
public final class QpackDecoderStream {

    private QpackDecoderStream() {
    }

    /**
     * Reads one instruction and reports how many insertions it acknowledges: zero for the
     * instructions that acknowledge none, and {@code -1} once the peer closes the stream.
     */
    public static long readInsertCountIncrement(InputStream input)
            throws IOException, QpackException {
        int first = input.read();
        if (first < 0) {
            return -1;
        }
        if ((first & 0x80) != 0) {                       // 1 StreamID(7+): Section Acknowledgement
            QpackEncoderStream.readPrefixInteger(first, 7, input);
            return 0;
        }
        if ((first & 0xc0) == 0x40) {                    // 01 StreamID(6+): Stream Cancellation
            QpackEncoderStream.readPrefixInteger(first, 6, input);
            return 0;
        }
        return QpackEncoderStream.readPrefixInteger(first, 6, input);   // 00 Increment(6+)
    }
}
