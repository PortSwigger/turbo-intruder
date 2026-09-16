package hp3.h3.qpack;

import hp3.h3.VarInt;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

/**
 * N-bit prefix integers, RFC 7541 section 5.1. QPACK inherits the encoding unchanged, and uses it
 * for every index and string length.
 *
 * <p>The first byte carries the low N bits of the value plus whatever representation flags belong
 * in the high bits; larger values continue into subsequent octets with a continuation bit.
 */
public final class PrefixInteger {

    private PrefixInteger() {
    }

    /**
     * Encodes {@code value} into an {@code prefixBits}-bit prefix, ORing {@code flags} into the
     * high bits of the first byte.
     */
    public static byte[] encode(long value, int prefixBits, int flags) {
        if (value < 0) {
            throw new IllegalArgumentException("prefix integers are unsigned: " + value);
        }
        int max = (1 << prefixBits) - 1;
        var out = new ByteArrayOutputStream();
        if (value < max) {
            out.write(flags | (int) value);
            return out.toByteArray();
        }
        // All prefix bits set means "the value continues in the following octets".
        out.write(flags | max);
        long rest = value - max;
        while (rest >= 128) {
            out.write((int) ((rest & 0x7f) | 0x80));
            rest >>>= 7;
        }
        out.write((int) rest);
        return out.toByteArray();
    }

    /** Reads a prefix integer, consuming the first byte and any continuation octets. */
    public static long read(ByteBuffer buffer, int prefixBits) throws QpackException {
        int max = (1 << prefixBits) - 1;
        long value = buffer.get() & max;
        if (value < max) {
            return value;
        }
        int shift = 0;
        while (true) {
            int octet = buffer.get() & 0xff;
            value += (long) (octet & 0x7f) << shift;
            // Checked after every octet, so the accumulator can never wrap into a negative value
            // that a later narrowing cast would turn back into a plausible-looking length.
            if (value < 0 || value > VarInt.MAX_VALUE) {
                throw new QpackException(
                        "prefix integer exceeds the maximum QUIC variable-length integer");
            }
            if ((octet & 0x80) == 0) {
                return value;
            }
            shift += 7;
            if (shift > 56) {
                throw new QpackException("prefix integer overflows 64 bits");
            }
        }
    }
}
