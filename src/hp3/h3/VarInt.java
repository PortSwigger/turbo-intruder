package hp3.h3;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * QUIC variable-length integers, RFC 9000 section 16. Every length and identifier in HTTP/3 is one
 * of these, so this is the foundation the frame codec and QPACK are built on.
 *
 * <p>The two most significant bits of the first byte select the encoded length; the remaining bits
 * carry the value:
 *
 * <pre>
 *   00  1 byte   6-bit value    0 .. 63
 *   01  2 bytes  14-bit value   0 .. 16383
 *   10  4 bytes  30-bit value   0 .. 1073741823
 *   11  8 bytes  62-bit value   0 .. 4611686018427387903
 * </pre>
 *
 * <p>RFC 9000 permits encodings that are longer than necessary, and a peer must accept them. That
 * is a control seam rather than a curiosity, so {@link #encode(long, int)} exposes it deliberately.
 */
public final class VarInt {

    /** Largest value a QUIC varint can carry: 2^62 - 1. */
    public static final long MAX_VALUE = 4611686018427387903L;

    private static final long MAX_1_BYTE = 63L;
    private static final long MAX_2_BYTE = 16383L;
    private static final long MAX_4_BYTE = 1073741823L;

    private VarInt() {
    }

    /** Number of bytes the minimal encoding of {@code value} occupies. */
    public static int encodedLength(long value) {
        requireInRange(value);
        if (value <= MAX_1_BYTE) return 1;
        if (value <= MAX_2_BYTE) return 2;
        if (value <= MAX_4_BYTE) return 4;
        return 8;
    }

    /** Encodes {@code value} using the fewest bytes possible. */
    public static byte[] encode(long value) {
        return encode(value, encodedLength(value));
    }

    /**
     * Encodes {@code value} into exactly {@code length} bytes, which must be 1, 2, 4 or 8 and large
     * enough to hold the value. Permits the deliberately non-minimal encodings RFC 9000 allows.
     */
    public static byte[] encode(long value, int length) {
        requireInRange(value);
        if (length != 1 && length != 2 && length != 4 && length != 8) {
            throw new IllegalArgumentException(
                    "varint length must be 1, 2, 4 or 8 but was " + length);
        }
        if (length < encodedLength(value)) {
            throw new IllegalArgumentException(
                    value + " does not fit in " + length + " byte(s)");
        }

        byte[] out = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            out[i] = (byte) value;
            value >>>= 8;
        }
        // Length prefix: 00, 01, 10, 11 for lengths 1, 2, 4, 8.
        out[0] |= (byte) (log2(length) << 6);
        return out;
    }

    /** Writes the minimal encoding of {@code value} to {@code out}. */
    public static void write(OutputStream out, long value) throws IOException {
        out.write(encode(value));
    }

    /** Reads one varint from {@code buffer}, advancing its position. */
    public static long read(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) {
            throw new BufferUnderflowException();
        }
        int first = buffer.get() & 0xff;
        int length = 1 << (first >>> 6);
        if (buffer.remaining() < length - 1) {
            throw new BufferUnderflowException();
        }
        long value = first & 0x3f;
        for (int i = 1; i < length; i++) {
            value = (value << 8) | (buffer.get() & 0xff);
        }
        return value;
    }

    /**
     * Reads one varint from {@code in}.
     *
     * @return the value, or -1 if the stream ends cleanly before any byte is read
     * @throws EOFException if the stream ends part-way through a varint
     */
    public static long read(InputStream in) throws IOException {
        int first = in.read();
        if (first < 0) {
            return -1;
        }
        int length = 1 << (first >>> 6);
        long value = first & 0x3f;
        for (int i = 1; i < length; i++) {
            int next = in.read();
            if (next < 0) {
                throw new EOFException(
                        "stream ended " + (length - i) + " byte(s) into a " + length + "-byte varint");
            }
            value = (value << 8) | next;
        }
        return value;
    }

    private static void requireInRange(long value) {
        if (value < 0 || value > MAX_VALUE) {
            throw new IllegalArgumentException(
                    "varint out of range 0.." + MAX_VALUE + ": " + value);
        }
    }

    /** {@code length} is known to be 1, 2, 4 or 8, so this is 0, 1, 2 or 3. */
    private static int log2(int length) {
        return Integer.numberOfTrailingZeros(length);
    }
}
