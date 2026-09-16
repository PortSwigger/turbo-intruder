package hp3.h3.qpack;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Reads the instructions a peer sends on its QPACK encoder stream, RFC 9204 section 4.3, and
 * applies them to our copy of its dynamic table.
 *
 * <p>The peer's table and ours only agree if every instruction is applied in order, so this reads
 * one instruction at a time from the stream and never skips one it does not understand: there is no
 * such thing, and guessing would silently desynchronise every later field section.
 */
public final class QpackEncoderStream {

    private QpackEncoderStream() {
    }

    /** Set Dynamic Table Capacity, RFC 9204 section 4.3.1: {@code 001 capacity(5+)}. */
    public static byte[] encodeSetCapacity(long capacity) {
        return PrefixInteger.encode(capacity, 5, 0x20);
    }

    /**
     * Insert With Name Reference against the static table, RFC 9204 section 4.3.2:
     * {@code 1 T index(6+)} then the value as a string literal.
     */
    public static byte[] encodeInsertWithNameReference(int staticIndex, String value) {
        var out = new java.io.ByteArrayOutputStream();
        out.writeBytes(PrefixInteger.encode(staticIndex, 6, 0x80 | 0x40));
        QpackEncoder.writeStringLiteral(
                out, value, HuffmanCodec.encodedLength(value) < value.length(), 7, 0);
        return out.toByteArray();
    }

    /**
     * Reads and applies one instruction, returning {@code false} once the peer closes the stream.
     */
    public static boolean readInstruction(InputStream input, QpackDynamicTable table)
            throws IOException, QpackException {
        int first = input.read();
        if (first < 0) {
            return false;
        }

        if ((first & 0x80) != 0) {                       // 1 T index(6+)
            boolean fromStaticTable = (first & 0x40) != 0;
            long index = readPrefixInteger(first, 6, input);
            String name = fromStaticTable
                    ? staticName(index)
                    : table.get(relativeToAbsolute(table, index)).name();
            table.insert(new FieldLine(name, readStringLiteral(input, 7)));
        } else if ((first & 0xc0) == 0x40) {             // 01 H nameLength(5+)
            boolean huffman = (first & 0x20) != 0;
            long length = readPrefixInteger(first, 5, input);
            String name = readString(input, length, huffman);
            table.insert(new FieldLine(name, readStringLiteral(input, 7)));
        } else if ((first & 0xe0) == 0x20) {             // 001 capacity(5+)
            table.setCapacity(readPrefixInteger(first, 5, input));
        } else {                                         // 000 index(5+)
            long index = readPrefixInteger(first, 5, input);
            table.insert(table.get(relativeToAbsolute(table, index)));
        }
        return true;
    }

    /**
     * RFC 9204 section 3.2.5: on the encoder stream, relative index 0 is the most recent insertion.
     */
    private static long relativeToAbsolute(QpackDynamicTable table, long relativeIndex) {
        return table.insertCount() - 1 - relativeIndex;
    }

    private static String staticName(long index) throws QpackException {
        if (index < 0 || index >= QpackStaticTable.size()) {
            throw new QpackException("static table index " + index + " is out of range 0.."
                    + (QpackStaticTable.size() - 1));
        }
        return QpackStaticTable.name((int) index);
    }

    private static String readStringLiteral(InputStream input, int prefixBits)
            throws IOException, QpackException {
        int first = input.read();
        if (first < 0) {
            throw new QpackException("encoder stream ended before a string literal");
        }
        boolean huffman = (first & (1 << prefixBits)) != 0;
        return readString(input, readPrefixInteger(first, prefixBits, input), huffman);
    }

    private static String readString(InputStream input, long length, boolean huffman)
            throws IOException, QpackException {
        if (length > Integer.MAX_VALUE) {
            throw new QpackException("string literal declares " + length + " octets");
        }
        byte[] octets = input.readNBytes((int) length);
        if (octets.length < length) {
            throw new QpackException("encoder stream ended " + (length - octets.length)
                    + " octets short of a string literal");
        }
        return huffman
                ? HuffmanCodec.decode(octets)
                : new String(octets, StandardCharsets.ISO_8859_1);
    }

    /** RFC 7541 section 5.1, reading onwards from a first byte already taken from the stream. */
    static long readPrefixInteger(int firstByte, int prefixBits, InputStream input)
            throws IOException, QpackException {
        int max = (1 << prefixBits) - 1;
        long value = firstByte & max;
        if (value < max) {
            return value;
        }
        int shift = 0;
        while (true) {
            int octet = input.read();
            if (octet < 0) {
                throw new QpackException("encoder stream ended part-way through a prefix integer");
            }
            value += (long) (octet & 0x7f) << shift;
            if (value < 0) {
                throw new QpackException("prefix integer overflows 64 bits");
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
