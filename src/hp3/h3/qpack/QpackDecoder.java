package hp3.h3.qpack;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Decodes QPACK field sections, RFC 9204 section 4.5.
 *
 * <p>With no dynamic table the decoder is static-only: a peer that sends a dynamic or post-base
 * reference anyway must fail loudly here rather than produce quietly wrong headers. Given a
 * {@link QpackDynamicTable} it also resolves references into it, which is what lets a server stop
 * repeating the same response headers in full on every message.
 *
 * <p>Order and duplicates are preserved exactly as received; nothing is normalised on the way in
 * either.
 */
public final class QpackDecoder {

    private final ByteBuffer buffer;
    private final QpackDynamicTable.Snapshot table;
    private long base;
    private long requiredInsertCount;

    private QpackDecoder(ByteBuffer buffer, QpackDynamicTable.Snapshot table) {
        this.buffer = buffer;
        this.table = table;
    }

    /**
     * A decoded field section and the Required Insert Count it carried. A non-zero count means the
     * section leaned on the dynamic table, which RFC 9204 section 4.4.1 requires be acknowledged.
     */
    public record FieldSection(List<FieldLine> fields, long requiredInsertCount) {
    }

    /** Decodes a field section that may reference only the static table. */
    public static List<FieldLine> decodeFieldSection(byte[] encoded) throws QpackException {
        return decodeFieldSection(encoded, null);
    }

    /**
     * Decodes a complete field section, resolving dynamic references against {@code table} when one
     * is given. Order and duplicates are preserved exactly as received.
     */
    public static List<FieldLine> decodeFieldSection(byte[] encoded, QpackDynamicTable table)
            throws QpackException {
        return decodeSection(encoded, table).fields();
    }

    /** As {@link #decodeFieldSection(byte[], QpackDynamicTable)}, reporting what it referenced. */
    public static FieldSection decodeSection(byte[] encoded, QpackDynamicTable table)
            throws QpackException {
        // One snapshot for the whole section: the peer's encoder stream may insert and evict while
        // this runs, and a half-old view would resolve indices against two different tables.
        var decoder = new QpackDecoder(ByteBuffer.wrap(encoded),
                table == null ? null : table.snapshot());
        List<FieldLine> fields = new ArrayList<>();
        try {
            decoder.readFieldSectionPrefix();
            while (decoder.buffer.hasRemaining()) {
                fields.add(decoder.readFieldLine());
            }
        } catch (BufferUnderflowException e) {
            throw new QpackException("field section ended part-way through a representation");
        }
        return new FieldSection(fields, decoder.requiredInsertCount);
    }

    /** RFC 9204 section 4.5.1. */
    private void readFieldSectionPrefix() throws QpackException {
        long encodedInsertCount = PrefixInteger.read(buffer, 8);
        boolean negativeDelta = (peek() & 0x80) != 0;
        long deltaBase = PrefixInteger.read(buffer, 7);

        if (table == null) {
            if (encodedInsertCount != 0) {
                throw new QpackException("Required Insert Count is " + encodedInsertCount
                        + " but the dynamic table is disabled (QPACK_MAX_TABLE_CAPACITY=0)");
            }
            if (negativeDelta || deltaBase != 0) {
                throw new QpackException("Base must be 0 when Required Insert Count is 0, got delta "
                        + (negativeDelta ? "-" : "+") + deltaBase);
            }
            base = 0;
            return;
        }

        requiredInsertCount = decodeRequiredInsertCount(encodedInsertCount);
        base = negativeDelta
                ? requiredInsertCount - deltaBase - 1
                : requiredInsertCount + deltaBase;
        if (base < 0) {
            throw new QpackException("field section Base is negative: " + base);
        }
    }

    /**
     * Reverses the wrapped encoding of the Required Insert Count, RFC 9204 section 4.5.1.1. The
     * value is sent modulo twice the table's entry capacity so it fits a small integer, and is
     * recovered here against the insertions actually seen.
     */
    private long decodeRequiredInsertCount(long encodedInsertCount) throws QpackException {
        if (encodedInsertCount == 0) {
            return 0;
        }
        long maxEntries = table.maxCapacity() / 32;
        long fullRange = 2 * maxEntries;
        if (encodedInsertCount > fullRange) {
            throw new QpackException("Required Insert Count " + encodedInsertCount
                    + " exceeds twice the table's maximum entries (" + fullRange + ")");
        }
        long maxValue = table.insertCount() + maxEntries;
        long maxWrapped = (maxValue / fullRange) * fullRange;
        long requiredInsertCount = maxWrapped + encodedInsertCount - 1;
        if (requiredInsertCount > maxValue) {
            if (requiredInsertCount <= fullRange) {
                throw new QpackException(
                        "Required Insert Count " + requiredInsertCount + " wraps below zero");
            }
            requiredInsertCount -= fullRange;
        }
        if (requiredInsertCount == 0) {
            throw new QpackException("Required Insert Count decoded to zero from a non-zero value");
        }
        if (requiredInsertCount > table.insertCount()) {
            throw new QpackException("field section needs " + requiredInsertCount
                    + " insertions but only " + table.insertCount() + " have arrived");
        }
        return requiredInsertCount;
    }

    private FieldLine readFieldLine() throws QpackException {
        int first = peek();

        if ((first & 0x80) != 0) {                       // 1 T index(6+)
            boolean fromStaticTable = (first & 0x40) != 0;
            long index = PrefixInteger.read(buffer, 6);
            if (fromStaticTable) {
                return staticEntry(index);
            }
            return dynamicEntry(relativeToAbsolute(index), "indexed field line");
        }
        if ((first & 0xc0) == 0x40) {                    // 01 N T index(4+)
            boolean fromStaticTable = (first & 0x10) != 0;
            long index = PrefixInteger.read(buffer, 4);
            String name = fromStaticTable
                    ? staticName(index)
                    : dynamicEntry(relativeToAbsolute(index),
                            "literal field line with name reference").name();
            return new FieldLine(name, readStringLiteral(7));
        }
        if ((first & 0xe0) == 0x20) {                    // 001 N H nameLength(3+)
            String name = readStringLiteral(3);
            return new FieldLine(name, readStringLiteral(7));
        }
        if ((first & 0xf0) == 0x10) {                    // 0001 index(4+)
            long index = PrefixInteger.read(buffer, 4);
            return dynamicEntry(postBaseToAbsolute(index),
                    "indexed field line with post-base index");
        }
        // 0000 N index(3+)
        long index = PrefixInteger.read(buffer, 3);
        String name = dynamicEntry(postBaseToAbsolute(index),
                "literal field line with post-base name reference").name();
        return new FieldLine(name, readStringLiteral(7));
    }

    /** RFC 9204 section 3.2.5: relative indices count back from Base. */
    private long relativeToAbsolute(long relativeIndex) {
        return base - 1 - relativeIndex;
    }

    /** RFC 9204 section 3.2.6: post-base indices count forward from Base. */
    private long postBaseToAbsolute(long postBaseIndex) {
        return base + postBaseIndex;
    }

    private FieldLine dynamicEntry(long absoluteIndex, String what) throws QpackException {
        if (table == null) {
            throw new QpackException(what + " references the dynamic table, which is disabled");
        }
        return table.get(absoluteIndex);
    }

    private String readStringLiteral(int prefixBits) throws QpackException {
        boolean huffman = (peek() & (1 << prefixBits)) != 0;
        long length = PrefixInteger.read(buffer, prefixBits);
        if (length > buffer.remaining()) {
            throw new QpackException("string literal declares " + length
                    + " octets but only " + buffer.remaining() + " remain");
        }
        byte[] octets = new byte[(int) length];
        buffer.get(octets);
        return huffman
                ? HuffmanCodec.decode(octets)
                : new String(octets, StandardCharsets.ISO_8859_1);
    }

    private static FieldLine staticEntry(long index) throws QpackException {
        requireStaticIndex(index);
        return new FieldLine(QpackStaticTable.name((int) index), QpackStaticTable.value((int) index));
    }

    private static String staticName(long index) throws QpackException {
        requireStaticIndex(index);
        return QpackStaticTable.name((int) index);
    }

    private static void requireStaticIndex(long index) throws QpackException {
        if (index < 0 || index >= QpackStaticTable.size()) {
            throw new QpackException("static table index " + index + " is out of range 0.."
                    + (QpackStaticTable.size() - 1));
        }
    }

    /** Reads the byte at the current position without consuming it. */
    private int peek() {
        if (!buffer.hasRemaining()) {
            throw new BufferUnderflowException();
        }
        return buffer.get(buffer.position()) & 0xff;
    }
}
