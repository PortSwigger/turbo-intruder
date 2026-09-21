package hp3.h3.qpack;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The RFC 7541 Appendix B Huffman code, which QPACK uses unmodified.
 *
 * <p>Not optional: real servers Huffman-encode their literal values. The phase 1 spike captured
 * quic.tech doing exactly that in a response HEADERS frame.
 *
 * <p>Strings are treated as ISO-8859-1 throughout, which maps every byte value 0-255 to exactly one
 * character and back. UTF-8 would be lossy for header values holding arbitrary bytes, and a tool
 * whose purpose is sending deliberately malformed traffic cannot afford a charset that mangles its
 * input.
 */
public final class HuffmanCodec {

    /** Decoding trie, flattened: {@code CHILD[2*node + bit]}, or -1 where there is no edge. */
    private static final int[] CHILD;
    /** Symbol at each node, or -1 for an internal node. */
    private static final int[] SYMBOL;

    static {
        List<int[]> children = new ArrayList<>();   // {zero, one}
        List<Integer> symbols = new ArrayList<>();
        children.add(new int[]{-1, -1});
        symbols.add(-1);

        for (int symbol = 0; symbol < HuffmanTable.CODES.length; symbol++) {
            int code = HuffmanTable.CODES[symbol];
            int length = HuffmanTable.LENGTHS[symbol];
            int node = 0;
            for (int bitIndex = length - 1; bitIndex >= 0; bitIndex--) {
                int bit = (code >>> bitIndex) & 1;
                int next = children.get(node)[bit];
                if (next == -1) {
                    children.add(new int[]{-1, -1});
                    symbols.add(-1);
                    next = children.size() - 1;
                    children.get(node)[bit] = next;
                }
                node = next;
            }
            symbols.set(node, symbol);
        }

        CHILD = new int[children.size() * 2];
        SYMBOL = new int[symbols.size()];
        for (int i = 0; i < children.size(); i++) {
            CHILD[2 * i] = children.get(i)[0];
            CHILD[2 * i + 1] = children.get(i)[1];
            SYMBOL[i] = symbols.get(i);
        }
    }

    private HuffmanCodec() {
    }

    /** Number of bytes {@code value} occupies once Huffman coded, including padding. */
    public static int encodedLength(String value) {
        long bits = 0;
        for (byte b : value.getBytes(StandardCharsets.ISO_8859_1)) {
            bits += HuffmanTable.LENGTHS[b & 0xff];
        }
        return (int) ((bits + 7) / 8);
    }

    /** Huffman codes {@code value}, padding to a byte boundary with EOS prefix bits (all ones). */
    public static byte[] encode(String value) {
        var out = new ByteArrayOutputStream();
        long buffer = 0;
        int bits = 0;

        for (byte b : value.getBytes(StandardCharsets.ISO_8859_1)) {
            int symbol = b & 0xff;
            buffer = (buffer << HuffmanTable.LENGTHS[symbol]) | HuffmanTable.CODES[symbol];
            bits += HuffmanTable.LENGTHS[symbol];
            while (bits >= 8) {
                bits -= 8;
                out.write((int) (buffer >>> bits) & 0xff);
            }
            buffer &= (1L << bits) - 1;   // drop the bits already emitted
        }

        if (bits > 0) {
            // Pad with the most significant bits of EOS, which are all ones.
            out.write((int) ((buffer << (8 - bits)) | ((1 << (8 - bits)) - 1)) & 0xff);
        }
        return out.toByteArray();
    }

    public static String decode(byte[] data) throws QpackException {
        return decode(data, 0, data.length);
    }

    /**
     * Decodes {@code length} bytes from {@code offset}.
     *
     * @throws QpackException on an encoded EOS symbol, over-long padding, or padding that is not
     *                        EOS prefix bits — all three are errors under RFC 7541 section 5.2
     */
    public static String decode(byte[] data, int offset, int length) throws QpackException {
        var out = new ByteArrayOutputStream();
        int node = 0;
        int bitsSinceSymbol = 0;
        boolean paddingIsAllOnes = true;

        for (int i = offset; i < offset + length; i++) {
            int octet = data[i] & 0xff;
            for (int bitIndex = 7; bitIndex >= 0; bitIndex--) {
                int bit = (octet >>> bitIndex) & 1;
                node = CHILD[2 * node + bit];
                if (node == -1) {
                    throw new QpackException("Huffman code walked off the table");
                }
                bitsSinceSymbol++;
                if (bit == 0) {
                    paddingIsAllOnes = false;
                }

                if (SYMBOL[node] != -1) {
                    if (SYMBOL[node] == HuffmanTable.EOS) {
                        throw new QpackException("Huffman string contains an encoded EOS symbol");
                    }
                    out.write(SYMBOL[node]);
                    node = 0;
                    bitsSinceSymbol = 0;
                    paddingIsAllOnes = true;
                }
            }
        }

        if (bitsSinceSymbol >= 8) {
            throw new QpackException(
                    "Huffman padding is " + bitsSinceSymbol + " bits, must be fewer than 8");
        }
        if (bitsSinceSymbol > 0 && !paddingIsAllOnes) {
            throw new QpackException("Huffman padding is not the EOS prefix (all ones)");
        }
        return out.toString(StandardCharsets.ISO_8859_1);
    }
}
