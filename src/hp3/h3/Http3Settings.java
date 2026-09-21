package hp3.h3;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A SETTINGS frame payload: a sequence of identifier/value varint pairs, RFC 9114 section 7.2.4.
 *
 * <p>Insertion order is preserved so a caller can control the order settings appear on the wire.
 */
public final class Http3Settings {

    public static final long QPACK_MAX_TABLE_CAPACITY = 0x01;
    public static final long MAX_FIELD_SECTION_SIZE = 0x06;
    public static final long QPACK_BLOCKED_STREAMS = 0x07;
    public static final long ENABLE_CONNECT_PROTOCOL = 0x08;

    private final Map<Long, Long> settings = new LinkedHashMap<>();

    /**
     * The dynamic table capacity this client offers a server, in octets.
     *
     * <p>Whatever a server repeats on every response — its {@code server} banner, the
     * {@code content-type} and {@code content-length} of a canned error page, the current
     * {@code date} — costs those bytes once here instead of once per response. A few dozen entries
     * covers that comfortably, and the table only ever holds what the server chooses to put in it.
     */
    public static final long DEFAULT_QPACK_MAX_TABLE_CAPACITY = 4096;

    /**
     * What this client advertises: a dynamic table the server may use, and no blocked streams.
     *
     * <p>Zero blocked streams is the load-bearing half. It lets a server reference an entry only
     * once it knows we have taken that entry in, so a field section can never arrive needing an
     * insertion we have not seen — no request ever waits on the encoder stream, and the decoder
     * needs no machinery for one that does. The cost is that the first few responses on a
     * connection are still literals, which against a run of any length rounds to nothing.
     */
    public static Http3Settings clientDefaults() {
        return new Http3Settings()
                .with(QPACK_MAX_TABLE_CAPACITY, DEFAULT_QPACK_MAX_TABLE_CAPACITY)
                .with(QPACK_BLOCKED_STREAMS, 0);
    }

    public static Http3Settings empty() {
        return new Http3Settings();
    }

    public Http3Settings with(long identifier, long value) {
        settings.put(identifier, value);
        return this;
    }

    public long get(long identifier, long defaultValue) {
        return settings.getOrDefault(identifier, defaultValue);
    }

    public boolean contains(long identifier) {
        return settings.containsKey(identifier);
    }

    public int size() {
        return settings.size();
    }

    public byte[] encodePayload() {
        var out = new ByteArrayOutputStream();
        try {
            for (Map.Entry<Long, Long> entry : settings.entrySet()) {
                VarInt.write(out, entry.getKey());
                VarInt.write(out, entry.getValue());
            }
        } catch (IOException e) {
            throw new IllegalStateException("ByteArrayOutputStream does not throw", e);
        }
        return out.toByteArray();
    }

    public static Http3Settings decodePayload(byte[] payload) throws Http3Exception {
        var result = new Http3Settings();
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        try {
            while (buffer.hasRemaining()) {
                long identifier = VarInt.read(buffer);
                long value = VarInt.read(buffer);
                if (result.settings.containsKey(identifier)) {
                    throw new Http3Exception(Http3Exception.H3_SETTINGS_ERROR,
                            "SETTINGS repeated identifier 0x" + Long.toHexString(identifier));
                }
                if (identifier >= 0x02 && identifier <= 0x05) {
                    throw new Http3Exception(Http3Exception.H3_SETTINGS_ERROR,
                            "SETTINGS used reserved HTTP/2 identifier 0x"
                                    + Long.toHexString(identifier));
                }
                result.settings.put(identifier, value);
            }
        } catch (BufferUnderflowException e) {
            throw new Http3Exception(Http3Exception.H3_FRAME_ERROR,
                    "SETTINGS payload ended part-way through an identifier/value pair");
        }
        return result;
    }

    @Override
    public String toString() {
        return settings.toString();
    }
}
