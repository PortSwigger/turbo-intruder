package hp3.h3;

/**
 * Unidirectional stream types, RFC 9114 section 6.2. The type is a varint sent as the first bytes
 * of the stream, before any frames.
 */
public final class Http3StreamType {

    public static final long CONTROL = 0x00;
    public static final long PUSH = 0x01;
    public static final long QPACK_ENCODER = 0x02;
    public static final long QPACK_DECODER = 0x03;

    private Http3StreamType() {
    }

    public static String name(long type) {
        if (type == CONTROL) return "CONTROL";
        if (type == PUSH) return "PUSH";
        if (type == QPACK_ENCODER) return "QPACK_ENCODER";
        if (type == QPACK_DECODER) return "QPACK_DECODER";
        return "UNKNOWN(0x" + Long.toHexString(type) + ")";
    }
}
