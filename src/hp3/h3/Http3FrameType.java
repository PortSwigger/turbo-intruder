package hp3.h3;

/**
 * HTTP/3 frame type codepoints, from the IANA HTTP/3 Frame Types registry (RFC 9114 section 11.2.1).
 *
 * <p>Frame types are varints, so this is a holder of constants rather than an enum: any 62-bit value
 * is a legal type on the wire, and the codec must be able to emit and receive types that are not
 * listed here.
 */
public final class Http3FrameType {

    public static final long DATA = 0x00;
    public static final long HEADERS = 0x01;
    public static final long CANCEL_PUSH = 0x03;
    public static final long SETTINGS = 0x04;
    public static final long PUSH_PROMISE = 0x05;
    public static final long GOAWAY = 0x07;
    public static final long ORIGIN = 0x0c;
    public static final long MAX_PUSH_ID = 0x0d;

    private Http3FrameType() {
    }

    /**
     * True for the four codepoints HTTP/2 used that HTTP/3 reserves: 0x02, 0x06, 0x08 and 0x09
     * (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION). RFC 9114 section 7.2.8 requires that receiving
     * one is a connection error of type H3_FRAME_UNEXPECTED.
     *
     * <p>Phase 1 only needs to recognise them. Phase 2 sends them deliberately, to find out whether
     * a target actually enforces the rule.
     */
    public static boolean isReservedHttp2Type(long type) {
        return type == 0x02 || type == 0x06 || type == 0x08 || type == 0x09;
    }

    /**
     * True for the grease codepoints of the form {@code 0x1f * N + 0x21}, which RFC 9114
     * section 7.2.8 reserves to exercise the requirement that unknown types be ignored.
     *
     * <p>Not hypothetical: quic.tech sent two of these ahead of HEADERS on a request stream during
     * the phase 1 spikes.
     */
    public static boolean isGreaseType(long type) {
        return type >= 0x21 && (type - 0x21) % 0x1f == 0;
    }

    /** A human-readable name for logging and test failures. Unknown types render as hex. */
    public static String name(long type) {
        if (type == DATA) return "DATA";
        if (type == HEADERS) return "HEADERS";
        if (type == CANCEL_PUSH) return "CANCEL_PUSH";
        if (type == SETTINGS) return "SETTINGS";
        if (type == PUSH_PROMISE) return "PUSH_PROMISE";
        if (type == GOAWAY) return "GOAWAY";
        if (type == ORIGIN) return "ORIGIN";
        if (type == MAX_PUSH_ID) return "MAX_PUSH_ID";
        if (isReservedHttp2Type(type)) return "RESERVED_H2(0x" + Long.toHexString(type) + ")";
        if (isGreaseType(type)) return "GREASE(0x" + Long.toHexString(type) + ")";
        return "UNKNOWN(0x" + Long.toHexString(type) + ")";
    }
}
