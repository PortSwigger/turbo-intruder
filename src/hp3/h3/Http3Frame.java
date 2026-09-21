package hp3.h3;

import java.util.HexFormat;

/**
 * One HTTP/3 frame: a varint type, a varint length, and that many payload bytes
 * (RFC 9114 section 7.1).
 *
 * <p>The type is a {@code long} rather than an enum because any 62-bit value is legal on the wire,
 * and both directions matter — we must be able to receive types we do not recognise, and to send
 * them on purpose.
 *
 * @param type    frame type codepoint
 * @param payload frame payload, never null; may be empty
 */
public record Http3Frame(long type, byte[] payload) {

    public Http3Frame {
        if (payload == null) {
            throw new IllegalArgumentException("payload must not be null");
        }
    }

    public static Http3Frame of(long type, byte[] payload) {
        return new Http3Frame(type, payload);
    }

    public int payloadLength() {
        return payload.length;
    }

    /** True if this frame's type is one HTTP/3 requires a receiver to ignore. */
    public boolean isGrease() {
        return Http3FrameType.isGreaseType(type);
    }

    @Override
    public String toString() {
        return Http3FrameType.name(type) + " len=" + payload.length
                + (payload.length == 0 ? "" : " " + HexFormat.of().formatHex(
                payload, 0, Math.min(payload.length, 32)));
    }
}
