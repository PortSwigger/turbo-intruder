package hp3.h3;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Parses a stream of HTTP/3 frames, RFC 9114 section 7.1.
 *
 * <p>Two read modes, because "unknown" and "reserved" are different failures. RFC 9114 section 7.2.8
 * requires that unknown frame types be ignored, and real servers rely on it — quic.tech sent two
 * grease frames ahead of HEADERS during the phase 1 spikes. The four codepoints HTTP/2 used are
 * reserved instead, and receiving one is a connection error, so those must be surfaced rather than
 * quietly dropped.
 */
public final class Http3FrameReader {

    /**
     * Refuse to allocate a payload larger than this. A frame length is a 62-bit varint, so a
     * corrupt or hostile stream can otherwise ask for an unbounded allocation.
     */
    public static final int DEFAULT_MAX_PAYLOAD_LENGTH = 16 * 1024 * 1024;

    private final InputStream in;
    private final int maxPayloadLength;

    public Http3FrameReader(InputStream in) {
        this(in, DEFAULT_MAX_PAYLOAD_LENGTH);
    }

    public Http3FrameReader(InputStream in, int maxPayloadLength) {
        this.in = in;
        this.maxPayloadLength = maxPayloadLength;
    }

    /**
     * Reads the next frame verbatim, whatever its type.
     *
     * @return the frame, or null at a clean end of stream
     */
    public Http3Frame readFrame() throws IOException {
        long type = VarInt.read(in);
        if (type < 0) {
            return null; // clean end of stream between frames
        }

        long length = VarInt.read(in);
        if (length < 0) {
            throw new EOFException("stream ended after frame type " + Http3FrameType.name(type)
                    + ", before its length");
        }
        if (length > maxPayloadLength) {
            throw new Http3Exception(Http3Exception.H3_EXCESSIVE_LOAD,
                    Http3FrameType.name(type) + " declares a " + length
                            + " byte payload, over the " + maxPayloadLength + " byte limit");
        }

        byte[] payload = in.readNBytes((int) length);
        if (payload.length < length) {
            throw new EOFException(Http3FrameType.name(type) + " declares " + length
                    + " payload bytes but the stream held " + payload.length);
        }
        return new Http3Frame(type, payload);
    }

    /**
     * Reads the next frame, discarding any whose type HTTP/3 requires a receiver to ignore.
     * Reserved HTTP/2 codepoints are returned rather than skipped, so the caller can raise
     * {@code H3_FRAME_UNEXPECTED}.
     *
     * @return the frame, or null at a clean end of stream
     */
    public Http3Frame readFrameIgnoringUnknown() throws IOException {
        Http3Frame frame;
        while ((frame = readFrame()) != null) {
            if (isKnown(frame.type()) || Http3FrameType.isReservedHttp2Type(frame.type())) {
                return frame;
            }
            // Unknown type, including grease: discard the whole frame and read the next one.
        }
        return null;
    }

    /** True for the frame types this implementation understands. */
    static boolean isKnown(long type) {
        return type == Http3FrameType.DATA
                || type == Http3FrameType.HEADERS
                || type == Http3FrameType.CANCEL_PUSH
                || type == Http3FrameType.SETTINGS
                || type == Http3FrameType.PUSH_PROMISE
                || type == Http3FrameType.GOAWAY
                || type == Http3FrameType.ORIGIN
                || type == Http3FrameType.MAX_PUSH_ID;
    }
}
