package hp3.h3;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Serialises HTTP/3 frames, RFC 9114 section 7.1.
 *
 * <p>This is the primary control seam of the whole extension. The general
 * {@link #write(OutputStream, long, byte[])} takes an arbitrary type and payload and is what the
 * typed helpers are built from, so emitting a reserved codepoint, a grease type, or a frame whose
 * declared length disagrees with its payload is a matter of calling a different method rather than
 * bypassing the codec.
 *
 * <p>Nothing here validates. That is deliberate: validation belongs to a peer, and the point of this
 * class is to be able to say exactly what we mean.
 */
public final class Http3FrameWriter {

    private Http3FrameWriter() {
    }

    /** Writes {@code type}, the payload's length, then the payload. */
    public static void write(OutputStream out, long type, byte[] payload) throws IOException {
        VarInt.write(out, type);
        VarInt.write(out, payload.length);
        out.write(payload);
    }

    public static void write(OutputStream out, Http3Frame frame) throws IOException {
        write(out, frame.type(), frame.payload());
    }

    /** Returns the frame as bytes rather than writing it to a stream. */
    public static byte[] toBytes(long type, byte[] payload) {
        byte[] typeBytes = VarInt.encode(type);
        byte[] lengthBytes = VarInt.encode(payload.length);
        byte[] out = new byte[typeBytes.length + lengthBytes.length + payload.length];
        System.arraycopy(typeBytes, 0, out, 0, typeBytes.length);
        System.arraycopy(lengthBytes, 0, out, typeBytes.length, lengthBytes.length);
        System.arraycopy(payload, 0, out, typeBytes.length + lengthBytes.length, payload.length);
        return out;
    }

    /**
     * Writes a frame whose declared length is {@code declaredLength} regardless of how many bytes
     * the payload actually contains. Produces an invalid frame on purpose.
     *
     * <p>Unused in phase 1 and reachable only from a caller that asks for it explicitly. It exists
     * because "the length field and the payload disagree" is a whole class of parser bug, and the
     * design commits to being able to express it.
     */
    public static void writeWithDeclaredLength(OutputStream out, long type, long declaredLength,
                                               byte[] payload) throws IOException {
        VarInt.write(out, type);
        VarInt.write(out, declaredLength);
        out.write(payload);
    }

    /**
     * Writes the type and length using deliberately non-minimal varint encodings. RFC 9000 permits
     * these and requires peers to accept them; not every implementation does.
     */
    public static void writeWithVarIntWidths(OutputStream out, long type, int typeWidth,
                                             byte[] payload, int lengthWidth) throws IOException {
        out.write(VarInt.encode(type, typeWidth));
        out.write(VarInt.encode(payload.length, lengthWidth));
        out.write(payload);
    }

    public static void writeData(OutputStream out, byte[] body) throws IOException {
        write(out, Http3FrameType.DATA, body);
    }

    public static void writeHeaders(OutputStream out, byte[] encodedFieldSection) throws IOException {
        write(out, Http3FrameType.HEADERS, encodedFieldSection);
    }
}
