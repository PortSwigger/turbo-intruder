package hp3.h3;

import hp3.h3.qpack.FieldLine;

import java.util.List;

/**
 * An HTTP/3 request as it will go on the wire: an ordered field list and a body.
 *
 * <p>Pseudo-headers are ordinary entries in {@code fields}, in whatever order and multiplicity the
 * caller chose. Nothing is derived, defaulted or validated here — the translator above decides what
 * the fields are, and this record carries them unchanged.
 *
 * @param fields ordered field lines, pseudo-headers included
 * @param body   request body; empty means no DATA frame is sent at all
 */
public record Http3Request(List<FieldLine> fields, byte[] body) {

    public Http3Request {
        if (fields == null || body == null) {
            throw new IllegalArgumentException("fields and body must not be null");
        }
        fields = List.copyOf(fields);
    }

    public static Http3Request of(List<FieldLine> fields) {
        return new Http3Request(fields, new byte[0]);
    }

    public static Http3Request of(List<FieldLine> fields, byte[] body) {
        return new Http3Request(fields, body);
    }

    public boolean hasBody() {
        return body.length > 0;
    }
}
