package hp3.h3;

import hp3.h3.qpack.FieldLine;

import java.util.List;

/**
 * An HTTP/3 response exactly as received: the field list in wire order, the concatenated DATA
 * payload, and any trailer field section.
 *
 * @param fields   ordered response field lines, {@code :status} included wherever it appeared
 * @param body     concatenation of every DATA frame
 * @param trailers trailer fields, empty when the response had none
 */
public record Http3Response(List<FieldLine> fields, byte[] body, List<FieldLine> trailers) {

    public Http3Response {
        fields = List.copyOf(fields);
        trailers = List.copyOf(trailers);
    }

    /**
     * The value of the first {@code :status} field, or -1 if there is none or it is not numeric.
     * A missing or malformed status is a real possibility here, because nothing in this stack
     * rejects a response for being malformed.
     */
    public int status() {
        for (FieldLine field : fields) {
            if (field.name().equals(":status")) {
                try {
                    return Integer.parseInt(field.value());
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    /** First value for {@code name}, case-sensitive, or null. */
    public String firstValue(String name) {
        for (FieldLine field : fields) {
            if (field.name().equals(name)) {
                return field.value();
            }
        }
        return null;
    }
}
