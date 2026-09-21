package hp3.h3.qpack;

/**
 * One header field as it appears on the wire: a raw name and a raw value, in the order the caller
 * supplied them.
 *
 * <p>Pseudo-headers are ordinary field lines whose name begins with a colon. There is deliberately
 * no separate pseudo-header map and no canonical ordering, because reproducing Burp's HTTP/2
 * capabilities means being able to emit duplicate, out-of-order, uppercase or otherwise malformed
 * fields exactly as written.
 *
 * @param name  field name, never normalised
 * @param value field value, never normalised
 */
public record FieldLine(String name, String value) {

    public FieldLine {
        if (name == null || value == null) {
            throw new IllegalArgumentException("field name and value must not be null");
        }
    }

    public static FieldLine of(String name, String value) {
        return new FieldLine(name, value);
    }

    public boolean isPseudoHeader() {
        return name.startsWith(":");
    }

    @Override
    public String toString() {
        return name + ": " + value;
    }
}
