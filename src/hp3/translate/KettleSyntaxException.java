package hp3.translate;

/**
 * A malformed escape sequence in a kettled request.
 *
 * <p>Checked, and deliberately so: the only sensible response is to refuse the request and say why,
 * and the compiler is the only thing that guarantees a caller does that rather than letting the
 * failure escape into Burp's handler thread. A request whose escapes do not parse must not go out
 * partially decoded — a harness comparing responses cannot tell a mangled request from an intended
 * one after the fact.
 */
public class KettleSyntaxException extends Exception {

    public KettleSyntaxException(String message) {
        super(message);
    }
}
