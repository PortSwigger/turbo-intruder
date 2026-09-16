package hp3.translate;

import java.util.HexFormat;

/**
 * The escape syntax that lets Burp carry a kettled request.
 *
 * <p>A client building requests through the HTTP/1 representation cannot express a kettled message,
 * because Burp's HTTP/1 parser resolves the very bytes that make it kettled: a smuggled CR LF is
 * absorbed into the header terminator, and a header line is split at its first colon. Those are
 * Burp's readings and they are not wrong — the HTTP/1 view genuinely cannot hold that message. So
 * rather than fight the parser, a kettled request writes the impossible bytes as text the parser is
 * happy to carry, and this class puts them back afterwards.
 *
 * <p>The HTTP/2 view needs the same trick for a narrower reason: it can hold a raw CR LF in a value,
 * but Burp's send pipeline sanitises one out before a handler is invoked, so an escape is the only
 * route to the wire there too.
 *
 * <table border="1">
 *   <caption>The alphabet</caption>
 *   <tr><td>{@code ^~}</td><td>CR LF, the pair that makes smuggling work</td></tr>
 *   <tr><td>{@code ^r}</td><td>CR alone</td></tr>
 *   <tr><td>{@code ^n}</td><td>LF alone</td></tr>
 *   <tr><td>{@code ^0}</td><td>NUL</td></tr>
 *   <tr><td>{@code ^s}</td><td>space, which the request line cannot otherwise hold</td></tr>
 *   <tr><td>{@code ^xNN}</td><td>any byte, exactly two hex digits</td></tr>
 *   <tr><td>{@code ^^}</td><td>a literal {@code ^}</td></tr>
 * </table>
 *
 * <p>Anything else after a caret is a {@link KettleSyntaxException}, never a silent literal. That
 * choice is the whole reason the syntax is safe to use: an unrecognised sequence passed through as
 * text would produce a request that looks like it was sent as written and was not, and no harness can
 * tell those apart from the response. A typo should cost one loud error, not a wrong conclusion.
 *
 * <p>Decoded escapes are characters {@code U+0000}–{@code U+00FF}, which is exactly the model the
 * rest of the pipeline already uses: field values reach the wire through
 * {@code getBytes(ISO_8859_1)}, so {@code ^xff} lands as {@code 0xFF} with no byte handling anywhere
 * else needing to know this class exists.
 *
 * <p>There is no encoder here, deliberately. Nothing in the extension needs one — a client writes
 * escapes by hand or generates them itself — and adding one would invite tests that feed our encoder
 * to our decoder, which would agree with each other no matter which byte both got wrong.
 */
public final class KettleEscapes {

    /**
     * The escape character. Rare in header values, and {@code ^^} covers the case where it is not;
     * decoding only ever runs on a request queued with {@code kettled=True}, so no ordinary traffic
     * can be caught by it.
     */
    public static final char ESCAPE = '^';

    private KettleEscapes() {
    }

    /**
     * Resolves every escape in {@code text}.
     *
     * @throws KettleSyntaxException if a caret is followed by anything the table does not define, or
     *                               by nothing at all
     */
    public static String decode(String text) throws KettleSyntaxException {
        if (text.indexOf(ESCAPE) < 0) {
            return text;    // the common case, and the one worth not allocating for
        }

        var decoded = new StringBuilder(text.length());
        int at = 0;
        while (at < text.length()) {
            char character = text.charAt(at);
            if (character != ESCAPE) {
                decoded.append(character);
                at++;
                continue;
            }
            if (at + 1 >= text.length()) {
                throw error(at, "^", "nothing follows it");
            }
            char code = text.charAt(at + 1);
            switch (code) {
                case '~' -> {
                    decoded.append('\r').append('\n');
                    at += 2;
                }
                case 'r' -> {
                    decoded.append('\r');
                    at += 2;
                }
                case 'n' -> {
                    decoded.append('\n');
                    at += 2;
                }
                case '0' -> {
                    decoded.append('\u0000');
                    at += 2;
                }
                case 's' -> {
                    decoded.append(' ');
                    at += 2;
                }
                case ESCAPE -> {
                    decoded.append(ESCAPE);
                    at += 2;
                }
                case 'x' -> {
                    decoded.append(hexByte(text, at));
                    at += 4;
                }
                default -> throw error(at, "^" + code, "not a recognised escape");
            }
        }
        return decoded.toString();
    }

    /**
     * The byte named by {@code ^xNN} at {@code at}. Exactly two hex digits, no more and no fewer: a
     * variable-length form could not be followed by a literal hex character, and half the point of
     * the syntax is writing arbitrary bytes next to ordinary text.
     */
    private static char hexByte(String text, int at) throws KettleSyntaxException {
        if (at + 3 >= text.length()) {
            throw error(at, text.substring(at), "^xNN needs two hex digits");
        }
        char high = text.charAt(at + 2);
        char low = text.charAt(at + 3);
        if (!HexFormat.isHexDigit(high) || !HexFormat.isHexDigit(low)) {
            throw error(at, text.substring(at, at + 4), "^xNN needs two hex digits");
        }
        return (char) (HexFormat.fromHexDigit(high) << 4 | HexFormat.fromHexDigit(low));
    }

    /**
     * The offset matters more than it looks: a kettled value is usually a wall of deliberately
     * unreadable bytes, and "somewhere in here" is not a diagnosis.
     */
    private static KettleSyntaxException error(int at, String sequence, String problem) {
        return new KettleSyntaxException(
                "kettle escape " + sequence + " at offset " + at + ": " + problem);
    }
}
