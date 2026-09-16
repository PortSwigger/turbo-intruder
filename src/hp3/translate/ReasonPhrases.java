package hp3.translate;

import java.util.HashMap;
import java.util.Map;

/**
 * Standard reason phrases, from the IANA HTTP Status Code Registry.
 *
 * <p>Needed because neither HTTP/2 nor HTTP/3 carries a reason phrase — RFC 9114 section 4.1.2 and
 * RFC 9113 section 8.3.2 define only {@code :status} — yet Burp writes one anyway when it renders
 * an HTTP/2 response, emitting {@code HTTP/2 200 OK}. Matching that convention is what makes an
 * adapted response indistinguishable from one Burp produced itself.
 *
 * <p>It also matters more than cosmetically. Turbo Intruder derives its Status column with
 * {@code response.split(" ", limit = 3)[1]}, splitting on spaces alone, so a status line ending
 * immediately after the code leaves it parsing {@code "200\r\ncontent-type:"} and falling into a
 * {@code catch} that returns 0. A status line without a reason phrase silently breaks other
 * people's tools.
 *
 * <p>Generated from the registry rather than transcribed. DO NOT EDIT BY HAND.
 */
public final class ReasonPhrases {

    private static final Map<Integer, String> REASONS = new HashMap<>();

    static {
        REASONS.put(100, "Continue");
        REASONS.put(101, "Switching Protocols");
        REASONS.put(102, "Processing");
        REASONS.put(103, "Early Hints");
        REASONS.put(104, "Upload Resumption Supported");
        REASONS.put(200, "OK");
        REASONS.put(201, "Created");
        REASONS.put(202, "Accepted");
        REASONS.put(203, "Non-Authoritative Information");
        REASONS.put(204, "No Content");
        REASONS.put(205, "Reset Content");
        REASONS.put(206, "Partial Content");
        REASONS.put(207, "Multi-Status");
        REASONS.put(208, "Already Reported");
        REASONS.put(226, "IM Used");
        REASONS.put(300, "Multiple Choices");
        REASONS.put(301, "Moved Permanently");
        REASONS.put(302, "Found");
        REASONS.put(303, "See Other");
        REASONS.put(304, "Not Modified");
        REASONS.put(305, "Use Proxy");
        REASONS.put(307, "Temporary Redirect");
        REASONS.put(308, "Permanent Redirect");
        REASONS.put(400, "Bad Request");
        REASONS.put(401, "Unauthorized");
        REASONS.put(402, "Payment Required");
        REASONS.put(403, "Forbidden");
        REASONS.put(404, "Not Found");
        REASONS.put(405, "Method Not Allowed");
        REASONS.put(406, "Not Acceptable");
        REASONS.put(407, "Proxy Authentication Required");
        REASONS.put(408, "Request Timeout");
        REASONS.put(409, "Conflict");
        REASONS.put(410, "Gone");
        REASONS.put(411, "Length Required");
        REASONS.put(412, "Precondition Failed");
        REASONS.put(413, "Content Too Large");
        REASONS.put(414, "URI Too Long");
        REASONS.put(415, "Unsupported Media Type");
        REASONS.put(416, "Range Not Satisfiable");
        REASONS.put(417, "Expectation Failed");
        REASONS.put(421, "Misdirected Request");
        REASONS.put(422, "Unprocessable Content");
        REASONS.put(423, "Locked");
        REASONS.put(424, "Failed Dependency");
        REASONS.put(425, "Too Early");
        REASONS.put(426, "Upgrade Required");
        REASONS.put(428, "Precondition Required");
        REASONS.put(429, "Too Many Requests");
        REASONS.put(431, "Request Header Fields Too Large");
        REASONS.put(451, "Unavailable For Legal Reasons");
        REASONS.put(500, "Internal Server Error");
        REASONS.put(501, "Not Implemented");
        REASONS.put(502, "Bad Gateway");
        REASONS.put(503, "Service Unavailable");
        REASONS.put(504, "Gateway Timeout");
        REASONS.put(505, "HTTP Version Not Supported");
        REASONS.put(506, "Variant Also Negotiates");
        REASONS.put(507, "Insufficient Storage");
        REASONS.put(508, "Loop Detected");
        REASONS.put(510, "Not Extended");
        REASONS.put(511, "Network Authentication Required");
    }

    private ReasonPhrases() {
    }

    /** The standard phrase for {@code status}, or an empty string if the registry has none. */
    public static String forStatus(int status) {
        return REASONS.getOrDefault(status, "");
    }
}
