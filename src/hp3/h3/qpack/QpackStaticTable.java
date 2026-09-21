package hp3.h3.qpack;

import java.util.HashMap;
import java.util.Map;

/**
 * The QPACK static table, RFC 9204 Appendix A — 99 entries, indexed from 0.
 *
 * <p>Generated from the RFC's XML source rather than transcribed, and rather than parsed from the
 * plain-text rendering: the text tables wrap long values across lines without marking whether the
 * break fell mid-word, which silently corrupts entries such as index 44
 * ({@code content-type: application/dns-message}).
 *
 * <p>Note this is indexed from 0, unlike the HPACK static table which is indexed from 1.
 *
 * <p>DO NOT EDIT BY HAND.
 */
public final class QpackStaticTable {

    private static final String[][] ENTRIES = {
            {":authority", ""},
            {":path", "/"},
            {"age", "0"},
            {"content-disposition", ""},
            {"content-length", "0"},
            {"cookie", ""},
            {"date", ""},
            {"etag", ""},
            {"if-modified-since", ""},
            {"if-none-match", ""},
            {"last-modified", ""},
            {"link", ""},
            {"location", ""},
            {"referer", ""},
            {"set-cookie", ""},
            {":method", "CONNECT"},
            {":method", "DELETE"},
            {":method", "GET"},
            {":method", "HEAD"},
            {":method", "OPTIONS"},
            {":method", "POST"},
            {":method", "PUT"},
            {":scheme", "http"},
            {":scheme", "https"},
            {":status", "103"},
            {":status", "200"},
            {":status", "304"},
            {":status", "404"},
            {":status", "503"},
            {"accept", "*/*"},
            {"accept", "application/dns-message"},
            {"accept-encoding", "gzip, deflate, br"},
            {"accept-ranges", "bytes"},
            {"access-control-allow-headers", "cache-control"},
            {"access-control-allow-headers", "content-type"},
            {"access-control-allow-origin", "*"},
            {"cache-control", "max-age=0"},
            {"cache-control", "max-age=2592000"},
            {"cache-control", "max-age=604800"},
            {"cache-control", "no-cache"},
            {"cache-control", "no-store"},
            {"cache-control", "public, max-age=31536000"},
            {"content-encoding", "br"},
            {"content-encoding", "gzip"},
            {"content-type", "application/dns-message"},
            {"content-type", "application/javascript"},
            {"content-type", "application/json"},
            {"content-type", "application/x-www-form-urlencoded"},
            {"content-type", "image/gif"},
            {"content-type", "image/jpeg"},
            {"content-type", "image/png"},
            {"content-type", "text/css"},
            {"content-type", "text/html; charset=utf-8"},
            {"content-type", "text/plain"},
            {"content-type", "text/plain;charset=utf-8"},
            {"range", "bytes=0-"},
            {"strict-transport-security", "max-age=31536000"},
            {"strict-transport-security", "max-age=31536000; includesubdomains"},
            {"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
            {"vary", "accept-encoding"},
            {"vary", "origin"},
            {"x-content-type-options", "nosniff"},
            {"x-xss-protection", "1; mode=block"},
            {":status", "100"},
            {":status", "204"},
            {":status", "206"},
            {":status", "302"},
            {":status", "400"},
            {":status", "403"},
            {":status", "421"},
            {":status", "425"},
            {":status", "500"},
            {"accept-language", ""},
            {"access-control-allow-credentials", "FALSE"},
            {"access-control-allow-credentials", "TRUE"},
            {"access-control-allow-headers", "*"},
            {"access-control-allow-methods", "get"},
            {"access-control-allow-methods", "get, post, options"},
            {"access-control-allow-methods", "options"},
            {"access-control-expose-headers", "content-length"},
            {"access-control-request-headers", "content-type"},
            {"access-control-request-method", "get"},
            {"access-control-request-method", "post"},
            {"alt-svc", "clear"},
            {"authorization", ""},
            {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
            {"early-data", "1"},
            {"expect-ct", ""},
            {"forwarded", ""},
            {"if-range", ""},
            {"origin", ""},
            {"purpose", "prefetch"},
            {"server", ""},
            {"timing-allow-origin", "*"},
            {"upgrade-insecure-requests", "1"},
            {"user-agent", ""},
            {"x-forwarded-for", ""},
            {"x-frame-options", "deny"},
            {"x-frame-options", "sameorigin"},
    };

    /** Exact (name, value) to the lowest index holding it. */
    private static final Map<String, Integer> BY_NAME_AND_VALUE = new HashMap<>();
    /** Name to the lowest index holding it, for literal-with-name-reference. */
    private static final Map<String, Integer> BY_NAME = new HashMap<>();

    static {
        for (int i = 0; i < ENTRIES.length; i++) {
            BY_NAME_AND_VALUE.putIfAbsent(ENTRIES[i][0] + '\u0000' + ENTRIES[i][1], i);
            BY_NAME.putIfAbsent(ENTRIES[i][0], i);
        }
    }

    private QpackStaticTable() {
    }

    public static int size() {
        return ENTRIES.length;
    }

    public static String name(int index) {
        return ENTRIES[index][0];
    }

    public static String value(int index) {
        return ENTRIES[index][1];
    }

    /** Lowest index whose name and value both match exactly, or -1. */
    public static int findExact(String name, String value) {
        return BY_NAME_AND_VALUE.getOrDefault(name + '\u0000' + value, -1);
    }

    /** Lowest index whose name matches exactly, or -1. */
    public static int findName(String name) {
        return BY_NAME.getOrDefault(name, -1);
    }
}
