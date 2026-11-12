package burp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

/**
 * Requests reach the engines through a String, so every byte has to survive
 * bytes -> String -> bytes. Burp's own helpers guarantee that (a byte 0xYZ becomes a char
 * 0x00YZ and back), and [Utils.stringToBytes] honours the same contract. Any conversion in
 * between that applies a real charset silently rewrites the payload instead.
 */
class RequestEncodingTest {

    /** A body that only an opaque byte-preserving conversion can round trip. */
    private val binaryBody = byteArrayOf(
        0x00, 0x01, 0x02, 0x09, 0x0A, 0x0D, 0x1F, // control characters, including NUL
        0x7F,
        0x80.toByte(), 0x81.toByte(), 0x9C.toByte(), // lone high bytes: invalid UTF-8
        0xC3.toByte(), 0xA9.toByte(),               // "é" as UTF-8: valid, and collapses if decoded
        0xE2.toByte(), 0x82.toByte(), 0xAC.toByte(), // "€" as UTF-8, three bytes
        0xF0.toByte(), 0x9F.toByte(), 0x92.toByte(), 0xA9.toByte(), // emoji, four bytes
        0xFE.toByte(), 0xFF.toByte(),
    )

    private fun ascii(value: String): ByteArray = value.toByteArray(Charsets.ISO_8859_1)

    private fun rawRequest(
        body: ByteArray,
        extraHeaders: ByteArray = ByteArray(0),
        declaredLength: Int = body.size,
    ): ByteArray = ascii(
        "POST /binary HTTP/1.1\r\n" +
            "Host: example.net\r\n" +
            "Content-Type: application/octet-stream\r\n",
    ) + extraHeaders + ascii("Content-Length: $declaredLength\r\n\r\n") + body

    /** What Burp hands over: byte 0xYZ becomes char 0x00YZ, with no charset involved. */
    private fun asBurpString(raw: ByteArray): String = String(raw, Charsets.ISO_8859_1)

    @Test
    fun `binary body is sent byte for byte`() {
        val raw = rawRequest(binaryBody)
        val sent = Request(asBurpString(raw), emptyList()).getRequestAsBytes()
        assertArrayEquals(raw, sent)
    }

    @Test
    fun `binary body is sent byte for byte when content length fixing is disabled`() {
        val raw = rawRequest(binaryBody)
        val request = Request(asBurpString(raw), emptyList()).also { it.autoFixContentLength = false }
        assertArrayEquals(raw, request.getRequestAsBytes())
    }

    @Test
    fun `high bytes in a header value are preserved`() {
        // A raw cookie or a non-ASCII custom header goes through the same conversion as the body.
        val raw = rawRequest(binaryBody, ascii("X-Raw: a") + byteArrayOf(0x80.toByte(), 0xE2.toByte(), 0x82.toByte(), 0xAC.toByte()) + ascii("b\r\n"))
        val sent = Request(asBurpString(raw), emptyList()).getRequestAsBytes()
        assertArrayEquals(raw, sent)
    }

    @Test
    fun `content length is rewritten to the real body length`() {
        // The declared length is wrong on the wire; the engine corrects it without touching the body.
        val raw = rawRequest(binaryBody, declaredLength = 1)
        val sent = Request(asBurpString(raw), emptyList()).getRequestAsBytes()
        assertArrayEquals(rawRequest(binaryBody), sent)
    }
}
