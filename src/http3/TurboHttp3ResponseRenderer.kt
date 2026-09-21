package http3

import hp3.h3.Http3Response
import hp3.translate.ReasonPhrases
import java.io.ByteArrayOutputStream

object TurboHttp3ResponseRenderer {
    private const val CRLF = "\r\n"

    @JvmStatic
    fun render(response: Http3Response, authoredVersion: String): ByteArray {
        val version = authoredVersion.takeIf { it.startsWith("HTTP/") } ?: "HTTP/1.1"
        val status = response.status().takeIf { it >= 0 } ?: 0
        val head = StringBuilder()
            .append(version)
            .append(' ')
            .append(status)
            .append(' ')
            .append(ReasonPhrases.forStatus(status))
            .append(CRLF)

        var statusSeen = false
        response.fields().forEach { field ->
            if (!statusSeen && field.name() == ":status") {
                statusSeen = true
            } else {
                head.append(field.name()).append(": ").append(field.value()).append(CRLF)
            }
        }
        response.trailers().forEach { field ->
            head.append(field.name()).append(": ").append(field.value()).append(CRLF)
        }
        head.append(CRLF)

        return ByteArrayOutputStream().apply {
            writeBytes(head.toString().toByteArray(Charsets.ISO_8859_1))
            writeBytes(response.body())
        }.toByteArray()
    }
}
