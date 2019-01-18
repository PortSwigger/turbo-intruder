package burp
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.*

open class Request(val template: String, val word: String?, val learnBoring: Int) {

    var response: String? = null
    var details: IResponseVariations? = null

    constructor(template: String): this(template, null, 0)

    fun getRequest(): String {
        if (word == null) {
            return template
        }

        if (!template.contains("%s")) {
            Utils.out("Bad base request - nowhere to inject payload")
        }

        val req = template.replace("%s", word)

        if (req.contains("%s")) {
            Utils.out("Bad base request - contains too many %s")
        }

        return template.replace("%s", word)
    }

    fun getRawRequest(): ByteArray {
        return fixContentLength(getRequest().toByteArray(Charsets.ISO_8859_1))
    }

    fun getRawResponse(): ByteArray? {
        return response?.toByteArray(Charsets.ISO_8859_1)
    }


    fun fixContentLength(request: ByteArray): ByteArray {
        if (String(request).contains("Content-Length: ")) {
            val start = getBodyStart(request)
            val contentLength = request.size - start
            return setHeader(request, "Content-Length", Integer.toString(contentLength))
        } else {
            return request
        }
    }

    fun setHeader(request: ByteArray, header: String, value: String): ByteArray {
        val offsets = getHeaderOffsets(request, header)
        val outputStream = ByteArrayOutputStream()
        try {
            outputStream.write(Arrays.copyOfRange(request, 0, offsets[1]))
            outputStream.write(value.toByteArray(Charsets.ISO_8859_1))
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.size))
            return outputStream.toByteArray()
        } catch (e: IOException) {
            throw RuntimeException("Request creation unexpectedly failed")
        } catch (e: NullPointerException) {
            Utils.out("header locating fail: $header")
            throw RuntimeException("Can't find the header")
        }

    }

    fun getHeaderOffsets(request: ByteArray, header: String): IntArray {
        var i = 0
        val end = request.size
        while (i < end) {
            val line_start = i
            while (i < end && request[i++] != ' '.toByte()) {
            }
            val header_name = Arrays.copyOfRange(request, line_start, i - 2)
            val headerValueStart = i
            while (i < end && request[i++] != '\n'.toByte()) {
            }
            if (i == end) {
                break
            }

            val header_str = String(header_name) // todo check this actually works

            if (header == header_str) {
                return intArrayOf(line_start, headerValueStart, i - 2)
            }

            if (i + 2 < end && request[i] == '\r'.toByte() && request[i + 1] == '\n'.toByte()) {
                break
            }
        }
        throw RuntimeException("Couldn't find header: '$header'")
    }

    fun getBodyStart(response: ByteArray): Int {
        var i = 0
        var newlines_seen = 0
        while (i < response.size) {
            val x = response[i]
            if (x == '\n'.toByte()) {
                newlines_seen++
            } else if (x != '\r'.toByte()) {
                newlines_seen = 0
            }

            if (newlines_seen == 2) {
                break
            }
            i += 1
        }


        while (i < response.size && (response[i] == ' '.toByte() || response[i] == '\n'.toByte() || response[i] == '\r'.toByte())) {
            i++
        }

        return i
    }

}