package burp
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.Exception
import java.util.*
import java.util.Arrays.asList
import kotlin.collections.HashMap

open class Request(val template: String, val words: List<String?>, val learnBoring: Int) {

    var response: String? = null
    var details: IResponseVariations? = null
    var engine: RequestEngine? = null
    var connectionID: Int? = null
    var callback: ((Request, Boolean) -> Boolean)? = null
    var gate: Floodgate? = null
    var time: Long = 0

    private val attributes: HashMap<String, Any> = HashMap()

    val code: Int get() = getAttribute("code") as Int
    val status: Int get() = code
    val length: Int get() = getAttribute("length") as Int
    val wordcount: Int get() = getAttribute("wordcount") as Int

    fun invokeCallback(isinteresting: Boolean) {
        if (callback != null) {
            callback!!.invoke(this, isinteresting)
        }
        else {
            engine!!.callback(this, isinteresting)
        }
    }

    fun getAttribute(name: String): Any? {
        if (name in attributes) {
            return attributes.get(name)
        }

        val result = when(name) {
            "length" -> response?.length ?: 0
            "wordcount" -> (response ?: "").split(Regex("[^a-zA-Z0-9]")).size
            "code" -> calculateCode()
            else -> "Unknown attribute"
        }

        attributes.put(name, result)

        return result
    }

    fun calculateCode(): Int {
        if (response == null) {
            return 0
        }
        try {
            return Integer.parseInt(response?.split(" ", ignoreCase = false, limit = 3)?.get(1))
        } catch (e: Exception) {
            return 0
        }
    }

    constructor(template: String): this(template, emptyList<String>(), 0)

    fun getBurpRequest(): IHttpRequestResponse {
        return BurpRequest(this)
    }

    fun getRequest(): String {
        if (words.isEmpty()) {
            return template
        }

        if (!template.contains("%s")) {
            Utils.out("Bad base request - nowhere to inject payload")
        }

        var req = template

        for (w in words){
            req = req.replaceFirst("%s", w.toString(), false)
        }

        if (req.contains("%s")) {

            Utils.out("Bad base request "+words.size+" words and more %s")
        }

        return req
    }

    fun getRequestAsBytes(): ByteArray {
        return fixContentLength(getRequest().toByteArray(Charsets.ISO_8859_1))
    }

    fun getResponseAsBytes(): ByteArray? {
        return response?.toByteArray(Charsets.ISO_8859_1)
    }

    fun fixContentLength(request: ByteArray): ByteArray {
        if (String(request).contains("Content-Length: ")) {
            val start = getBodyStart(request)
            val contentLength = request.size - start
            try {
                return setHeader(request, "Content-Length", Integer.toString(contentLength))
            } catch (e: RuntimeException) {
                return request
            }

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

class BurpRequest(val req: Request): IHttpRequestResponse {


    override fun getRequest(): ByteArray {
        return req.getRequestAsBytes()
    }

    override fun getResponse(): ByteArray? {
        return req.getResponseAsBytes()
    }

    override fun getHttpService(): IHttpService {
        val url = req.engine!!.target
        return Utils.callbacks.helpers.buildHttpService(url.host, url.port, url.protocol)
    }

    override fun getComment(): String? {
        return null
    }

    override fun setComment(comment: String?) {
    }

    override fun getHighlight(): String? {
        return null
    }

    override fun setResponse(message: ByteArray?) {
    }

    override fun setRequest(message: ByteArray?) {
    }

    override fun setHttpService(httpService: IHttpService?) {
    }

    override fun setHighlight(color: String?) {
    }
}

class StubRequest(val req: ByteArray, val service: IHttpService): IHttpRequestResponse {
    override fun getRequest(): ByteArray {
        return req
    }

    override fun getResponse(): ByteArray? {
        return null
    }

    override fun getHttpService(): IHttpService {
        return service
    }

    override fun getComment(): String? {
        return null
    }

    override fun setComment(comment: String?) {
    }

    override fun getHighlight(): String? {
        return null
    }

    override fun setResponse(message: ByteArray?) {
    }

    override fun setRequest(message: ByteArray?) {
    }

    override fun setHttpService(httpService: IHttpService?) {
    }

    override fun setHighlight(color: String?) {
    }
}