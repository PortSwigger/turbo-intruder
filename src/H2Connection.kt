package burp
import HeaderEncoder
import com.twitter.hpack.Decoder
import java.io.OutputStream
import java.lang.Exception
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URL
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.net.ssl.*
import kotlin.collections.HashMap

class H2Connection(val target: URL, val seedQueue: Queue<Request>, private val requestQueue: LinkedBlockingQueue<Request>, var requestsPerConnection: Int, val engine: HTTP2RequestEngine) {

    companion object {
        const val CONNECTING = 1
        const val ALIVE = 2
        const val HALFCLOSED = 3
        const val CLOSED = 4

        private const val DEBUG = false

        fun debug(message: String) {
            if (DEBUG) {
                Utils.out("Debug ${Thread.currentThread().id}: $message")
            }
        }

        private fun transformHeader(value: String, name: Boolean = false): String {
            var out = value.replace("^", "\r")
            out = out.replace("~", "\n")
            if (name) {
                out = out.replace("`", ":")
            }
            return out
        }

        fun buildReq(parsedRequest: HTTP2Request): LinkedList<Pair<String, String>> {
            return buildReq(parsedRequest, true)
        }

        fun buildReq(parsedRequest: HTTP2Request, transform: Boolean): LinkedList<Pair<String, String>> {
            val pseudoHeaders = LinkedHashMap<String, String>()
            val headers = LinkedList<Pair<String, String>>()
            val final = LinkedList<Pair<String, String>>()
            var host = ""

            for (header: String in parsedRequest.headers) {
                var name: String
                var value = ""
                if (header.contains(": ")) {
                    val split = header.split(": ", limit = 2)
                    name = split[0]
                    value = split[1]
               } else {
                   name = header
                }

                if (name == "Connection") {
                    continue
                }

                if (name == ":connection") {
                    name = "Connection"
                }

                if (name == "Host" && host == "") {
                    host = value
                }

                if (name == "Cookie") {
                    val cookiesplit = value.split(";")
                    for (cookie: String in cookiesplit) {
                        if (cookie != "") {
                            var fixed = cookie
                            if (transform) {
                                fixed = transformHeader(cookie)
                            }
                            headers.add(Pair("cookie", fixed))
                        }
                    }
                    continue
                }

                if (transform) {
                    name = transformHeader(name, true)
                    value = transformHeader(value, false)
                }
                name = name.lowercase()

                if (name.startsWith(":")) {
                    if (pseudoHeaders.containsKey(name)) {
                        headers.add(Pair(name, value))
                    } else {
                        pseudoHeaders.put(name, value)
                    }
                } else {
                    headers.add(Pair(name, value))
                }
            }

            var stripHost = false

            if (!pseudoHeaders.containsKey(":scheme")) {
                final.add(Pair(":scheme", "https"))
            }
            if (!pseudoHeaders.containsKey(":method")) {
                final.add(Pair(":method", parsedRequest.method))
            }
            if (!pseudoHeaders.containsKey(":path")) {
                final.add(Pair(":path", parsedRequest.path))
            }
            if (!pseudoHeaders.containsKey(":authority")) {
                final.add(Pair(":authority", host))
                stripHost = true // if there's no :authority and there is a Host header, strip the first instance of the host header
            }

            for ((key, value) in pseudoHeaders) {
                final.add(Pair(key, value))
            }

            for ((key, value) in headers) {
                if (stripHost && key.equals("host")) {
                    stripHost = false
                    continue
                }
                final.add(Pair(key, value))
            }

            return final
        }
    }

    var done = false
    val streams: HashMap<Int, Stream> = HashMap()
    var totalQueuedRequests = 0
    private lateinit var socket: Socket
    private lateinit var output: OutputStream
    val decoder = Decoder(4096, 4096)
    var maxConcurrentStreams = 100

    val stateLock = ReentrantReadWriteLock() // todo I have no idea if this is even necessary
    var state: Int = CONNECTING
    var lastCreatedStreamID = -1

    init {
        connect()
    }

    private fun connect() {
        val port = if (target.port == -1) { target.defaultPort } else { target.port }
        if (target.protocol == "https") {
            val sslsf = createSSLSocketFactory()
            target.port
            socket = sslsf.createSocket(target.host, port) as SSLSocket
            val sslp = (socket as SSLSocket).sslParameters
            val clientAPs = arrayOf("h2") // don't offer "http/1.1"
            sslp.applicationProtocols = clientAPs
            (socket as SSLSocket).sslParameters = sslp
            (socket as SSLSocket).startHandshake()
            socket.soTimeout = 10000
            //val ap = (socket as SSLSocket).applicationProtocol
        } else {
            socket = Socket(target.host, port)
            socket.soTimeout = 10000
        }

        output = socket.outputStream
        val message = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        output.write(message.toByteArray())
        val settingsPayload = byteArrayOf(0, 4, 0x7f, -1, -1, -1, // MAXINT window size (Burp match)
                                          0, 2, 0, 0, 0, 0,   // no PUSH (Burp match)
                                          0, 1, 0, 0, 0x10, 0, //  4096 header table size (Burp match)
                                          0, 3, 0, 0, 0x01, 0 // 256 max *concurrent* streams (Burp match)
            )
        val initialSettingsFrame = Frame(0x04, 0x00, 0, settingsPayload)
        sendFrame(initialSettingsFrame)

        val flowControlFrame = Frame(0x08, 0x00, 0, HTTP2Utils.intToFourBytes(2147418112)) // Burp match
        sendFrame(flowControlFrame)

        thread { readForever() }
    }

    fun startSendingRequests() {
        if (state != CONNECTING) {
            return
        }
        state = ALIVE
        thread { writeForever() }
    }


    private fun checkState(): Int {
        if (engine.attackState.get() >= 3) {
            close()
        }
        return state
    }

    private fun req(req: Request) {

        val parsedRequest = HTTP2Request(req.getRequest())
        val built = buildReq(parsedRequest)
        val encoder = HeaderEncoder()
        for ((key, value) in built) {
            encoder.addHeader(key, value)
        }

        val streamID = addStream(req)
        if (parsedRequest.body == null || parsedRequest.body == "") {
            // 5 = 4 + 1 (end headers & end stream)
            req.time = System.nanoTime()
            sendFrame(Frame(0x01, 0x05, streamID, encoder.headers.toByteArray()))
        }
        else {
            //debug("Sending a data frame: '"+parsedRequest.body+"'")
            sendFrame(Frame(0x01, 0x04, streamID, encoder.headers.toByteArray()))
            req.time = System.nanoTime()
            sendFrame(Frame(0x00, 0x01, streamID, parsedRequest.body!!.toByteArray()))
        }
        //Utils.out(request.asBytes().asList())
    }


    fun close() {
        debug("Closing connection...")
        val locked = stateLock.writeLock().tryLock(5, TimeUnit.SECONDS)
        if (locked) {
            state = CLOSED
            stateLock.writeLock().unlock()
            debug("Full close complete")
        }
        else {
            throw Exception("Deadlock closing connection: ${stateLock.readLockCount}")
        }
    }

    private fun readForever() {
        try {
            val input = socket.inputStream
            while (checkState() != CLOSED) {
                if (state == HALFCLOSED && !hasInflightRequests()) {
                    debug("Transitioning halfclosed connection to closed")
                    close()
                    return
                }

                debug("Reading...")

                if (streams.size == 0 && state != CONNECTING) {
                    Thread.sleep(100)
                    continue
                }

                val sizeBuffer = ByteArray(3)
                try {
                    val needToRead = 3
                    var haveRead = 0
                    while (haveRead < needToRead) {
                        //debug("reading inital 3 bytes")
                        if (checkState() == CLOSED) {
                            return
                        }
                        val justRead = input.read(sizeBuffer, haveRead, needToRead - haveRead)
                        if (justRead == -1) {
                            Thread.sleep(10)
                            continue
                        }
                        haveRead += justRead
                    }
                } catch (ex: SocketTimeoutException) {
                    if (hasInflightRequests()) {
                        Utils.out("Socket read timeout with ~" + streams.size + " inflight requests")
                        Utils.out(streams.keys.toString())
                    }
                    close()
                    return
                } catch (ex: SSLProtocolException) {
                    Utils.out("Invoking fullClose due to socket read error")
                    close()
                    return
                }

                val size = HTTP2Utils.threeByteInt(sizeBuffer)


                //debug("Received frame with payload size $size")
                //debug("Raw payload size: " + sizeBuffer.asList())

                // header size is 9 bytes but we already read 3
                val needToRead = size + 6
                val frameBuffer = ByteArray(needToRead)
                var haveRead = 0
                while (haveRead < needToRead) {
                    //debug("reading needToRead")
                    if (checkState() == CLOSED) {
                        return
                    }
                    val justRead = input.read(frameBuffer, haveRead, needToRead - haveRead)
                    if (justRead == -1) {
                        Thread.sleep(10)
                        continue
                    }
                    haveRead += justRead
                }
                passResponseToStream(sizeBuffer + frameBuffer)
            }
        } catch (e: Exception) {
            Utils.out("Killing read thread")
            close()
        }
        debug("Closing read thread...")
    }

    private fun passResponseToStream(frameBytes: ByteArray) {
        val streamID = HTTP2Utils.fourByteInt(frameBytes.sliceArray(5..8))
        //debug("StreamID " + streamID)
        //debug("Whole frame: " + frameBytes.asList())

        if (streamID != 0 && !streams.containsKey(streamID)) {
            throw Exception("Received message on unrecognised or closed stream: $streamID | ${lastCreatedStreamID}")
        }

        streams.putIfAbsent(
                streamID,
                Stream(this, streamID, Request("dud"), true)
        )
        streams[streamID]!!.processFrame(frameBytes)
    }

    private fun writeForever() {
        debug("Starting write thread")
        try {
            var completedSeedQueue = false

            while (state == ALIVE && engine.attackState.get() < 3) {

                // todo use a lock instead, should be faster
                if (streams.size >= maxConcurrentStreams) {
                    Thread.sleep(100)
                    continue
                }

                if (totalQueuedRequests >= requestsPerConnection) {
                    //Utils.out("Reached max streams of "+requestsPerConnection)
                    state = HALFCLOSED
                    return
                }

                val req: Request?

                if (completedSeedQueue) {
                    req = requestQueue.poll(1000, TimeUnit.MILLISECONDS)
                    if (req == null) {
                        if (engine.attackState.get() == 2 && !hasInflightRequests()) {
                            close()
                            done = true
                            return
                        }
                        continue
                    }
                } else {
                    req = seedQueue.poll()
                    if (req == null) {
                        completedSeedQueue = true
                        continue
                    }
                }


                if (state == CLOSED) {
                    requestQueue.put(req)
                    close()
                    return
                }

                try {
                    req(req)
                } catch (ex: SocketException) {
                    requestQueue.put(req)
                    close()
                } catch (ex: SSLProtocolException) {
                    requestQueue.put(req)
                    close()
                }
            }
        } catch (e: Exception) {
            Utils.out("Killing write thread")
            close()
        } finally {
            engine.completedLatch.countDown()
        }
        debug("Exiting write thread")
    }

    fun hasInflightRequests(): Boolean {
        if (streams.size == 0) {
            return false
        }

        if (streams.size > 1) {
            return true
        }

        return !streams.containsKey(0)
    }

    fun getInflightRequests(): List<Request> {
        if (state != CLOSED) {
            throw Exception("Access to in-flight requests is hazardous on live connections")
        }
        return streams.values.map{it.req}
    }

//    private fun ping() {
//        // issue a ping
//        val ping = Frame(0x06, 0x00, 0x00, byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08))
//        socket.outputStream.write(ping.asBytes())
//        socket.outputStream.flush()
//    }

    fun sendFrame(frame: Frame) {
        socket.outputStream.write(frame.asBytes())
        socket.outputStream.flush()
    }

    private fun addStream(req: Request): Int {

        if (state == CLOSED || totalQueuedRequests > requestsPerConnection) {
            throw SocketException("Attempt to create a stream on a dud connection")
        }

        totalQueuedRequests += 1
        lastCreatedStreamID += 2
        val stream = Stream(this, lastCreatedStreamID, req,true)
        streams[lastCreatedStreamID] = stream
        debug("Sending on stream ${stream.streamID}")

        if (stream.streamID % 2 == 0 && !streams.containsKey(stream.streamID)) {
            throw Exception("Client-initiated frames must have an odd ID. Not ${stream.streamID}")
        }

        return stream.streamID
    }

    private fun createSSLSocketFactory(): SSLSocketFactory {
        val trustingSslContext = SSLContext.getInstance("TLS")
        trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager()), null)
        return trustingSslContext.socketFactory
    }

    private class TrustingTrustManager : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    }
}


class HTTP2Request(raw: String) {
    val method: String
    val path: String
    val headers: List<String>
    var body: String? = null

    init {
        val start = raw.split(" ", limit=3)
        method = start[0]
        path = start[1]
        val prepped: String
        if (!raw.contains("\r\n")) {
            prepped = raw.replace("\n", "\r\n")
        } else {
            prepped = raw
        }
        val split = prepped.split("\r\n\r\n", ignoreCase = false, limit = 2)
        headers = split[0].split("\r\n").drop(1).dropLastWhile { it == ""}
        if (split.size > 1) {
            body = split[1]
        }
    }
}