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
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.net.ssl.*
import kotlin.collections.HashMap

class Connection(val target: URL, val seedQueue: Queue<Request>, private val requestQueue: LinkedBlockingQueue<Request>, var requestsPerConnection: Int, val engine: HTTP2RequestEngine) {

    companion object {
        const val CONNECTING = 1
        const val ALIVE = 2
        const val HALFCLOSED = 3
        const val CLOSED = 4

        private const val DEBUG = false

        fun debug(message: String) {
            if (DEBUG) {
                Utils.out("Debug: $message")
            }
        }
    }

    var done = false
    val streams: HashMap<Int, Stream> = HashMap()
    var totalQueuedRequests = 0
    private lateinit var socket: Socket
    private lateinit var output: OutputStream
    val decoder = Decoder(4096, 4096)

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
            val clientAPs = arrayOf("h2")
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
        val settingsPayload = byteArrayOf(0, 4, 0x00, -1, -1, -1, // high window size
                                          0, 2, 0, 0, 0, 0,   // no PUSH
                                          0, 1, 0, 1, 0, 0, //  4096 header table size
                                          0, 3, 0, 0, 1, 0 // 256 max *concurrent* streams
            )
        val initialSettingsFrame = Frame(0x04, 0x00, 0, settingsPayload)
        sendFrame(initialSettingsFrame)

        val flowControlFrame = Frame(0x08, 0x00, 0, HTTP2Utils.intToFourBytes(2147418112))
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

    private fun req(req: Request) {

        val parsedRequest = HTTP2Request(req.getRequest())

        val encoder = HeaderEncoder()

        encoder.addHeader(":scheme", target.protocol)
        encoder.addHeader(":method", parsedRequest.method)
        encoder.addHeader(":path", parsedRequest.path)

        for (header: String in parsedRequest.headers) {
            var (name, value) = header.split(": ", limit=2)
            if (name == "Host") {
                encoder.addHeader(":authority", value)
                continue
            }
            if (name == "Connection") {
                continue
            }
            name = name.replace("^", "\r")
            name = name.replace("~", "\n")
            value = value.replace("^", "\r")
            value = value.replace("~", "\n")
            encoder.addHeader(name.toLowerCase(), value)
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
            while (state != CLOSED) {
                if (state == HALFCLOSED && streams.size == 0) {
                    debug("Transitioning halfclosed connection to closed")
                    close()
                    return
                }

                if (streams.size == 0 && state != CONNECTING) {
                    Thread.sleep(100)
                    continue
                }

                val sizeBuffer = ByteArray(3)
                try {
                    val needToRead = 3
                    var haveRead = 0
                    while (haveRead < needToRead) {
                        if (state == CLOSED) {
                            return
                        }
                        val justRead = input.read(sizeBuffer, haveRead, needToRead - haveRead)
                        if (justRead == -1) {
                            continue
                        }
                        haveRead += justRead
                    }
                } catch (ex: SocketTimeoutException) {
                    if (streams.size > 0) {
                        Utils.out("Socket read timeout with " + streams.size + " inflight requests")
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
                    if (state == CLOSED) {
                        return
                    }
                    val justRead = input.read(frameBuffer, haveRead, needToRead - haveRead)
                    if (justRead == -1) {
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
        try {
            var completedSeedQueue = false

            while (state == ALIVE) {

                if (totalQueuedRequests >= requestsPerConnection) {
                    //Utils.out("Reached max streams of "+requestsPerConnection)
                    state = HALFCLOSED
                    return
                }

                val req: Request?

                if (completedSeedQueue) {
                    req = requestQueue.poll(1000, TimeUnit.MILLISECONDS)
                    if (req == null) {
                        if (engine.attackState.get() == 2 && streams.size == 0) {
                            close()
                            done = true
                            engine.completedLatch.countDown()
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
        }
    }

    fun hasInflightRequests(): Boolean {
        return streams.size != 0
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