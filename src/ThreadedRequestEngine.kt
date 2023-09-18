package burp

//import jdk.net.ExtendedSocketOptions
import burp.api.montoya.utilities.CompressionType
import burp.api.montoya.utilities.CompressionUtils
import java.io.*
import java.net.*
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import javax.net.SocketFactory
import javax.net.ssl.*
import kotlin.IllegalStateException
import kotlin.concurrent.thread

open class ThreadedRequestEngine(url: String, val threads: Int, maxQueueSize: Int, val readFreq: Int, val requestsPerConnection: Int, override val maxRetriesPerRequest: Int, override var idleTimeout: Long = 0, override val callback: (Request, Boolean) -> Boolean, var timeout: Int, override var readCallback: ((String) -> Boolean)?, val readSize: Int, val resumeSSL: Boolean, var explodeOnEarlyRead: Boolean = false): RequestEngine() {

    private val connectedLatch = CountDownLatch(threads)

    private val threadPool = ArrayList<Thread>()

    private val IGNORE_LENGTH = false

    var domains = HashSet<String>()

    init {

        idleTimeout *= 1000

        try {
            target = URL(url)

            requestQueue = if (maxQueueSize > 0) {
                LinkedBlockingQueue(maxQueueSize)
            }
            else {
                LinkedBlockingQueue()
            }

            completedLatch = CountDownLatch(threads)
            val retryQueue = LinkedBlockingQueue<Request>()
            val ipAddress = InetAddress.getByName(target.host)
            val port = if (target.port == -1) { target.defaultPort } else { target.port }

            val trustingSslSocketFactory = createSSLSocketFactory()

            Utils.err("Establishing $threads connection to $url ...");
            for(j in 1..threads) {
                threadPool.add(
                    thread {
                        sendRequests(target, trustingSslSocketFactory, ipAddress, port, retryQueue, completedLatch, readFreq, requestsPerConnection, connectedLatch)
                    }
                )
            }
        } catch(e: Exception) {
            if (Utils.gotBurp && !Utils.unloaded) {
                Utils.callbacks.removeExtensionStateListener(this)
            }
            throw e
        }

    }

    companion object {

        fun uncompressIfNecessary(headers: String, body: String): String {
            if (headers.lowercase().indexOf("content-encoding: ") == -1) {
                return body
            }
            val compressionType: CompressionType
            if (headers.lowercase().indexOf("content-encoding: gzip") != -1) {
                compressionType = CompressionType.GZIP
            } else if (headers.lowercase().indexOf("content-encoding: deflate") != -1) {
                compressionType = CompressionType.DEFLATE
            } else if (headers.lowercase().indexOf("content-encoding: br") != -1) {
                compressionType = CompressionType.BROTLI
            } else {
                return body
            }
            val decompressed = Utils.montoyaApi.utilities().compressionUtils().decompress(burp.api.montoya.core.ByteArray.byteArray(body), compressionType)
            return Utils.montoyaApi.utilities().byteUtils().convertToString(decompressed.bytes)
        }

        fun ungzip(compressed: ByteArray): String {
            if (compressed.isEmpty()) {
                return ""
            }

            val out = ByteArrayOutputStream()
            try {
                val bytesIn = ByteArrayInputStream(compressed)
                val unzipped = GZIPInputStream(bytesIn)
                while (true) {
                    val bytes = ByteArray(1024)
                    val read = unzipped.read(bytes, 0, 1024)
                    if (read <= 0) {
                        break
                    }
                    out.write(bytes, 0, read)
                }
            } catch (e: IOException) {
                Utils.err("GZIP decompression failed - possible partial response. Using undecompressed bytes instead.")
                return String(compressed)
            }

            return String(out.toByteArray())
        }


    }
    fun createSSLSocketFactory(): SSLSocketFactory {
        val trustingSslContext = SSLContext.getInstance("TLS")
        trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager(this)), null)
        return trustingSslContext.socketFactory
    }

    // val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("localhost", 6574))

    override fun start(timeout: Int) {
        connectedLatch.await(timeout.toLong(), TimeUnit.SECONDS)
        attackState.set(1)
        start = System.nanoTime()
    }

    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String?): Request {
        var prepared = template

        if (Utilities.isHTTP2(prepared.toByteArray())) {
            prepared = prepared.replaceFirst("HTTP/2\r\n", "HTTP/1.1\r\n")
        }

        if(Utils.getHeaders(prepared).contains("Connection: close")) {
            prepared = prepared.replaceFirst("Connection: close", "Connection: keep-alive")
        }

        return Request(prepared, payloads, learnBoring?: 0, label)
    }

    private fun sendRequests(url: URL, trustingSslSocketFactory: SSLSocketFactory, ipAddress: InetAddress?, port: Int, retryQueue: LinkedBlockingQueue<Request>, completedLatch: CountDownLatch, baseReadFreq: Int, baseRequestsPerConnection: Int, connectedLatch: CountDownLatch) {
        val readFreq = baseReadFreq
        val inflight = ArrayDeque<Request>()
        val requestsPerConnection = baseRequestsPerConnection
        var connected = false
        var reqWithResponse: Request? = null
        var answeredRequests = 0
        val badWords = HashSet<String>()
        var consecutiveFailedConnections = 0
        var startTime: Long = 0
        var reuseSSL = resumeSSL

        while (!shouldAbandonAttack()) {
            try {

                val socket: Socket?
                try {
                    socket = if (url.protocol == "https") {
                        if (reuseSSL) {
                            trustingSslSocketFactory.createSocket(ipAddress, port)
                        } else {
                            createSSLSocketFactory().createSocket(ipAddress, port)
                        }
                    } else {
                        SocketFactory.getDefault().createSocket(ipAddress, port)
                    }
                }
                catch (ex: Exception) {
                    Utils.out("Thread failed to connect")
                    retries.getAndIncrement()
                    val stackTrace = StringWriter()
                    ex.printStackTrace(PrintWriter(stackTrace))
                    Utils.err(stackTrace.toString())
                    consecutiveFailedConnections += 1
                    val sleep = Math.pow(2.0, consecutiveFailedConnections.toDouble())
                    Thread.sleep(sleep.toLong() * 200)
                    continue
                }
                val connectionID = connections.incrementAndGet()
                //(socket as SSLSocket).session.peerCertificates
                socket!!.soTimeout = timeout * 1000
                socket.tcpNoDelay = true
                socket.receiveBufferSize = readSize
                socket.keepAlive = true
                // socket.setOption(ExtendedSocketOptions.TCP_KEEPIDLE, 30)
                // todo tweak other TCP options for max performance

                if(!connected) {
                    connected = true
                    connectedLatch.countDown()
                    while(!Utils.unloaded && attackState.get() == 0 && !shouldAbandonAttack()) {
                        Thread.sleep(10)
                    }
                }

                consecutiveFailedConnections = 0


                var requestsSent = 0
                answeredRequests = 0
                while (requestsSent < requestsPerConnection && !shouldAbandonAttack()) {

                    var readCount = 0
                    startTime = 0
                    var endTime: Long = 0
                    var buffer = ""

                    for (j in 1..readFreq) {
                        if (requestsSent >= requestsPerConnection) {
                            break
                        }

                        var req = retryQueue.poll()
                        while (req == null && !shouldAbandonAttack()) {
                            req = requestQueue.poll(100, TimeUnit.MILLISECONDS)

                            if (req == null) {
                                if (readCount > 0) {
                                    break
                                }
                                if(attackState.get() >= 2) {
                                    completedLatch.countDown()
                                    return
                                }
                            }
                        }

                        if (req == null) break

                        inflight.addLast(req)
                        val byteReq = req.getRequestAsBytes()
                        val outputstream = socket.getOutputStream()
                        if (req.gate != null) {
                            val withHold = 1
                            outputstream.write(byteReq, 0, byteReq.size-withHold)
                            req.gate!!.waitForGo()
                            startTime = System.nanoTime()
                            outputstream.write(byteReq, byteReq.size-withHold, withHold)
                        }
                        else if (req.pauseBefore != 0) {
                            val end: Int
                            if (req.pauseBefore < 0) {
                                end = byteReq.size + req.pauseBefore
                            } else {
                                end = req.pauseBefore - 1 // since it's 0-indexed
                            }
                            val part1 = byteReq.sliceArray(0 until end)
                            //Utils.out("'"+Utilities.helpers.bytesToString(part1)+"'")
                            outputstream.write(part1)
                            startTime = System.nanoTime()

                            waitForData(socket, req.pauseTime)

                            val part2 = byteReq.sliceArray(end until byteReq.size)
                            outputstream.write(part2)
                            //Utils.out("'"+Utilities.helpers.bytesToString(part2)+"'")
                        } else if (!req.pauseMarkers.isEmpty()) {
                            var i = 0
                            startTime = System.nanoTime()
                            // pauses *after* sending the pauseMarker
                            while (i < byteReq.size && !shouldAbandonAttack()) {
                                var pausePoint = -1
                                //val z: ByteArray = req.pauseMarkers.get(0)
                                for (pauseMarker in req.pauseMarkers) {
                                    val pauseBytes = pauseMarker.toByteArray(Charsets.ISO_8859_1)
                                    pausePoint = Utils.helpers.indexOf(byteReq, pauseBytes, true, i, byteReq.size)
                                    if (pausePoint != -1) {
                                        outputstream.write(byteReq.sliceArray(i until (pausePoint+pauseBytes.size)))
                                        buffer = waitForData(socket, req.pauseTime)
                                        i = pausePoint + pauseBytes.size
                                        break
                                    }
                                }

                                if (pausePoint == -1) {
                                    outputstream.write(byteReq.sliceArray(i until byteReq.size))
                                    break
                                }

                            }
                        }
                        else {
                            outputstream.write(byteReq)
                            startTime = System.nanoTime()
                        }

                        readCount++
                        requestsSent++

                    }

                    val readBuffer = ByteArray(readSize)

                    for (k in 1..readCount) {

                        var bodyStart = buffer.indexOf("\r\n\r\n")
                        if (bodyStart != -1) {
                            endTime = System.nanoTime()
                        }

                        while (bodyStart == -1 && !shouldAbandonAttack()) {
                            val len = socket.getInputStream().read(readBuffer)
                            if(len == -1) {
                                break
                            }
                            endTime = System.nanoTime()

                            val read = Utils.bytesToString(readBuffer.copyOfRange(0, len))
                            triggerReadCallback(read)
                            buffer += read
                            bodyStart = buffer.indexOf("\r\n\r\n")
                        }

                        val contentLength = getContentLength(buffer)

                        if (buffer.isEmpty()) {
                            throw ConnectException("No response")
                        } else if (bodyStart == -1) {
                            throw ConnectException("Unterminated response")
                        }

                        if (contentLength > 10000000) {
                            throw ConnectException("Response too large - 10mb max")
                        }

                        val headers = buffer.substring(0, bodyStart+4)
                        var body = ""

                        if (contentLength != -1 && !IGNORE_LENGTH) {
                            val responseLength = bodyStart + contentLength + 4

                            while (buffer.length < responseLength && !shouldAbandonAttack()) {
                                val len = socket.getInputStream().read(readBuffer)
                                if (len == -1) {
                                    throw RuntimeException("CL response finished unexpectedly")
                                }
                                val read =  Utils.bytesToString(readBuffer.copyOfRange(0, len))
                                triggerReadCallback(read)
                                buffer += read
                            }

                            body = buffer.substring(bodyStart + 4, responseLength)
                            buffer = buffer.substring(responseLength)
                        }
                        else if (headers.lowercase().contains("transfer-encoding: chunked") || headers.contains("^transfer-encoding:[ ]*chunked".toRegex(setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)))  && !IGNORE_LENGTH) {

                            buffer = buffer.substring(bodyStart + 4)

                            while (!shouldAbandonAttack()) {
                                var chunk = getNextChunkLength(buffer)
                                while (chunk.length == -1 || buffer.length < (chunk.length+2)) {
                                    val len = socket.getInputStream().read(readBuffer)
                                    if (len == -1) {
                                        throw RuntimeException("Chunked response finished unexpectedly")
                                    }
                                    val read = Utils.bytesToString(readBuffer.copyOfRange(0, len))
                                    triggerReadCallback(read)
                                    buffer += read
                                    chunk = getNextChunkLength(buffer)
                                }

                                body += buffer.substring(chunk.skip, chunk.length)
                                buffer = buffer.substring(chunk.length + 2)

                                if (chunk.length == chunk.skip) {
                                    break
                                }
                            }
                        }
                        else {
                            if (IGNORE_LENGTH) {
                                socket.soTimeout = 5000
                            }
                            else {
                                Utils.err("Response has no content-length - doing a one-second socket read instead. This is slow!")
                                socket.soTimeout = 1000
                            }

                            try {
                                body += buffer.substring(bodyStart + 4)
                                while (!shouldAbandonAttack()) {
                                    val len = socket.getInputStream().read(readBuffer)

                                    if (len == -1) {
                                        break
                                    }

                                    buffer = Utils.bytesToString(readBuffer.copyOfRange(0, len))
                                    body += buffer
                                }
                            } catch (ex: SocketTimeoutException) {

                            } catch (ex: SSLProtocolException) {

                            } catch (ex: java.lang.Exception) {
                                Utils.err("Exception during timed read: "+ex)
                            }
                        }


                        if (!headers.startsWith("HTTP")) {
                            throw Exception("no http")
                        }

                        var msg = headers
                        msg += uncompressIfNecessary(headers, body)

                        reqWithResponse = inflight.removeFirst()
                        successfulRequests.getAndIncrement()
                        reqWithResponse.response = msg
                        reqWithResponse.connectionID = connectionID
                        reqWithResponse.time = (endTime - startTime) / 1000 // convert ns to microseconds
                        reqWithResponse.arrival = (endTime - start) / 1000

                        answeredRequests += 1
                        val interesting = processResponse(reqWithResponse, (reqWithResponse.response as String).toByteArray(Charsets.ISO_8859_1))

                        invokeCallback(reqWithResponse, interesting)

                    }
                    badWords.clear()
                }
            } catch (ex: Exception) {

                if (reuseSSL && (ex is SSLHandshakeException || ex is SSLException)) {
                    reuseSSL = false
                }
                else {
                    // todo distinguish couldn't send vs couldn't read
                    val activeRequest = inflight.peek()
                    if (activeRequest != null) {
                        val activeWord = activeRequest.words.joinToString(separator="/")
                        if (shouldRetry(activeRequest)) {
                            if (reqWithResponse != null) {
                                Utils.out("Autorecovering error after $answeredRequests answered requests. After '${reqWithResponse.words.joinToString(separator = "/")}' during '$activeWord'")
                            } else {
                                Utils.out("Autorecovering first-request error during '$activeWord'")
                            }
                        } else {
                            ex.printStackTrace()
                            Utils.err("Ignoring error: "+ex.toString())
                            val badReq = inflight.pop()
                            if (ex is IllegalStateException) {
                                badReq.response = "early-response"
                            } else {
                                badReq.response = "null"
                            }
                            if (startTime != 0L) {
                                badReq.time = (System.nanoTime() - startTime) / 1000000 // convert to NS and lose precision
                            }
                            invokeCallback(badReq, true)
                        }
                    } else {
                        Utils.out("Autorecovering error with empty queue: ${ex.message}")
                        ex.printStackTrace()
                    }
                }

                // do callback here (allow user code change
                //readFreq = max(1, readFreq / 2)
                //requestsPerConnection = max(1, requestsPerConnection/2)
                //println("Lost ${inflight.size} requests. Changing requestsPerConnection to $requestsPerConnection and readFreq to $readFreq")
                retryQueue.addAll(inflight)
                inflight.clear()
            }
        }
    }

    private fun waitForData(socket: Socket, pauseTime: Int): String {

        val oldTimeout = socket.soTimeout
        socket.soTimeout = pauseTime
        var len = -1
        val readBuffer = ByteArray(readSize)
        try {
            len = socket.getInputStream().read(readBuffer)
        } catch (e: Exception) {

        }
        socket.soTimeout = oldTimeout
        if (explodeOnEarlyRead && len != -1) {
            throw IllegalStateException()
        }
        var read = ""
        if (len != -1) {
            read = Utils.bytesToString(readBuffer.copyOfRange(0, len))
        }

        return read
    }

    fun getContentLength(buf: String): Int {
        val cstart = buf.indexOf("Content-Length: ")+16
        if (cstart == 15) {
            return -1
        }

        val cend = buf.indexOf("\r", cstart)
        try {
            return buf.substring(cstart, cend).toInt()
        } catch (e: NumberFormatException) {
            throw RuntimeException("Can't parse content length in $buf")
        }
    }

    data class Result(val skip: Int, val length: Int)

    fun getNextChunkLength(buf: String): Result {
        if (buf.isEmpty()) {
            return Result(-1, -1)
        }

        val chunkLengthStart = 0
        val chunkLengthEnd = buf.indexOf("\r\n")
        if(chunkLengthEnd == -1) {
            return Result(-1, -1)
            //throw RuntimeException("Couldn't find the chunk length. Response size may be unspecified - try Burp request engine instead?")
        }

        try {
            val skip = 2+chunkLengthEnd-chunkLengthStart
            return Result(skip, Integer.parseInt(buf.substring(chunkLengthStart, chunkLengthEnd).trim(), 16)+skip)
        } catch (e: NumberFormatException) {
            throw RuntimeException("Can't parse followup chunk length '${buf.substring(chunkLengthStart, chunkLengthEnd)}' in $buf")
        }
    }

    private class TrustingTrustManager(val engine: ThreadedRequestEngine) : X509TrustManager {

        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            for (x in chain.get(0).getSubjectAlternativeNames()) {
                engine.domains.add(x.get(1).toString())
            }
        }
    }
}