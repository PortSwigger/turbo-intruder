package burp

import burp.RequestEngine
import java.net.InetAddress
import java.net.URL
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

open class ThreadedRequestEngine(url: String, val threads: Int, val readFreq: Int, val requestsPerConnection: Int, val callback: (Request, Boolean) -> Boolean): RequestEngine() {

    private val requestQueue = ArrayBlockingQueue<Request>(1000000)
    private val connectedLatch = CountDownLatch(threads)
    private val target = URL(url)
    private val threadPool = ArrayList<Thread>()

    init {
        completedLatch = CountDownLatch(threads)
        val retryQueue = LinkedBlockingQueue<Request>();
        val ipAddress = InetAddress.getByName(target.host)
        val port = if (target.port == -1) { target.defaultPort } else { target.port }

        val trustingSslContext = SSLContext.getInstance("TLS")
        trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager()), null)
        val trustingSslSocketFactory = trustingSslContext.socketFactory

        Utilities.out("Warming up...")
        for(j in 1..threads) {
            threadPool.add(
                thread {
                    sendRequests(target, trustingSslSocketFactory, ipAddress, port, retryQueue, completedLatch, readFreq, requestsPerConnection, connectedLatch)
                }
            )
        }

    }

    override fun start(timeout: Int) {
        connectedLatch.await(timeout.toLong(), TimeUnit.SECONDS)
        attackState.set(1)
        start = System.nanoTime()
    }

    override fun queue(req: String) {
        queue(req, null, 0)
    }

    fun queue(template: String, payload: String?) {
        queue(template, payload, 0)
    }

    fun queue(template: String, payload: String?, learnBoring: Int?) {

        val request = Request(template.replace("Connection: close", "Connection: keep-alive"), payload, learnBoring ?: 0)

        val queued = requestQueue.offer(request, 10, TimeUnit.SECONDS)
        if (!queued) {
            Utilities.out("Timeout queuing request. Aborting.")
            this.showStats(1)
        }
    }

    private fun sendRequests(url: URL, trustingSslSocketFactory: SSLSocketFactory, ipAddress: InetAddress?, port: Int, retryQueue: LinkedBlockingQueue<Request>, completedLatch: CountDownLatch, baseReadFreq: Int, baseRequestsPerConnection: Int, connectedLatch: CountDownLatch) {
        var readFreq = baseReadFreq
        val inflight = ArrayDeque<Request>()
        var requestsPerConnection = baseRequestsPerConnection
        var connected = false
        var reqWithResponse: Request? = null
        var answeredRequests = 0

        while (!BurpExtender.unloaded) {

            try {
                val socket = if (url.protocol.equals("https")) {
                    trustingSslSocketFactory.createSocket(ipAddress, port)
                } else {
                    SocketFactory.getDefault().createSocket(ipAddress, port)
                }
                socket.soTimeout = 10000
                // todo tweak other TCP options for max performance

                if(!connected) {
                    connected = true
                    connectedLatch.countDown()
                    while(attackState.get() == 0) {
                        Thread.sleep(10)
                    }
                }

                var requestsSent = 0
                answeredRequests = 0
                while (requestsSent < requestsPerConnection) {

                    if(attackState.get() == 3) {
                        return
                    }

                    var readCount = 0
                    for (j in 1..readFreq) {
                        if (requestsSent >= requestsPerConnection) {
                            break
                        }

                        var req = retryQueue.poll()
                        while (req == null) {
                            req = requestQueue.poll(100, TimeUnit.MILLISECONDS);

                            if (req == null) {
                                if (readCount > 0) {
                                    break
                                }
                                if(attackState.get() == 2) {
                                    completedLatch.countDown()
                                    return
                                }
                            }
                        }

                        if (req == null) break

                        inflight.addLast(req)
                        socket.getOutputStream().write(req.getRawRequest())
                        readCount++
                        requestsSent++

                    }

                    val read = ByteArray(1024)
                    var buffer = ""

                    for (k in 1..readCount) {
                        var bodyStart = buffer.indexOf("\r\n\r\n")
                        while (bodyStart == -1) {
                            val len = socket.getInputStream().read(read)
                            if(len == -1) {
                                break
                            }
                            buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                            bodyStart = buffer.indexOf("\r\n\r\n")
                        }

                        val contentLength = getContentLength(buffer)
                        val shouldGzip = shouldGzip(buffer)
                        val headers = buffer.substring(0, bodyStart+4) // fixme java.lang.StringIndexOutOfBoundsException: begin 0, end 3, length 0
                        var body = ""
                        if (contentLength != -1) {
                            val responseLength = bodyStart + contentLength + 4

                            while (buffer.length < responseLength) {
                                val len = socket.getInputStream().read(read)
                                buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                            }

                            body = buffer.substring(bodyStart+4, responseLength)
                            buffer = buffer.substring(responseLength)
                        }
                        else {
                            //body += buffer.substring(0, bodyStart+4)
                            buffer = buffer.substring(bodyStart+4)

                            var chunk = getNextChunkLength(buffer)

                            while (chunk.length != 3) {
                                //println("Chunk length: "+chunk.length)
                                while (buffer.length < chunk.length) {
                                    val len = socket.getInputStream().read(read)
                                    buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                                }

                                //println("Got chunk: "+buffer.substring(chunk.skip, chunk.length))
                                body += buffer.substring(chunk.skip, chunk.length)
                                buffer = buffer.substring(chunk.length+2)

                                chunk = getNextChunkLength(buffer)
                                if (chunk.length == -1) {
                                    val len = socket.getInputStream().read(read)
                                    buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                                    chunk = getNextChunkLength(buffer)
                                }
                            }


                        }


                        if (!headers.startsWith("HTTP")) {
                            throw Exception("no http")
                        }

                        var msg = headers
                        if(shouldGzip) {
                            msg += Utilities.decompress(body.toByteArray(Charsets.ISO_8859_1))
                        }
                        else {
                            msg += body
                        }

                        reqWithResponse = inflight.removeFirst()
                        successfulRequests.getAndIncrement()
                        answeredRequests += 1
                        val interesting = processResponse(reqWithResponse, msg.toByteArray(Charsets.ISO_8859_1))
                        reqWithResponse.response = msg
                        callback(reqWithResponse, interesting)

                    }
                }
            } catch (ex: Exception) {

                if (reqWithResponse != null) {
                    Utilities.out("Controlled error after "+answeredRequests+" answered requests. After '" + reqWithResponse.word + "' during '" + inflight.pop().word + "'")
                }
                else if (answeredRequests == 0) {
                    Utilities.out("Error on first request :(  '"+inflight.pop().word+"'")
                    ex.printStackTrace()
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

    fun getContentLength(buf: String): Int {
        val cstart = buf.indexOf("Content-Length: ")+16
        if (cstart == 15) {
            return -1
        }

        val cend = buf.indexOf("\r", cstart)
        try {
            return buf.substring(cstart, cend).toInt()
        } catch (e: NumberFormatException) {
            throw RuntimeException("Can't parse content length in "+buf)
        }
    }

    fun shouldGzip(buf: String): Boolean {
        return buf.indexOf("Content-Encoding: gzip") != -1
    }

    data class Result(val skip: Int, val length: Int)

    fun getNextChunkLength(buf: String): Result {
        if (buf.length == 0) {
            return Result(-1, -1)
        }

        val chunkLengthStart = 0
        val chunkLengthEnd = buf.indexOf("\r\n")

        try {
            val skip = 2+chunkLengthEnd-chunkLengthStart
            return Result(skip, Integer.parseInt(buf.substring(chunkLengthStart, chunkLengthEnd), 16)+skip)
        } catch (e: NumberFormatException) {
            throw RuntimeException("Can't parse followup chunk length '"+buf.substring(chunkLengthStart, chunkLengthEnd)+"' in "+buf)
        }
    }

    private class TrustingTrustManager : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    }
}