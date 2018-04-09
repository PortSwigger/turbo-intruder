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

class ThreadedRequestEngine(url: String, val threads: Int, val readFreq: Int, val requestsPerConnection: Int, val callback: (String, String) -> Boolean): RequestEngine {

    private val statusMap = HashMap<Int, Int>()
    private val requestQueue = ArrayBlockingQueue<ByteArray>(8192)
    private val completedLatch = CountDownLatch(threads)
    private val connectedLatch = CountDownLatch(threads)
    private val target = URL(url)
    private var start: Long = 0
    val attackState = AtomicInteger(0) // 0 = connecting, 1 = live, 2 = fully queued
    var successfulRequests = AtomicInteger(0)
    private val threadPool = ArrayList<Thread>()


    init {
        val retryQueue = LinkedBlockingQueue<ByteArray>();
        val ipAddress = InetAddress.getByName(target.host)
        val port = if (target.port == -1) { target.defaultPort } else { target.port }

        val trustingSslContext = SSLContext.getInstance("TLS")
        trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager()), null)
        val trustingSslSocketFactory = trustingSslContext.socketFactory

        println("Warming up...")
        for(j in 1..threads) {
            threadPool.add(
                thread {
                    sendRequests(target, trustingSslSocketFactory, ipAddress, port, requestQueue, retryQueue, completedLatch, readFreq, requestsPerConnection, connectedLatch)
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
        queue(req.toByteArray(Charsets.ISO_8859_1))
    }

    fun queue(req: ByteArray) {
        requestQueue.offer(req, 10, TimeUnit.SECONDS) // todo should this be synchronised?
    }

    override fun showStats(timeout: Int) {
        attackState.set(2)
        val success = completedLatch.await(timeout.toLong(), TimeUnit.SECONDS)
        if (!success) {
            println("Aborting attack due to timeout")
            attackState.set(3)
        }
        val duration = System.nanoTime().toFloat() - start
        val requests = successfulRequests.get().toFloat()
        println("Sent " + requests.toInt() + " requests in "+duration / 1000000000 + " seconds")
        System.out.printf("RPS: %.0f\n", requests / (duration / 1000000000))
    }


    private fun sendRequests(url: URL, trustingSslSocketFactory: SSLSocketFactory, ipAddress: InetAddress?, port: Int, requestQueue: ArrayBlockingQueue<ByteArray>, retryQueue: LinkedBlockingQueue<ByteArray>, completedLatch: CountDownLatch, baseReadFreq: Int, baseRequestsPerConnection: Int, connectedLatch: CountDownLatch) {
        var readFreq = baseReadFreq
        val inflight = ArrayDeque<ByteArray>()
        var requestsPerConnection = baseRequestsPerConnection
        var connected = false

        while (true) {

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
                            if (req == null && attackState.get() == 2) {
                                completedLatch.countDown()
                                return
                            }
                        }

                        inflight.addLast(req)
                        socket.getOutputStream().write(req)
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
                        var msg = ""
                        if (contentLength != -1) {
                            val responseLength = bodyStart + contentLength + 4

                            while (buffer.length < responseLength) {
                                val len = socket.getInputStream().read(read)
                                buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                            }

                            msg = buffer.substring(0, responseLength)
                            buffer = buffer.substring(responseLength)
                        }
                        else {
                            msg += buffer.substring(0, bodyStart+4)
                            buffer = buffer.substring(bodyStart+4)

                            var chunk = getNextChunkLength(buffer)

                            while (chunk.length != 3) {
                                //println("Chunk length: "+chunk.length)
                                while (buffer.length < chunk.length) {
                                    val len = socket.getInputStream().read(read)
                                    buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                                }

                                //println("Got chunk: "+buffer.substring(chunk.skip, chunk.length))
                                msg += buffer.substring(chunk.skip, chunk.length)
                                buffer = buffer.substring(chunk.length+2)

                                chunk = getNextChunkLength(buffer)
                                if (chunk.length == -1) {
                                    val len = socket.getInputStream().read(read)
                                    buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                                    chunk = getNextChunkLength(buffer)
                                }
                            }
                        }


                        if (!msg.startsWith("HTTP")) {
                            throw Exception("no http")
                        }

                        val req = inflight.removeFirst()
                        successfulRequests.getAndIncrement()
                        callback(String(req), msg)

//                        val status = msg.split(" ")[1].toInt()
//                        synchronized(statusMap) {
//                            statusMap.put(status, statusMap.getOrDefault(status, 0) + 1)
//                        }
                    }
                }
            } catch (ex: Exception) {

                ex.printStackTrace()
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