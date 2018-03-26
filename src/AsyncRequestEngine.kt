package burp;

import burp.RequestEngine
import burp.TurboHandler
import org.apache.http.*
import org.apache.http.config.ConnectionConfig
import org.apache.http.entity.StringEntity
import org.apache.http.impl.nio.DefaultHttpClientIODispatch
import org.apache.http.impl.nio.pool.BasicNIOConnFactory
import org.apache.http.impl.nio.pool.BasicNIOConnPool
import org.apache.http.impl.nio.pool.BasicNIOPoolEntry
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor
import org.apache.http.impl.nio.reactor.IOReactorConfig
import org.apache.http.message.BasicHttpEntityEnclosingRequest
import java.io.IOException
import java.io.InterruptedIOException
import java.net.URL
import java.util.ArrayList
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext

class AsyncRequestEngine (val url: String, val threads: Int, val readFreq: Int, val requestsPerConnection: Int, val callback: ((String, String) -> Boolean)?): RequestEngine {

    private val requestQueue = ArrayBlockingQueue<HttpRequest>(1000000)
    val config = IOReactorConfig.custom().setTcpNoDelay(true).setSoTimeout(10000).setConnectTimeout(10000).build()
    val ioreactor = DefaultConnectingIOReactor(config)

    val sslcontext = SSLContext.getInstance("Default")
    val connectionFactory = BasicNIOConnFactory(sslcontext, null, ConnectionConfig.custom().build())
    lateinit var poolThread: Thread
    var start: Long = 0
    var successfulRequests = AtomicInteger(0)

    override fun start() {

        val connpool = BasicNIOConnPool(ioreactor, connectionFactory, 300000)
        connpool.maxTotal = threads
        connpool.defaultMaxPerRoute = threads

        val pendingConnections = ArrayList<Future<BasicNIOPoolEntry>>()
        val url = URL(url)
        pendingConnections.add(connpool.lease(HttpHost(url.host, url.port, url.protocol), null))

        val turboHandler = TurboHandler(requestQueue, requestsPerConnection, readFreq, successfulRequests, callback)
        val eventDispatch = DefaultHttpClientIODispatch(turboHandler, sslcontext, ConnectionConfig.DEFAULT)

        // Run the I/O reactor in a separate thread
        val reactorThread = Thread(Runnable {
            try {
                ioreactor.execute(eventDispatch)
            } catch (ex: InterruptedIOException) {
                System.err.println("Interrupted")
            } catch (e: IOException) {
                System.err.println("I/O error: " + e.message)
                e.printStackTrace()
                System.err.println("--------------")
            }
        })

        poolThread = Thread(Runnable {
            var it: MutableIterator<Future<BasicNIOPoolEntry>> = pendingConnections.iterator()
            while (it.hasNext()) {
                val future = it.next()
                if (future.isDone) {
                    val poolEntry = future.get(60, TimeUnit.SECONDS)
                    if (poolEntry != null && poolEntry.isClosed) {
                        connpool.release(poolEntry, false)
                        it.remove()
                    }
                }

                if (!it.hasNext()) {
                    if (pendingConnections.isEmpty() && !requestQueue.isEmpty()) {
                        // println("Adding extra lease")
                        val queueSize = requestQueue.size
                        for (i in 0..queueSize / 100) {
                            pendingConnections.add(connpool.lease(HttpHost("hackxor.net", 443, "https"), null))
                        }
                    }
                    it = pendingConnections.iterator()
                }
            }
        })

        start = System.nanoTime()
        poolThread.start()
        reactorThread.start()
    }

    override fun queue(req: String) {
        requestQueue.add(stringToRequest(req));
    }

    override fun showStats() {
//        println("Sent " + REQUESTS + " requests in " + duration / 1000000000 + " seconds")
        poolThread.join()
        val duration = System.nanoTime().toFloat() - start
        val requests = successfulRequests.get().toFloat()
        println("Sent " + requests + " requests over "+duration / 1000000000)
        System.out.printf("RPS: %.0f\n", requests / (duration / 1000000000))
        val gracePeriod = 90000L // milliseconds
        ioreactor.shutdown(gracePeriod)
    }


    companion object {
        fun stringToRequest(req: String): HttpRequest? {
            try {
                val headers = req.split("\r\n\r\n".toRegex(), 2).toTypedArray()[0].split("\r\n".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                val requestParts = headers[0].split(" ".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

                if (requestParts.size < 2) {
                    throw Exception("Bad request line")
                }

                val output = BasicHttpEntityEnclosingRequest(requestParts[0], requestParts[1])


                for (i in 1 until headers.size - 1) {
                    val headerParts = headers[i].split(": ".toRegex(), 2).toTypedArray()

                    if (headerParts.size < 2) {
                        throw Exception("Bad header: "+headerParts)
                    }

                    output.addHeader(headerParts[0], headerParts[1])
                }

                val body = req.split("\r\n\r\n".toRegex(), 2).toTypedArray()
                if (body.size > 1 && "" != body[1]) {
                    output.entity = StringEntity(body[1])
                }
                return output
            } catch (e: Exception) {
                println("Error creating request from input string. If the request is malformed, you may need to use the non-async approach")
                e.printStackTrace()
            }

            return null
        }

        fun appendEntity(output: StringBuilder, entity: HttpEntity?) {
            if (entity == null) {
                return
            }

            val body = entity.content

            val buff = ByteArray(256)
            while (true) {
                val length = body.read(buff)
                if (length == -1) {
                    break
                }
                output.append(String(buff, 0, length))
            }

        }

        @Throws(IOException::class)
        fun responseToString(resp: HttpResponse): String {
            val output = StringBuilder()

            val status = resp.statusLine
            output.append(status.protocolVersion.toString())
            output.append(" ")
            output.append(status.statusCode)
            output.append(" ")
            output.append(status.reasonPhrase)
            output.append("\r\n")

            val headers = resp.headerIterator()
            while (headers.hasNext()) {
                val header = headers.nextHeader()
                output.append(header.name)
                output.append(": ")
                output.append(header.value)
                output.append("\r\n")
            }
            output.append("\r\n")

            appendEntity(output, resp.entity)

            return output.toString()
        }

        fun requestToString(req: HttpRequest): String {
            val output = StringBuilder();

            output.append(req.requestLine.method)
            output.append(" ")
            output.append(req.requestLine.uri)
            output.append(" ")
            output.append(req.requestLine.protocolVersion)
            output.append("\r\n")

            val headers = req.headerIterator()
            while (headers.hasNext()) {
                val header = headers.nextHeader()
                output.append(header.name)
                output.append(": ")
                output.append(header.value)
                output.append("\r\n")
            }
            output.append("\r\n")
            if (req is HttpEntityEnclosingRequest) {
                appendEntity(output, req.entity)
            }

            return output.toString()
        }
    }
}