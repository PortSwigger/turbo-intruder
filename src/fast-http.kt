package req
import java.net.InetAddress
import java.net.URL
import java.security.cert.X509Certificate
import java.util.*
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread
import java.io.File
import java.io.InputStream

import org.python.core.PyObject;
import org.python.core.PyString;
import org.python.util.PythonInterpreter;
import java.util.concurrent.*

import javax.script.ScriptEngine
import javax.script.ScriptEngineManager



fun main(args : Array<String>) {
    val urlfile = args[0]
    val threads = args[1].toInt()
    val requestsPerConnection = args[2].toInt()
    var readFreq = requestsPerConnection
    if(args.size > 3) {
        readFreq = args[3].toInt();
    }

    val inputStream: InputStream = File(urlfile).inputStream()

    var target = URL("https://research1.hackxor.net/static/cow")


    val latch = CountDownLatch(threads)
    val engine = RequestEngine(target, threads, readFreq, requestsPerConnection, latch)
    val start = System.nanoTime()

    val lines = inputStream.bufferedReader().readLines()
    var requests = 0
    for(line in lines) {
        requests++
        target = URL(line);
        engine.queue(("GET ${target.path}?${target.query} HTTP/1.1\r\n"
                +"Host: ${target.host}\r\n"
                +"Connection: keep-alive\r\n"
                +"\r\n").toByteArray(Charsets.ISO_8859_1))
    }
    latch.await()

    val time = System.nanoTime() - start
//    for((status, freq) in statusMap) {
//        println("Status ${status} count ${freq}")
//    }
    println("Time: " + "%.2f".format(time.toFloat() / 1000000000))
    println("RPS: %.0f".format(requests/(time.toFloat() / 1000000000)-1))

}

fun jyval() {
    val engine = ScriptEngineManager().getEngineByName("python")
    if(engine == null) {
        println("can't find engine")
    }
    else {
        engine.eval("import req.RequestEngine")
        engine.eval("req.RequestEngine.hello()")
    }
}

class RequestEngine(target: URL, threads: Int, readFreq: Int, requestsPerConnection: Int, latch: CountDownLatch) {

    companion object {
        @JvmStatic
        fun hello() {
            println("hello")
        }
    }

    val statusMap = HashMap<Int,Int>()
    val requestQueue = ArrayBlockingQueue<ByteArray>(200005)

    init {
        val retryQueue = LinkedBlockingQueue<ByteArray>();


        val ipAddress = InetAddress.getByName(target.host)
        val port = if (target.port == -1) { target.defaultPort } else { target.port }

        val trustingSslContext = SSLContext.getInstance("TLS")
        trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager()), null)
        val trustingSslSocketFactory = trustingSslContext.socketFactory

        for(j in 1..threads) {
            thread {
                sendRequests(target, trustingSslSocketFactory, ipAddress, port, requestQueue, retryQueue, latch, readFreq, requestsPerConnection)
            }
        }
    }

    fun queue(req: ByteArray) {
        requestQueue.add(req) // todo should this be synchronised?
    }


    private fun sendRequests(url: URL, trustingSslSocketFactory: SSLSocketFactory, ipAddress: InetAddress?, port: Int, requestQueue: ArrayBlockingQueue<ByteArray>, retryQueue: LinkedBlockingQueue<ByteArray>, latch: CountDownLatch, baseReadFreq: Int, baseRequestsPerConnection: Int) {
        var readFreq = baseReadFreq
        val inflight = ArrayDeque<ByteArray>()

        var requestsPerConnection = baseRequestsPerConnection

        while (true) {

            try {
                val socket = if (url.protocol.equals("https")) {
                    trustingSslSocketFactory.createSocket(ipAddress, port)
                } else {
                    SocketFactory.getDefault().createSocket(ipAddress, port)
                }
                socket.soTimeout = 10000
                // todo tweak other TCP options for max performance

                var requestsSent = 0
                while (requestsSent < requestsPerConnection) {

                    var readCount = 0
                    for (j in 1..readFreq) {
                        if (requestsSent >= requestsPerConnection) {
                            break
                        }

                        var req = retryQueue.poll()
                        if (req == null) {
                            req = requestQueue.poll(1, TimeUnit.SECONDS);
                            if(req == null) {
                                //println("Timeout - completed!")
                                latch.countDown()
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
                        var delimOffset = buffer.indexOf("\r\n\r\n")
                        while (delimOffset == -1) {
                            val len = socket.getInputStream().read(read)
                            buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                            delimOffset = buffer.indexOf("\r\n\r\n")
                        }

                        // val contentLength = Regex("Content-Length: (\\d+)").find(buffer)!!.groups[1]!!.value.toInt()
                        val contentLength = getContentLength(buffer)
                        val responseLength = delimOffset + contentLength + 4

                        while (buffer.length < responseLength) {
                            val len = socket.getInputStream().read(read)
                            buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                        }

                        val msg = buffer.substring(0, responseLength)
                        buffer = buffer.substring(responseLength)

                        if (!msg.startsWith("HTTP")) {
                            throw Exception("no http")
                        }

                        val status = msg.split(" ")[1].toInt()
                        val req = inflight.removeFirst()
                        if (status != 404 && status != 401) {
                            println("" + status + ": " + String(req).split("\n")[0])
                        }

                        synchronized(statusMap) {
                            statusMap.put(status, statusMap.getOrDefault(status, 0) + 1)
                        }
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
        val cend = buf.indexOf("\r", cstart)
        return buf.substring(cstart, cend).toInt()
    }

    private class TrustingTrustManager : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    }
}


