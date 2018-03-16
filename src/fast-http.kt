import java.net.InetAddress
import java.net.URL
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.CountDownLatch
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread
import java.io.File
import java.io.InputStream
import java.util.concurrent.ArrayBlockingQueue


fun main(args : Array<String>) {
    val urlfile = args[0]
    val threads = args[1].toInt()
    val requestsPerConnection = args[2].toInt()

    var readFreq = requestsPerConnection
    if(args.size > 3) {
        readFreq = args[3].toInt();
    }

    val requestQueue = ArrayBlockingQueue<ByteArray>(1000000);

    val inputStream: InputStream = File(urlfile).inputStream()

    var target : URL?=null
    val lines = inputStream.bufferedReader().readLines()

    var requests = 0
    for(line in lines) {
        requests++
        target = URL(line);
        requestQueue.add(("GET ${target.path}?${target.query} HTTP/1.1\r\n"
                +"Host: ${target.host}\r\n"
                +"Connection: keep-alive\r\n"
                +"\r\n").toByteArray(Charsets.ISO_8859_1))
    }


    val ipAddress = InetAddress.getByName(target!!.host)
    val port = if (target.port == -1) { target.defaultPort } else { target.port }

    val trustingSslContext = SSLContext.getInstance("TLS")
    trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager()), null)
    val trustingSslSocketFactory = trustingSslContext.socketFactory

    val start = System.nanoTime()
    val latch = CountDownLatch(threads)
    val statusMap = HashMap<Int,Int>()

    for(j in 1..threads) {
        thread {
            sendRequests(target, trustingSslSocketFactory, ipAddress, port, requestQueue, statusMap, latch, readFreq, requestsPerConnection)
        }
    }
    latch.await()

    val time = System.nanoTime() - start
    for((status, freq) in statusMap) {
        println("Status ${status} count ${freq}")
    }
    println("Time: " + "%.2f".format(time.toFloat() / 1000000000))
    println("RPS: %.0f".format(requests/(time.toFloat() / 1000000000)))
}


private fun sendRequests(url: URL, trustingSslSocketFactory: SSLSocketFactory, ipAddress: InetAddress?, port: Int, requestQueue: ArrayBlockingQueue<ByteArray>, statusMap: HashMap<Int, Int>, latch: CountDownLatch, baseReadFreq: Int, baseRequestsPerConnection: Int) {
    var readFreq = baseReadFreq
    val inflight = ArrayDeque<ByteArray>()

    var requestsPerConnection = baseRequestsPerConnection

    while (!requestQueue.isEmpty()) {

        try {
            val socket = if (url.protocol.equals("https")) {
                trustingSslSocketFactory.createSocket(ipAddress, port)
            } else {
                SocketFactory.getDefault().createSocket(ipAddress, port)
            }
            socket.soTimeout = 10000
            // todo tweak other TCP options for max performance

            var requestsSent = 0
            while (requestsSent < requestsPerConnection && !requestQueue.isEmpty()) {

                var readCount = 0
                for (j in 1..readFreq) {
                    if (requestsSent >= requestsPerConnection) {
                        break
                    }

                    val req = requestQueue.poll();
                    if(req == null) {
                        break
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
            requestQueue.addAll(inflight)
            inflight.clear()
        }
    }

    latch.countDown()
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