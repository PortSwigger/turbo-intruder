import java.lang.Integer.max
import java.net.InetAddress
import java.net.URL
import java.security.Security
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.CountDownLatch
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread
import java.io.IOException
import jdk.nashorn.internal.objects.NativeArray.forEach
import java.io.File
import java.io.InputStream
import java.nio.file.Paths
import java.nio.file.Files
import java.util.function.Consumer
import java.util.stream.Stream




fun main(args : Array<String>) {
    val urlfile = args[0]
    val threads = args[1].toInt()
    val requestsPerConnection = args[2].toInt()

    var readFreq = requestsPerConnection
    if(args.size > 3) {
        readFreq = args[3].toInt();
    }

    val inputStream: InputStream = File(urlfile).inputStream()
    val urls = ArrayList<ArrayList<String>>()
    for(i in 1..threads) {
        urls.add(ArrayList<String>())
    }

    var i = 0
    inputStream.bufferedReader().useLines { lines -> lines.forEach { urls.get(i++ % threads).add(it)} }

    val url = URL(urls.get(0).get(0))
    val ipAddress = InetAddress.getByName(url.host)
    val port = if (url.port == -1) { url.defaultPort } else { url.port }

    val trustingSslContext = SSLContext.getInstance("TLS")
    trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager()), null)
    val trustingSslSocketFactory = trustingSslContext.socketFactory

    val start = System.nanoTime()
    val latch = CountDownLatch(threads)
    var totalBytes = 0
    val statusMap = HashMap<Int,Int>()

    for(j in 1..threads) {
        thread {
            sendRequests(url, trustingSslSocketFactory, ipAddress, port, urls.get(j-1), statusMap, totalBytes, latch, readFreq, requestsPerConnection)
        }
    }
    latch.await()

    for((status, freq) in statusMap) {
        println("Status ${status} count ${freq}")
    }

    println("Bytes read: ${totalBytes}")

    val time = System.nanoTime() - start
    println("Time: " + "%.2f".format(time.toFloat() / 1000000000))
    var requests = 0
    for (e in urls) {
        requests += e.size
    }
    println("RPS: %.0f".format(requests/(time.toFloat() / 1000000000)))
}


private fun sendRequests(url: URL, trustingSslSocketFactory: SSLSocketFactory, ipAddress: InetAddress?, port: Int, urls: ArrayList<String>, statusMap: HashMap<Int, Int>, totalBytes: Int, latch: CountDownLatch, baseReadFreq: Int, baseRequestsPerConnection: Int) {
    var readFreq = baseReadFreq
    var totalBytes1 = totalBytes
    var threadBytes = 0
    val inflight = ArrayDeque<ByteArray>()
    val todo = ArrayDeque<ByteArray>();

    for (i in urls) {
        val target = URL(i)
        val request = ("GET ${target.path}?${target.query} HTTP/1.1\r\n"
                +"Host: ${target.host}\r\n"
                +"Connection: keep-alive\r\n"
                +"\r\n").toByteArray(Charsets.ISO_8859_1)
        todo.add(request);
    }

    var requestsPerConnection = baseRequestsPerConnection

    while (!todo.isEmpty()) {

        try {
            val socket = if (url.protocol.equals("https")) {
                trustingSslSocketFactory.createSocket(ipAddress, port)
            } else {
                SocketFactory.getDefault().createSocket(ipAddress, port)
            }
            socket.soTimeout = 10000
            // todo tweak other TCP options for max performance

            var requestsSent = 0
            while (requestsSent < requestsPerConnection && !todo.isEmpty()) {

                var readCount = 0
                for (j in 1..readFreq) {
                    if (todo.isEmpty() || requestsSent >= requestsPerConnection) {
                        break
                    }

                    val req = todo.pop();
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

                    val contentLength = Regex("Content-Length: (\\d+)").find(buffer)!!.groups[1]!!.value.toInt()
                    val responseLength = delimOffset + contentLength + 4

                    while (buffer.length < responseLength) {
                        val len = socket.getInputStream().read(read)
                        buffer += String(read.copyOfRange(0, len), Charsets.ISO_8859_1)
                    }

                    val msg = buffer.substring(0, responseLength)
                    buffer = buffer.substring(responseLength)
                    threadBytes += responseLength

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
            //readFreq = max(1, readFreq / 2)
            //requestsPerConnection = max(1, requestsPerConnection/2)
            //println("Lost ${inflight.size} requests. Changing requestsPerConnection to $requestsPerConnection and readFreq to $readFreq")
            todo.addAll(inflight)
            inflight.clear()
        }
    }

    synchronized(totalBytes1) {
        totalBytes1 += threadBytes
    }

    latch.countDown()
}


private class TrustingTrustManager : X509TrustManager {
    override fun getAcceptedIssuers(): Array<X509Certificate>? {
        return null
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
}