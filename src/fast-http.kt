package burp
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

import java.util.concurrent.*

import javax.script.ScriptEngineManager

import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

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
import org.apache.http.nio.ContentDecoder
import org.apache.http.nio.ContentEncoder
import org.apache.http.nio.NHttpClientConnection
import org.apache.http.nio.NHttpClientEventHandler
import java.awt.*
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.io.*
import javax.swing.*


class BurpExtender(): IBurpExtender {
    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks

        val sampleScript = """import burp.RequestEngine
import burp.Env
from urlparse import urlparse

def handleResponse(req, resp):
    code = resp.split(' ', 2)[1]
    if code != '404':
        print(code + ': '+req.split('\r', 1)[0])

def queueRequests():
    baseRequest = burp.Env.request
    service = baseRequest.getHttpService()
    targeturl = service.getProtocol() + "://" + service.getHost() + ":" + service.getPort()
    wordfile = 'payloads'
    concurrentConnections = 50
    readFreq = 100
    requestsPerConnection = 100
    engine = burp.AsyncRequestEngine(targeturl, concurrentConnections, readFreq, requestsPerConnection, handleResponse)
    # burp.ThreadedRequestEngine is an alternative option that's generally slower but may overcome some connection issues
    engine.start()
    requests = 0
    with open(wordfile) as file:
        for line in file:
            requests+=1
            engine.queue(baseRequest.replace('INJECTION', line)

    engine.showStats(requests)


queueRequests()"""
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?) {
        callbacks!!.registerContextMenuFactory(OfferTurboIntruder())
        Companion.callbacks = callbacks
    }
}

class OfferTurboIntruder(): IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val options = ArrayList<JMenuItem>()
        if (invocation!!.selectedMessages[0] != null) {
            val probeButton = JMenuItem("Send to turbo intruder")
            probeButton.addActionListener(TurboIntruderFrame(invocation.selectedMessages[0]))
            options.add(probeButton)
        }
        return options
    }
}


class TurboIntruderFrame(val req: IHttpRequestResponse): ActionListener, JFrame("Turbo Intruder - " + req.httpService.host)  {
    init {

    }

    override fun actionPerformed(e: ActionEvent?) {
        SwingUtilities.invokeLater{
            val outerpane = JPanel(GridBagLayout())
            val pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            val textEditor = BurpExtender.callbacks.createTextEditor()
            val messageEditor = BurpExtender.callbacks.createMessageEditor(null, true)
            messageEditor.setMessage(req.request, true)
            textEditor.setText(BurpExtender.sampleScript.toByteArray())
            textEditor.setEditable(true)

            pane.topComponent = messageEditor.component
            pane.bottomComponent = textEditor.component

            messageEditor.component.preferredSize = Dimension(1280, 200);
            textEditor.component.preferredSize = Dimension(1280, 600);

            val button = JButton("Attack");
            val c =  GridBagConstraints();
            outerpane.add(pane, c)
            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridx = 0
            c.gridy = 1
            outerpane.add(button, c)

            add(outerpane)
            pack()
            setLocationRelativeTo(getBurpFrame())
            isVisible = true
        }
    }

    fun getBurpFrame(): Frame? {
        return Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
    }
}



fun main(args : Array<String>) {
    val scriptFile = args[0]
    Args.args = args
    jythonSend(scriptFile)

    //    val url = args[0]
//    val urlfile = args[1]
//    val threads = args[2].toInt()
//    val requestsPerConnection = args[3].toInt()
//    var readFreq = requestsPerConnection
//    if (args.size > 4) {
//        readFreq = args[4].toInt();
//    }
    //javaSend(url, urlfile, threads, requestsPerConnection, readFreq)
}

fun handlecallback(req: String, resp: String): Boolean {
    val status = resp.split(" ")[1].toInt()
    if (status != 404 && status != 401) {
        println("" + status + ": " + req.split("\n")[0])
        // println(resp)
    }

    return true
}

fun javaSend(url: String, urlfile: String, threads: Int, requestsPerConnection: Int, readFreq: Int) {
    var target: URL
    val engine = AsyncRequestEngine(url, threads, readFreq, requestsPerConnection, ::handlecallback)
    engine.start()

    val inputStream: InputStream = File(urlfile).inputStream()
    val lines = inputStream.bufferedReader().readLines()
    var requests = 0
    for(line in lines) {
        requests++
        target = URL(line);
        engine.queue("GET ${target.path}?${target.query} HTTP/1.1\r\n"
                +"Host: ${target.host}\r\n"
                +"Connection: keep-alive\r\n"
                +"\r\n")
    }

    engine.showStats(requests)
}

fun evalJython(code: String) {
    val engine = ScriptEngineManager().getEngineByName("python")
    if(engine == null) {
        println("Can't find Jython engine")
    }
    engine.eval(code)
}


fun jythonSend(scriptFile: String) {
    try {
        evalJython(File(scriptFile).readText())
    }
    catch (e: FileNotFoundException) {
        val content = """import burp.RequestEngine
import burp.Args
from urlparse import urlparse

def handleResponse(req, resp):
    code = resp.split(' ', 2)[1]
    if code != '404':
        print(code + ': '+req.split('\r', 1)[0])

def queueRequests():
    args = burp.Args.args
    targeturl = args[1]
    urlfile = args[2]
    threads = int(args[3])
    readFreq = int(args[4])
    requestsPerConnection = readFreq
    engine = burp.AsyncRequestEngine(targeturl, threads, readFreq, requestsPerConnection, handleResponse)
    # burp.ThreadedRequestEngine is an alternative option that's generally slower but may overcome some connection issues
    engine.start()
    requests = 0
    with open(urlfile) as file:
        for line in file:
            requests+=1
            url = urlparse(line.rstrip())
            engine.queue('GET %s?%s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n' % (url.path, url.query, url.netloc))

    engine.showStats(requests)


queueRequests()"""

        File(scriptFile).printWriter().use { out -> out.println(content) }
        System.out.println("Wrote example script to "+scriptFile);
    }
}

class Args(args: Array<String>) {

    companion object {
        lateinit var args: Array<String>
    }

    init {
        Companion.args = args
    }
}

class Env(req: HttpRequest) {

    companion object {
        lateinit var request: HttpRequest
    }

    init {
        Companion.request = req
    }
}


interface RequestEngine {
    fun start()
    fun showStats(requestCount: Int)
    fun queue(req: String)
}

class ThreadedRequestEngine(url: String, val threads: Int, val readFreq: Int, val requestsPerConnection: Int, val callback: (String, String) -> Boolean): RequestEngine {

    private val statusMap = HashMap<Int,Int>()
    private val requestQueue = ArrayBlockingQueue<ByteArray>(8192)
    private val latch = CountDownLatch(threads)
    private val target = URL(url)
    private var start: Long = 0

    override fun start() {
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
        start = System.nanoTime()
    }

    override fun queue(req: String) {
        requestQueue.offer(req.toByteArray(Charsets.ISO_8859_1), 10, TimeUnit.SECONDS) // todo should this be synchronised?
    }

    override fun showStats(requestCount: Int) {
//        while(latch.count > 0) {
//
//        }
        latch.await()

        val time = System.nanoTime() - start
//    for((status, freq) in statusMap) {
//        println("Status ${status} count ${freq}")
//    }
        println("Time: " + "%.2f".format(time.toFloat() / 1000000000))
        println("RPS: %.0f".format(requestCount/(time.toFloat() / 1000000000)-1))
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

                        val req = inflight.removeFirst()
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



class AsyncRequestEngine (val url: String, val threads: Int, val readFreq: Int, val requestsPerConnection: Int, val callback: (String, String) -> Boolean): RequestEngine {

    private val requestQueue = ArrayBlockingQueue<HttpRequest>(1000000)
    val config = IOReactorConfig.custom().setTcpNoDelay(true).setSoTimeout(10000).setConnectTimeout(10000).build()
    val ioreactor = DefaultConnectingIOReactor(config)

    val sslcontext = SSLContext.getInstance("Default")
    val connectionFactory = BasicNIOConnFactory(sslcontext, null, ConnectionConfig.custom().build())
    lateinit var poolThread: Thread
    var start: Long = 0

    override fun start() {

        val connpool = BasicNIOConnPool(ioreactor, connectionFactory, 300000)
        connpool.maxTotal = threads
        connpool.defaultMaxPerRoute = threads

        val pendingConnections = ArrayList<Future<BasicNIOPoolEntry>>()
        val url = URL(url)
        pendingConnections.add(connpool.lease(HttpHost(url.host, url.port, url.protocol), null))

        val turboHandler = TurboHandler(requestQueue, requestsPerConnection, readFreq, callback)
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

    override fun showStats(requestCount: Int) {
//        println("Sent " + REQUESTS + " requests in " + duration / 1000000000 + " seconds")
        poolThread.join()
        val duration = System.nanoTime().toFloat() - start
        println("Duration: "+duration / 1000000000)
        System.out.printf("RPS: %.0f\n", requestCount / (duration / 1000000000))
        val gracePeriod = 90000L // milliseconds
        ioreactor.shutdown(gracePeriod)
    }


    companion object {
        fun stringToRequest(req: String): HttpRequest? {
            try {
                val headers = req.split("\r\n\r\n".toRegex(), 2).toTypedArray()[0].split("\r\n".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                val requestParts = headers[0].split(" ".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                val output = BasicHttpEntityEnclosingRequest(requestParts[0], requestParts[1])

                for (i in 1 until headers.size - 1) {
                    val headerParts = headers[i].split(": ".toRegex(), 2).toTypedArray()
                    output.addHeader(headerParts[0], headerParts[1])
                }

                val body = req.split("\r\n\r\n".toRegex(), 2).toTypedArray()[1]
                if ("" != body) {
                    output.entity = StringEntity(body)
                }
                return output
            } catch (e: Exception) {
                println("Errror creating request from input string. If the request is malformed, you may need to use the non-async approach")
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



class TurboHandler(var requestQueue: ArrayBlockingQueue<HttpRequest>, val requestsPerConnection: Int, val readFreq: Int, val callback: (String, String) -> Boolean) : NHttpClientEventHandler {

    @Throws(IOException::class, HttpException::class)
    override fun connected(nHttpClientConnection: NHttpClientConnection, o: Any) {
        val inflight = ArrayDeque<HttpRequest>()
        nHttpClientConnection.context.setAttribute("inflight", inflight)
        nHttpClientConnection.context.setAttribute("total", 0)
        nHttpClientConnection.context.setAttribute("burst", 0)
        nHttpClientConnection.requestOutput()
        //System.out.println("Connected!");
    }

    @Throws(IOException::class, HttpException::class)
    @Suppress("UNCHECKED_CAST")
    override fun requestReady(nHttpClientConnection: NHttpClientConnection) {

        val context = nHttpClientConnection.context

        val inflight = context.getAttribute("inflight") as ArrayDeque<HttpRequest>

        if (requestQueue.isEmpty()) {
            //System.out.println("Queued everything - requesting responses now");
            if (inflight.isEmpty()) {
                nHttpClientConnection.close()
            }
        } else {
            val total = context.getAttribute("total") as Int
            var burst = context.getAttribute("burst") as Int
            if (inflight.isEmpty() && total < requestsPerConnection) {
                burst = 0
            }

            if (burst < readFreq && total < requestsPerConnection) { // inflight.size() < 100
                val req = requestQueue.poll()
                if (req != null) {
                    inflight.add(req)
                    context.setAttribute("total", total + 1)
                    context.setAttribute("burst", burst + 1)
                    nHttpClientConnection.submitRequest(req)
                }
            } else {

            }
        }
    }

    @Throws(IOException::class, HttpException::class)
    override fun responseReceived(nHttpClientConnection: NHttpClientConnection) {

    }

    @Throws(IOException::class, HttpException::class)
    @Suppress("UNCHECKED_CAST")
    override fun inputReady(nHttpClientConnection: NHttpClientConnection, contentDecoder: ContentDecoder) {

        val dst = ByteBuffer.allocate(nHttpClientConnection.httpResponse.getFirstHeader("Content-Length").value.toInt()+8)
        val bytesRead = contentDecoder.read(dst)

        // todo check contentDecoder.isCompleted - supported repeated calls with partial data

        if (bytesRead != -1) {

            val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>
            val req = inflight.pop()
            val resp = nHttpClientConnection.httpResponse

            resp.entity = StringEntity(String(dst.array()))

            callback(AsyncRequestEngine.requestToString(req), AsyncRequestEngine.responseToString(resp))

            if (inflight.isEmpty()) {
                val total = nHttpClientConnection.context.getAttribute("total") as Int
                if (total >= requestsPerConnection) {
                    nHttpClientConnection.close()
                }
            }
        }
    }

    @Throws(IOException::class, HttpException::class)
    @Suppress("UNCHECKED_CAST")
    override fun outputReady(nHttpClientConnection: NHttpClientConnection, contentEncoder: ContentEncoder) {
        if (nHttpClientConnection.isRequestSubmitted) {
            val content = (nHttpClientConnection.httpRequest as BasicHttpEntityEnclosingRequest).entity.content
            val expectedLength = nHttpClientConnection.httpRequest.getFirstHeader("Content-Length").value.toInt()
            val dst = ByteArray(expectedLength+8)
            val i = content.read(dst)
            val buf = ByteBuffer.wrap(dst)
            buf.flip()
            contentEncoder.write(buf)

            val buffering = buf.hasRemaining()
            buf.compact()
            if (i == -1 && !buffering) {
                contentEncoder.complete()
            }

            // todo support repeated calls with partial data
            //nHttpClientConnection.suspendOutput();
            //nHttpClientConnection.requestInput();
        }
    }

    @Throws(IOException::class)
    @Suppress("UNCHECKED_CAST")
    override fun endOfInput(nHttpClientConnection: NHttpClientConnection) {
        val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>
        if (inflight.size > 0) {
            println("End of input lost " + inflight.size + " pending responses. Retry scheduled")
        }
        nHttpClientConnection.close()
    }

    @Throws(IOException::class, HttpException::class)
    @Suppress("UNCHECKED_CAST")
    override fun timeout(nHttpClientConnection: NHttpClientConnection) {
        val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>
        if (inflight.size > 0) {
            println("Timeout lost " + inflight.size + " pending responses. Retry scheduled.")
        }
        nHttpClientConnection.close()
    }

    @Suppress("UNCHECKED_CAST")
    override fun closed(nHttpClientConnection: NHttpClientConnection) {
        val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>

        while (!inflight.isEmpty()) {
            requestQueue.add(inflight.pop())
        }
    }

    @Suppress("UNCHECKED_CAST")
    override fun exception(nHttpClientConnection: NHttpClientConnection, e: Exception) {
        val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>
        if (inflight.size > 0) {
            println(e.message + " lost " + inflight.size + " pending responses. Retry scheduled.")
        }
        //e.printStackTrace();
    }
}