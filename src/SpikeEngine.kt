package burp

import burp.H2Connection.Companion.buildReq
import burp.network.stack.http2.frame.Frame
import net.hackxor.api.*
import net.hackxor.api.Header.header
import net.hackxor.utils.CompositeStreamFrameProcessor
import net.hackxor.utils.DefaultThreadLauncher
import net.hackxor.utils.TrustAllSocketFactory
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

class SpikeEngine(url: String, threads: Int, maxQueueSize: Int, override val maxRetriesPerRequest: Int, override val callback: (Request, Boolean) -> Boolean, override var readCallback: ((String) -> Boolean)?): RequestEngine() {
    var socket: SSLSocket
    var streamCompleteLatch: CountDownLatch
    var connectionFactory: ConnectionFactory
    var connection: Connection
    var frameFactory: RequestFrameFactory
    var threadLauncher: DefaultThreadLauncher
    var socketFactory: SocketFactory
    var inflight: ConcurrentHashMap<Int, Request>

    init {
        requestQueue = if (maxQueueSize > 0) {
            LinkedBlockingQueue(maxQueueSize)
        }
        else {
            LinkedBlockingQueue()
        }

        inflight = ConcurrentHashMap<Int, Request>()
        threadLauncher = DefaultThreadLauncher()
        socketFactory = TrustAllSocketFactory()
        target = URL(url)
        socket = socketFactory.create(target.host, 443)
        socket.soTimeout = 10000
        socket.tcpNoDelay = false
        streamCompleteLatch = CountDownLatch(200)
        completedLatch = CountDownLatch(1)
        val connectionClosedLatch = CountDownLatch(1)
        val loggingStreamFrameProcessor: StreamFrameProcessor = ResponseFrameHandler(this)
        val compositeStreamFrameProcessor = CompositeStreamFrameProcessor(loggingStreamFrameProcessor)
        connectionFactory = ConnectionFactory.create(threadLauncher, compositeStreamFrameProcessor)
        connection =
            connectionFactory.createConnection(socket) { connectionClosedLatch.countDown() } // callback is invoked when connection is killed
        frameFactory = RequestFrameFactory.createDefaultRequestFrameFactory(connection.negotiatedMaximumFrameSize())

        thread {
            sendRequests()
        }
    }

    private fun sendRequests() {
        while (!Utils.unloaded && attackState.get() < 3) {
            // todo for pass one just send the requests! then worry about gates/syncing after

            val req = requestQueue.poll(100, TimeUnit.MILLISECONDS) ?: continue
            val frames = reqToFrames(req)
            inflight[frames[0].Q] = req
            connection.sendFrames(frames)
        }
        completedLatch.countDown()
    }

    fun reqToFrames(req: Request): List<Frame> {
        val headerList = buildReq(HTTP2Request(req.getRequest()))
        val properHeaders = ArrayList<Header>(headerList.size)
        for (pair in headerList) {
            properHeaders.add(header(pair.first, pair.second))
        }

        return frameFactory.framesFor(properHeaders, Utils.getBodyBytes(req.getRequestAsBytes()))
    }

//    @Throws(IOException::class, InterruptedException::class)
//    fun sendSynced(vararg requests: List<Header?>?) {
//        val frames: MutableList<Frame> = ArrayList()
//        for (headers in requests) {
//            frames.addAll(frameFactory.framesFor(headers))
//        }
//        frames.sortWith(FrameComparator())
//        assert(frames.size == requests.size * 2)
//        val sublist: List<Frame> = frames.subList(0, requests.size)
//        val endlist: List<Frame> = frames.subList(requests.size, frames.size)
//        socket.tcpNoDelay = false
//        connection.sendFrames(sublist)
//        Thread.sleep(500)
//        socket.tcpNoDelay = true
//        connection.sendFrames(endlist)
//        //Thread.sleep(500);
//        //socket.setTcpNoDelay(false);
//        //responseCollectingStreamFrameProcessor.responses().forEach(System.out::println);
//    }

    fun stop() {
        // latch blah
        connection.stop()
        threadLauncher.destroy()
    }

    override fun start(timeout: Int) {
        // todo wait for connection?
        attackState.set(1)
        start = System.nanoTime()
    }

    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String?): Request {
        return Request(template, payloads, learnBoring ?: 0, label)
    }

    fun handleResponse(streamID: Int, resp: String) {
        successfulRequests.getAndIncrement()
        val req = inflight.remove(streamID) ?: throw RuntimeException("Couldn't find "+streamID+ " in inflight: "+inflight.keys().asSequence())
        req.response = resp
        val interesting = processResponse(req, req.getResponseAsBytes()!!)
        invokeCallback(req, interesting)
    }
}