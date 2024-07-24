package burp

import burp.H2Connection.Companion.buildReq
import burp.network.stack.http2.frame.ContinuationFrame
import burp.network.stack.http2.frame.Frame
import burp.network.stack.http2.frame.FrameFlags
import net.hackxor.api.ConnectionFactory
import net.hackxor.api.Header
import net.hackxor.api.Header.header
import net.hackxor.api.RequestFrameFactory
import net.hackxor.api.SocketFactory
import net.hackxor.utils.DefaultThreadLauncher
import net.hackxor.utils.FrameComparator
import net.hackxor.utils.TrustAllSocketFactory
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class SpikeEngine(url: String, threads: Int, maxQueueSize: Int, val requestsPerConnection: Int, override val maxRetriesPerRequest: Int, override var idleTimeout: Long = 0, override val callback: (Request, Boolean) -> Boolean, override var readCallback: ((String) -> Boolean)?, val warmLocalConnection: Boolean = true, val fatPacket: Boolean = false): RequestEngine() {

    var threadLauncher: DefaultThreadLauncher
    var socketFactory: SocketFactory
    var responseQueue: LinkedBlockingQueue<Request>

    init {
        requestQueue = if (maxQueueSize > 0) {
            LinkedBlockingQueue(maxQueueSize)
        }
        else {
            LinkedBlockingQueue()
        }

        responseQueue = LinkedBlockingQueue(50)
        idleTimeout *= 1000
        threadLauncher = DefaultThreadLauncher()
        socketFactory = TrustAllSocketFactory()
        target = URL(url)
        val retryQueue = LinkedBlockingQueue<Request>()

        completedLatch = CountDownLatch(threads)
        for(j in 1..threads) {
            thread {
                sendRequests(retryQueue)
            }
        }

        thread { processRequests() }
    }

    private fun processRequests() {
        while (!Utils.unloaded && !shouldAbandonAttack()) {
            val resp: Request? = responseQueue.poll(100, TimeUnit.MILLISECONDS) ?: continue
            successfulRequests.getAndIncrement()
            while (resp!!.sent == 0L && !shouldAbandonAttack()) {
                Thread.sleep(100)
            }
            resp.time = (resp.arrival - resp.sent) / 1000
            resp.arrival = (resp.arrival - start) / 1000
            val interesting = processResponse(resp, resp.getResponseAsBytes()!!)
            invokeCallback(resp, interesting)
        }
    }

    private fun sendRequests(retryQueue: LinkedBlockingQueue<Request>) {
        var responseStreamHandler: SpikeConnection? = null

        while (!Utils.unloaded && !shouldAbandonAttack()) {
            val socket = socketFactory.create(target.host, 443)
            socket.soTimeout = 10000
            socket.tcpNoDelay = false
            responseStreamHandler = SpikeConnection(this)
            val connectionID = connections.incrementAndGet()
            val connectionFactory = ConnectionFactory.create(threadLauncher, responseStreamHandler)
            val connection = connectionFactory.createConnection(socket) { } // callback is invoked when connection is killed
            val frameFactory: RequestFrameFactory
            if (fatPacket) {
                frameFactory = RequestFrameFactory.createDefaultRequestFrameFactory(connection.negotiatedMaximumFrameSize())
            } else {
                frameFactory = RequestFrameFactory.createSmallFinalDataFrameRequestFrameFactory(connection.negotiatedMaximumFrameSize())
                //RequestFrameFactory.
                // frameFactory = RequestFrameFactory.createSmallTrailingHeaderRequestFrameFactory(connection.negotiatedMaximumFrameSize()) // this approach sucks
            }

            var requestsSent = 0

            try {
                while (requestsSent < requestsPerConnection && !shouldAbandonAttack()) {
                    if (responseStreamHandler.inflight.size >= 1){
                        // todo make this configurable
                        Thread.sleep(10)
                        continue
                    }

                    var req = retryQueue.poll()
                    if (req == null) {
                        req = requestQueue.poll(100, TimeUnit.MILLISECONDS)
                    }
                    if (req == null) {
                        if (attackState.get() == 2) {
                            waitForPendingRequests(responseStreamHandler)
                            return
                        }
                        continue
                    }

                    if (req.gate == null) {
                        val frames = reqToFrames(req, frameFactory)
                        responseStreamHandler.inflight[frames[0].G] = req
                        req.connectionID = connectionID
                        req.sent = System.nanoTime()
                        connection.sendFrames(frames)
                        requestsSent += 1
                        continue
                    }

                    val gatedReqs = ArrayList<Request>(10)
                    req.gate!!.reportReadyWithoutWaiting()
                    req.connectionID = connectionID
                    gatedReqs.add(req)
                    while ((!req.gate!!.fullyQueued.get() || responseStreamHandler.inflight.size != 0) && !shouldAbandonAttack()) {
                        Thread.sleep(10)
                    }

                    while (!req.gate!!.isOpen.get() && !shouldAbandonAttack()) {
                        //Utils.out("Waiting on ${req.gate!!.remaining.get()} signals for gate to open on ${req.gate!!.name}")
                        val nextReq = requestQueue.poll(50, TimeUnit.MILLISECONDS) ?: throw RuntimeException("Gate deadlock")
                        if (nextReq.gate!!.name != req.gate!!.name) {
                            throw RuntimeException("Over-read while waiting for gate to open")
                        }
                        nextReq.connectionID = connectionID
                        gatedReqs.add(nextReq)
                        if (nextReq.gate!!.reportReadyWithoutWaiting()) {
                            break
                        }
                    }

                    val prepFrames = ArrayList<Frame>(gatedReqs.size)

                    if (fatPacket) {
                        for (gatedReq in gatedReqs) {
                            val reqFrames = reqToFrames(gatedReq, frameFactory)
                            for (frame in reqFrames) {
                                prepFrames.add(frame)
                            }
                            responseStreamHandler.inflight[reqFrames[0].G] = gatedReq
                            requestsSent += 1
                        }

                        if (warmLocalConnection) {
                            val warmer = burp.network.stack.http2.frame.PingFrame("12345678".toByteArray())
                            connection.sendFrames(warmer)
                        }

                        for (gatedReq in gatedReqs) {
                            gatedReq.sent = System.nanoTime()
                        }

                        connection.sendFrames(prepFrames)
                        continue
                    }

                    val finalFrames = ArrayList<Pair<Frame, Long>>(gatedReqs.size)

                    for (gatedReq in gatedReqs) {
                        val reqFrames = reqToFrames(gatedReq, frameFactory)
                        for (frame in reqFrames) {
                            if (frame.isFlagSet(0x01)) { // end_stream
                                finalFrames.add(Pair(frame, gatedReq.delayCompletion))
                            }
                            else {

                                // negative spike thing to check for pseudo-only reply
                                if (frame.isFlagSet(0x04)) {
                                    frame.v.Z(FrameFlags(0x04))
                                }

                                prepFrames.add(frame)
                            }
                        }
                        responseStreamHandler.inflight[reqFrames[0].G] = gatedReq
                        requestsSent += 1
                    }

                    socket.tcpNoDelay = false // original

                    if (warmLocalConnection) {
                        val warmer = burp.network.stack.http2.frame.PingFrame("12345678".toByteArray())
                        connection.sendFrames(warmer) // just send it straight away
                    }

                    connection.sendFrames(prepFrames)
                    Thread.sleep(100) // headstart size

                    for (gatedReq in gatedReqs) {
                        gatedReq.sent = System.nanoTime()
                    }

                    if (warmLocalConnection) {
                        val warmer = burp.network.stack.http2.frame.PingFrame("12345678".toByteArray())
                        // val warmer = burp.network.stack.http2.frame.DataFrame(finalFrames[0].Q, FrameFlags(0), "".toByteArray())
                        // using an empty data frame upsets some servers
                        connection.sendFrames(warmer) // just send it straight away
                        //finalFrames.add(0, warmer)
                    }

                    for (pair in finalFrames) {
                        //Utils.out("Sending final frame")
                        if (pair.second != 0L) {
                            //Utils.out("Sleeping for "+pair.second)
                            // fixme response arrives before this frame is sent!
                            Thread.sleep(pair.second)
                        }
                        //Utils.out("Finished sleeping")
                        connection.sendFrames(pair.first)
                    }
                    //connection.sendFrames(finalFrames)
                }
            } catch (ex: Exception) {
                if (!responseStreamHandler.inflight.isEmpty()) {
                    for (req in responseStreamHandler.inflight.values) {
                        if (shouldRetry(req)) {
                            retryQueue.add(req)
                        }
                    }
                }
                ex.printStackTrace()
                Utils.out(ex.message)
                continue
            }
        }

        waitForPendingRequests(responseStreamHandler)
    }

    private fun waitForPendingRequests(responseStreamHandler: SpikeConnection?) {
        for (x in 1..100) {
            if (responseStreamHandler != null && !responseStreamHandler.inflight.isEmpty()) {
                Thread.sleep(100)
            } else {
                break
            }
        }
        completedLatch.countDown()
    }

    fun reqToFrames(req: Request, factory: RequestFrameFactory): List<Frame> {
        val headerList = buildReq(HTTP2Request(req.getRequest()), false)
        val properHeaders = ArrayList<Header>(headerList.size)
        for (pair in headerList) {
            properHeaders.add(header(pair.first, pair.second))
        }
        return factory.framesFor(properHeaders, Utils.getBodyBytes(req.getRequestAsBytes()))
    }

    fun stop() {
        // latch blah
        // connection.stop()
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
}