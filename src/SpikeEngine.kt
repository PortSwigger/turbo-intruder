package burp

import burp.H2Connection.Companion.buildReq
import burp.network.stack.http2.frame.Frame
import net.hackxor.api.*
import net.hackxor.api.Header.header
import net.hackxor.utils.DefaultThreadLauncher
import net.hackxor.utils.TrustAllSocketFactory
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class SpikeEngine(url: String, threads: Int, maxQueueSize: Int, override val maxRetriesPerRequest: Int, override val callback: (Request, Boolean) -> Boolean, override var readCallback: ((String) -> Boolean)?): RequestEngine() {

    var threadLauncher: DefaultThreadLauncher
    var socketFactory: SocketFactory

    init {
        requestQueue = if (maxQueueSize > 0) {
            LinkedBlockingQueue(maxQueueSize)
        }
        else {
            LinkedBlockingQueue()
        }

        threadLauncher = DefaultThreadLauncher()
        socketFactory = TrustAllSocketFactory()
        target = URL(url)

        completedLatch = CountDownLatch(threads)
        for(j in 1..threads) {
            thread {
                sendRequests()
            }
        }
    }

    private fun sendRequests() {
        while (!Utils.unloaded && attackState.get() < 3) {
            val socket = socketFactory.create(target.host, 443)
            socket.soTimeout = 10000
            socket.tcpNoDelay = false
            val responseStreamHandler = SpikeConnection(this)
            val connectionFactory = ConnectionFactory.create(threadLauncher, responseStreamHandler)
            val connection = connectionFactory.createConnection(socket) { } // callback is invoked when connection is killed
            val frameFactory = RequestFrameFactory.createDefaultRequestFrameFactory(connection.negotiatedMaximumFrameSize())

            try {
                while (!Utils.unloaded && attackState.get() < 3) {
                    if (responseStreamHandler.inflight.size > 10){ // todo make this configurable
                        Thread.sleep(10)
                        continue
                    }

                    val req = requestQueue.poll(100, TimeUnit.MILLISECONDS)
                    if (req == null) {
                        if (attackState.get() == 2) {
                            completedLatch.countDown()
                            return
                        }
                        continue
                    }
                    val frames = reqToFrames(req, frameFactory)
                    responseStreamHandler.inflight[frames[0].Q] = req
                    req.time = System.nanoTime()
                    connection.sendFrames(frames)
                }
            } catch (ex: Exception) {
                // todo sort out lost inflight requests
                continue
            }
        }
        completedLatch.countDown()
    }

    fun reqToFrames(req: Request, factory: RequestFrameFactory): List<Frame> {
        val headerList = buildReq(HTTP2Request(req.getRequest()))
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

    fun handleResponse(streamID: Int, resp: String, req: Request) {
        successfulRequests.getAndIncrement()
        req.response = resp
        val interesting = processResponse(req, req.getResponseAsBytes()!!)
        invokeCallback(req, interesting)
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