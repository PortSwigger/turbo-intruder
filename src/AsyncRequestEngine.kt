/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */
//package org.apache.hc.core5.http.examples;
package burp
import java.util.ArrayDeque
import java.util.concurrent.*

import org.apache.hc.core5.concurrent.FutureCallback
import org.apache.hc.core5.http.*
import org.apache.hc.core5.http.impl.Http1StreamListener
import org.apache.hc.core5.http.impl.bootstrap.AsyncRequesterBootstrap
import org.apache.hc.core5.http.impl.bootstrap.HttpAsyncRequester
import org.apache.hc.core5.http.io.entity.StringEntity
import org.apache.hc.core5.http.message.BasicClassicHttpRequest
import org.apache.hc.core5.http.nio.*
import org.apache.hc.core5.http.nio.entity.BasicAsyncEntityConsumer
import org.apache.hc.core5.http.nio.entity.StringAsyncEntityConsumer
import org.apache.hc.core5.http.nio.entity.StringAsyncEntityProducer
import org.apache.hc.core5.http2.config.H2Config
import org.apache.hc.core5.http2.frame.RawFrame
import org.apache.hc.core5.http2.impl.nio.Http2StreamListener
import org.apache.hc.core5.http2.impl.nio.bootstrap.H2RequesterBootstrap
import org.apache.hc.core5.io.ShutdownType
import org.apache.hc.core5.reactor.IOReactorConfig
import org.apache.hc.core5.util.Timeout
import java.io.IOException
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class AsyncRequestEngine(url: String, threads: Int, readFreq: Int, requestsPerConnection: Int, http2: Boolean, callback: ((String, String) -> Boolean)?): RequestEngine {


    private val requestQueue = ArrayBlockingQueue<Request>(1000000)
    var start: Long = 0
    var successfulRequests = AtomicInteger(0)
    var requester: HttpAsyncRequester
    var latch: CountDownLatch
    var parsed = URL(url)
    val attackState = AtomicInteger(0) // 0 = connecting, 1 = live, 2 = fully queued
    var queuedRequestCount = 0
    private val threadPool = ArrayList<Connection>()

    init {
        if (http2) {
            requester = createHTTP2()
        }
        else {
            requester = createPipe()
        }

        Runtime.getRuntime().addShutdownHook(object : Thread() {
            override fun run() {
                //System.out.println("HTTP requester shutting down");
                requester.shutdown(ShutdownType.GRACEFUL)
            }
        })
        requester.start()


        val target = HttpHost(parsed.host, parsed.port, parsed.protocol)
        latch = CountDownLatch(threads)
        try {
            println("Warming up...")
            for (i in 0 until threads) {
                threadPool.add(Connection(requester, target, requestQueue, requestsPerConnection, readFreq, successfulRequests, latch, attackState, i, callback))
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }


    override fun start(timeout: Int) {
        val stopAt = System.currentTimeMillis() + timeout*1000
        for (thread in threadPool) {
            while (!thread.asleep && System.currentTimeMillis() < stopAt) {
                Thread.sleep(10)
            }
        }

        if(System.currentTimeMillis() >= stopAt) {
            println("Timed out while waiting for all threads to connect")
        }

        start = System.nanoTime()
        attackState.set(1)
        for(thread in threadPool) {
            thread.wake()
        }
    }

    override fun showStats(timeout: Int) {
        attackState.set(2)
        requester.closeExpired()

        for(thread in threadPool) {
            thread.murder()
        }

        val stopAt = System.currentTimeMillis() + timeout*1000


//        Thread.sleep(timeout*1000L)
        while (System.currentTimeMillis() < stopAt) {
            if (successfulRequests.get() >= queuedRequestCount || latch.count == 0L) {
                break
            }

            Thread.sleep(100)

//            for (thread in threadPool) {
//
//                if (thread.connectionFuture != null && !thread.connectionFuture!!.isDone && thread.connectionFuture!!.isDone) {
//                    try {
//                        thread.connectionFuture?.get(1000, TimeUnit.MILLISECONDS)
//                    } catch (e: TimeoutException) {
//                        thread.connectionFuture?.cancel(true)
//                    } catch (e: CancellationException) {
//
//                    }
//                }
//            }
        }

        if (0L != latch.count) {
            println("Timed out with " + latch.count + " threads still running")
            for(thread in threadPool) {
                thread.cancelled()
            }
        }

        val requests = successfulRequests.get().toFloat()
        val duration = System.nanoTime().toFloat() - start
        println("Sent " + requests + " requests in " + duration / 1000000000 + " seconds")
        System.out.printf("RPS: %.0f\n", requests / (duration / 1000000000))
        requester.initiateShutdown()
    }

    override fun queue(req: String) {
        queuedRequestCount += 1
        if (requestQueue.isEmpty()) {
            requestQueue.add(Request(req, parsed))
            threadPool.get(0).wake()
        }
        else {
            requestQueue.add(Request(req, parsed))
        }
    }

    private fun createHTTP2(): HttpAsyncRequester {
        // Create and start requester
        val h2Config = H2Config.custom()
                .setPushEnabled(false)
                .setMaxConcurrentStreams(1000)
                .build()
        //h2Config = H2Config.DEFAULT;

        val requester = H2RequesterBootstrap.bootstrap()
                .setH2Config(h2Config).setMaxTotal(9000000).setDefaultMaxPerRoute(9000000)
                .setStreamListener(object : Http2StreamListener {

                    override fun onHeaderInput(connection: HttpConnection, streamId: Int, headers: List<Header>) {
                        for (i in headers.indices) {
//                            println(connection.toString() + " (" + streamId + ") << " + headers[i])
                        }
                    }

                    override fun onHeaderOutput(connection: HttpConnection, streamId: Int, headers: List<Header>) {
//                        for (i in headers.indices) {
//                            println(connection.toString() + " (" + streamId + ") >> " + headers[i])
//                        }
                    }

                    override fun onFrameInput(connection: HttpConnection, streamId: Int, frame: RawFrame) {
//                        println("argh")
                    }

                    override fun onFrameOutput(connection: HttpConnection, streamId: Int, frame: RawFrame) {}

                    override fun onInputFlowControl(connection: HttpConnection, streamId: Int, delta: Int, actualSize: Int) {}

                    override fun onOutputFlowControl(connection: HttpConnection, streamId: Int, delta: Int, actualSize: Int) {}

                })
                .create()
        return requester
    }

    private fun createPipe(): HttpAsyncRequester {
        val ioReactorConfig = IOReactorConfig.custom()
                .setSoTimeout(5, TimeUnit.SECONDS)
                .build()

        // Create and start requester

        return AsyncRequesterBootstrap.bootstrap()
                .setIOReactorConfig(ioReactorConfig).setMaxTotal(9000000).setDefaultMaxPerRoute(9000000)
                .setStreamListener(object : Http1StreamListener {

                    override fun onRequestHead(connection: HttpConnection, request: HttpRequest) {
                        //System.out.println(connection + " " + new RequestLine(request));

                    }

                    override fun onResponseHead(connection: HttpConnection, response: HttpResponse) {
                        //System.out.println(connection + " " + new StatusLine(response));
                    }

                    override fun onExchangeComplete(connection: HttpConnection, keepAlive: Boolean) {

                    }

                })
                .create()
    }
}

internal class Request(var base: String, var url: URL) {
    lateinit var request: BasicClassicHttpRequest
    var dataProducer: AsyncEntityProducer? = null

    init  {
        try {
            val headers = base.split("\r\n\r\n".toRegex(), 2).toTypedArray()[0].split("\r\n".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            val requestParts = headers[0].split(" ".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

            if (requestParts.size < 2) {
                throw Exception("Bad request line")
            }

            request = BasicClassicHttpRequest(requestParts[0], requestParts[1])


            for (i in 1 until headers.size - 1) {
                val headerParts = headers[i].split(": ".toRegex(), 2).toTypedArray()

                if (headerParts.size < 2) {
                    throw Exception("Bad header: "+headerParts)
                }

                request.addHeader(headerParts[0], headerParts[1])
            }

            request.scheme = url.protocol

            val body = base.split("\r\n\r\n".toRegex(), 2).toTypedArray()
            if (body.size > 1 && "" != body[1]) {
                val entity = StringEntity(body[1])
                entity.isChunked = false
                request.setEntity(entity)
                //dataProducer = BasicAsyncEntityProducer(body[1], ContentType.APPLICATION_FORM_URLENCODED)
                dataProducer = StringAsyncEntityProducer(body[1], 7, 7, ContentType.APPLICATION_FORM_URLENCODED)
            }
            else {
                dataProducer = null
            }


        } catch (e: Exception) {
            println("Error creating request from input string. If the request is malformed, you may need to use the non-async approach")
            e.printStackTrace()
        }
    }

}

internal class Connection(private val requester: HttpAsyncRequester, private val target: HttpHost, private val requestQueue: ArrayBlockingQueue<Request>, private val requestsPerConnection: Int, private val readFreq: Int, private val successfulRequests: AtomicInteger, val latch: CountDownLatch, val attackState: AtomicInteger, val id: Int, val callback: ((String, String) -> Boolean)?) : FutureCallback<Message<HttpResponse, ByteArray>> {
    private var clientEndpoint: AsyncClientEndpoint? = null
    private val inFlight = ArrayDeque<Request>()
    private val connectionCallbackHandler: FutureCallback<AsyncClientEndpoint>
    var connectionFuture: Future<AsyncClientEndpoint>? = null
    private var total = 0
    private var burst = 0
    var asleep = false
    private var abort = false

    init {
        connectionCallbackHandler = ConnectionCallback(this)
        createCon()
    }

    internal fun closeIfComplete(): Boolean {
        if (abort || (inFlight.isEmpty() && requestQueue.isEmpty() && attackState.get() == 2)) {
            conclude()
            return true
        }
        return false
    }

    fun createCon() {
        if (closeIfComplete()) {
            println("Abandoning reconnection - no longer necessary "+id)
            return
        }
        clientEndpoint?.releaseAndDiscard()

        // does this establish a new connection, or just a new channel?
        connectionFuture = requester.connect(target, Timeout.ofSeconds(1), null, connectionCallbackHandler)
        //println("Initiated connection request "+id)
    }

    fun connected(clientEndpoint: AsyncClientEndpoint) {
        this.clientEndpoint = clientEndpoint
        connectionFuture = null
        total = 0
        burst = 0
        //println("Connected: "+id)
        if (attackState.get() == 0) {
            asleep = true
        }
        else {
            triggerRequests()
        }
    }

    fun wake() {
        if (asleep) {
            //println("waking up")
            if (this.clientEndpoint == null) {
                createCon()
            }
            else {
                triggerRequests()
            }
        }
    }

    fun murder() {
        if (asleep) {
            //println("dying in sleep")
            conclude()
        }
    }

    private fun triggerRequests() {
        if (closeIfComplete()) return

        if (total >= requestsPerConnection) {
            createCon()
            return
        }

        if (inFlight.isEmpty()) {
            burst = 0
        }

        while(burst < readFreq && total < requestsPerConnection) {
            val target = requestQueue.poll() ?: break
            request(target)
            burst++
            total++
        }

        asleep = burst == 0
        if (asleep) {
            //println("going to sleep")
        }
    }

    private fun request(req: Request): Future<*> {

        val requestProducer = BasicRequestProducer(req.request, req.dataProducer)

        //val requestProducer = BasicRequestProducer("POST", URI("https://hackxor.net/static/cow"), null) // proves the dataProducer is the problem

        val consumer =  BasicResponseConsumer(BasicAsyncEntityConsumer()) // StringAsyncEntityConsumer vs BasicAsyncEntityConsumer

        val future = clientEndpoint!!.execute(
                requestProducer,
                consumer,
                this)

        inFlight.add(req)
        return future
    }

    override fun completed(message: Message<HttpResponse, ByteArray>) {
        successfulRequests.getAndIncrement()
        val request = inFlight.pop()

        if (callback != null) {
            callback.invoke(request.base, responseToString(message.head, String(message.body)))
        }

        if (inFlight.isEmpty()) {
            triggerRequests()
        }
    }

    override fun failed(ex: Exception) {
        if (!abort) {
            println("Failed!: " + id + " |||" + inFlight.peek().request.requestUri + "->" + ex)
            ex.printStackTrace()

            if (!inFlight.isEmpty()) {
                println("Re-queuing "+inFlight.size +" dropped requests "+id)
                requestQueue.addAll(inFlight)
                inFlight.clear()
            }
            createCon()
        }
    }

    override fun cancelled() {
        //System.out.println("Cancelled " +inFlight.size + " pending requests "+id);
        abort = true
        conclude()
    }

    private fun conclude() {
        //println("done "+id)
        clientEndpoint?.releaseAndDiscard()
        latch.countDown()
    }


    @Throws(IOException::class)
    fun responseToString(resp: HttpResponse, body: String): String {
        val output = StringBuilder()


        output.append(resp.version)
        output.append(" ")
        output.append(resp.code)
        output.append(" ")
        output.append(resp.reasonPhrase)
        output.append("\r\n")

        val headers = resp.headerIterator()
        while (headers.hasNext()) {
            val header = headers.next()
            output.append(header.name)
            output.append(": ")
            output.append(header.value)
            output.append("\r\n")
        }
        output.append("\r\n")

        output.append(body)

        return output.toString()
    }

}

internal class ConnectionCallback(private val con: Connection) : FutureCallback<AsyncClientEndpoint> {

    override fun completed(endpoint: AsyncClientEndpoint) {
        //println("connection established " + con.id)
        con.connected(endpoint)
    }

    override fun failed(e: Exception) {
        //println("Attempt to establish new connection failed. Retrying. " + con.id)
        con.createCon()
    }

    override fun cancelled() {
        //println("Connection attempted cancelled " + con.id)
        con.cancelled()
    }
}