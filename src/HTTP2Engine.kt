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


object Http2MultiStreamExecutionExample {

    @Throws(Exception::class)
    @JvmStatic
    fun main(args: Array<String>) {
        val engine = HTTP2Engine("https://research1.hackxor.net/", args[0].toInt(), args[1].toInt(), args[2].toInt(), ::callback)

        val REQUESTCOUNT = args[3].toInt()
        for (i in 0 until REQUESTCOUNT) {
            //val requestString = "GET /static/cow HTTP/1.1\r\nHost: research1.hackxor.net\r\nConnection: keep-alive\r\n\r\n"
            val requestString = "POST /static/cow HTTP/1.1\r\nHost: hackxor.net\r\nConnectionz: keep-alive\r\nContent-Length: 7\r\n\r\nfoo=bar"

            engine.queue(requestString)
            //Thread.sleep(10);
        }
        engine.start()
        engine.showStats()
    }


    fun callback(req: String, resp: String): Boolean {
        //println(req)
        //println("-------")
        //println(resp)
        return false
    }

}

class HTTP2Engine(val url: String, val threads: Int, val readFreq: Int, val requestsPerConnection: Int, val callback: ((String, String) -> Boolean)?): RequestEngine {


    private val requestQueue = ArrayBlockingQueue<Request>(1000000)
    var start: Long = 0
    var successfulRequests = AtomicInteger(0)
    var requester: HttpAsyncRequester
    lateinit var latch: CountDownLatch
    var parsed = URL(url)
    val fullyQueued = AtomicBoolean(false)
    private val threadPool = ArrayList<Connection>()

    init {
        requester = createPipe();
        //requester = createHTTP2()

        Runtime.getRuntime().addShutdownHook(object : Thread() {
            override fun run() {
                //System.out.println("HTTP requester shutting down");
                requester.shutdown(ShutdownType.GRACEFUL)
            }
        })
        requester.start()

    }


    override fun start() {
        val target = HttpHost(parsed.host, parsed.port, parsed.protocol)
        start = System.nanoTime()
        latch = CountDownLatch(threads)


        try {
            println("Starting...")
            for (i in 0 until threads) {
                threadPool.add(Connection(requester, target, requestQueue, requestsPerConnection, readFreq, successfulRequests, latch, fullyQueued, callback))
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }

    }

    override fun showStats(timeout: Int) {
        fullyQueued.set(true)

        if (timeout != -1) {
            latch.await(timeout.toLong(), TimeUnit.SECONDS)
        } else {
            latch.await()
        }

        if (0L != latch.count) {
            println("Timed out with " + latch.count + " threads still running")
        }
        else {
            println("Completed.")
        }

        val requests = successfulRequests.get().toFloat()
        val duration = System.nanoTime().toFloat() - start
        println("Sent " + requests + " requests in " + duration / 1000000000 + " seconds")
        System.out.printf("RPS: %.0f\n", requests / (duration / 1000000000))
        requester.initiateShutdown()
    }

    override fun queue(req: String) {
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

internal class Connection(private val requester: HttpAsyncRequester, private val target: HttpHost, private val requestQueue: ArrayBlockingQueue<Request>, private val requestsPerConnection: Int, private val readFreq: Int, private val successfulRequests: AtomicInteger, val latch: CountDownLatch, val fullyQueued: AtomicBoolean, val callback: ((String, String) -> Boolean)?) : FutureCallback<Message<HttpResponse, String>> {
    private var clientEndpoint: AsyncClientEndpoint? = null
    private val inFlight = ArrayDeque<Request>()
    private val connectionCallbackHandler: FutureCallback<AsyncClientEndpoint>
    private var total = 0
    private var burst = 0
    private var asleep = false

    init {
        connectionCallbackHandler = ConnectionCallback(this)
        createCon()
    }

    internal fun closeIfComplete(): Boolean {
        if (inFlight.isEmpty() && requestQueue.isEmpty() && fullyQueued.get()) {
            conclude()
            return true
        }
        return false
    }

    fun createCon() {
        if (closeIfComplete()) return

        // does this establish a new connection, or just a new channel?
        requester.connect(target, Timeout.ofSeconds(5), null, connectionCallbackHandler)
        //clientEndpoint = future.get();
    }

    fun connected(clientEndpoint: AsyncClientEndpoint) {
        this.clientEndpoint = clientEndpoint
        total = 0
        triggerRequests()
    }

    fun wake() {
        if (asleep) {
            if (this.clientEndpoint == null) {
                createCon()
            }
            else {
                triggerRequests()
            }
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
    }

    private fun request(req: Request): Future<*> {

        val requestProducer = BasicRequestProducer(req.request, req.dataProducer)

        //val requestProducer = BasicRequestProducer("POST", URI("https://hackxor.net/static/cow"), null) // proves the dataProducer is the problem

        val consumer =  BasicResponseConsumer(StringAsyncEntityConsumer()) // StringAsyncEntityConsumer vs BasicAsyncEntityConsumer

        val future = clientEndpoint!!.execute(
                requestProducer,
                consumer,
                this)

        inFlight.add(req)
        return future
    }

    private fun connectionDropped() {
        println("Connection dropped. Reconnecting")
        if (!inFlight.isEmpty()) {
            println("Re-queuing dropped requests")
            requestQueue.addAll(inFlight)
            inFlight.clear()
        }
        //clientEndpoint!!.releaseAndDiscard();
        createCon()
    }


    override fun completed(message: Message<HttpResponse, String>) {
        successfulRequests.getAndIncrement()
        val request = inFlight.pop()

        if (callback != null) {
            callback.invoke(request.base, responseToString(message.head, message.body))
        }

        if (inFlight.isEmpty()) {
            triggerRequests()
        }
    }

    override fun failed(ex: Exception) {
        println("Failed!: " + inFlight.peek().request.requestUri + "->" + ex)
        connectionDropped()
    }

    override fun cancelled() {
        if (closeIfComplete()) return
        System.out.println("Cancelled: " +inFlight.size);
        conclude()
    }

    private fun conclude() {
        print("done!")
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
        //System.out.println("Connection established");
        con.connected(endpoint)
    }

    override fun failed(e: Exception) {
        println("Attempt to establish new connection failed. Retrying.")
        con.createCon()
    }

    override fun cancelled() {

    }
}