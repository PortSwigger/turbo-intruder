package burp
import java.lang.RuntimeException
import java.net.URL
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import kotlin.collections.ArrayList

open class BurpRequestEngine(url: String, threads: Int, maxQueueSize: Int, override val maxRetriesPerRequest: Int, override var idleTimeout: Long = 0, override val callback: (Request, Boolean) -> Boolean, override var readCallback: ((String) -> Boolean)?, val useHTTP1: Boolean): RequestEngine() {

    private val threadPool = ArrayList<Thread>()
    private val gatedRequests: HashMap<String, LinkedList<Request>> = HashMap()

    init {
        requestQueue = if (maxQueueSize > 0) {
            LinkedBlockingQueue(maxQueueSize)
        }
        else {
            LinkedBlockingQueue()
        }


        completedLatch = CountDownLatch(threads)

        target = URL(url)
        val service = Utils.callbacks.helpers.buildHttpService(target.host, target.port, target.protocol == "https")

        for(j in 1..threads) {
            threadPool.add(
                    thread {
                        sendRequests(service)
                    }
            )
        }
    }

    override fun start(timeout: Int) {
        attackState.set(1)
        start = System.nanoTime()
    }


    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String?): Request {
        var prepared = template
        if (useHTTP1) {
            prepared = prepared.replace("Connection: keep-alive", "Connection: close").replaceFirst("HTTP/2\r\n", "HTTP/1.1\r\n")
        } else {
            if (!Utilities.isHTTP2(prepared.toByteArray())) {
                prepared = prepared.replaceFirst("HTTP/1.1\r\n", "HTTP/2\r\n")
            }
        }
        return Request(prepared, payloads, learnBoring ?: 0, label)
    }

    private fun request(service: IHttpService, req: Request): Pair<IHttpRequestResponse?, Long> {
        val resp: IHttpRequestResponse?
        val startTime = System.nanoTime()
        var responseTime = 0L
        if (useHTTP1) {
            try {

                resp = Utils.callbacks.makeHttpRequest(service, req.getRequestAsBytes(), true)
                responseTime = System.nanoTime() - startTime
            } catch (e: NoSuchMethodError) {
                throw RuntimeException("Please update Burp Suite")
            }
        } else {
            val respBytes = Utils.h2request(service, req.getRequestAsBytes())
            responseTime = System.nanoTime() - startTime
            if (respBytes != null) {
                req.response = Utils.helpers.bytesToString(respBytes)
            }
            resp = BurpRequest(req)
        }

        return Pair(resp, responseTime/1000) // convert to microseconds
    }


    // this will return null unless there's an open gate with pending requests
    private fun getGatedRequests(): List<Request>? {
        val gates = gatedRequests.keys
        for (gate in gates) {
            synchronized(gate) {
                if (floodgates.get(gate)?.isOpen?.get() == true) {
                    val toSend = gatedRequests.get(gate)
                    gatedRequests.remove(gate)
                    return toSend
                }
            }
        }
        return null
    }

    private fun sendRequests(service: IHttpService) {
        while(attackState.get()<1) {
            Thread.sleep(10)
        }


        while(attackState.get() < 3 && !Utils.unloaded) {

            try {
                val requestGroup = getGatedRequests()
                if (requestGroup != null) {
                    val preppedRequestBatch = ArrayList<HttpRequest>()

                    val montoyaService =
                        HttpService.httpService(service.host, service.port, "https".equals(service.protocol))

                    for (req in requestGroup) {
                        val montoyaReq = HttpRequest.httpRequest(montoyaService, req.getRequest())
                        preppedRequestBatch.add(montoyaReq)
                    }

                    val protocolVersion: HttpMode
                    var connectionID = 0
                    if (useHTTP1) {
                        connections.addAndGet(requestGroup.size)
                        protocolVersion = HttpMode.HTTP_1
                    } else {
                        protocolVersion = HttpMode.HTTP_2
                        connectionID = connections.incrementAndGet()
                    }

                    val timer = System.nanoTime()
                    val responses = Utils.montoyaApi.http().sendRequests(preppedRequestBatch, protocolVersion)

                    var n = 0

                    val reqs: ArrayList<Request> = ArrayList()
                    for (resp in responses) {
                        val req = requestGroup.get(n++)

                        // we don't need to support retries for batches requests
                        if (resp.response() == null) {
                            req.response = "The server closed the connection without issuing a response."
                            permaFails.incrementAndGet()
                        } else {
                            successfulRequests.getAndIncrement()
                            req.response = resp.response().toString()
                        }

                        req.time = resp.timingData().get().timeBetweenRequestSentAndStartOfResponse().toNanos() / 1000
                        req.arrival = (timer - start) / 1000 + req.time

                        if (useHTTP1) {
                            req.connectionID = connections.incrementAndGet()
                        } else {
                            req.connectionID = connectionID
                        }
                        req.interesting = processResponse(req, resp.response().toByteArray().bytes)
                        reqs.add(req)
                    }

                    reqs.sortBy { it.time }

                    for (req in reqs) {
                        invokeCallback(req, req.interesting)
                    }

                    continue
                }

                val req = requestQueue.poll(100, TimeUnit.MILLISECONDS)

                if (req == null) {
                    if (gatedRequests.isNotEmpty()) {
                        continue;
                    }

                    if (attackState.get() == 2) {
                        completedLatch.countDown()
                        return
                    } else {
                        continue
                    }
                }

                if (req.gate != null) {
                    gatedRequests.putIfAbsent(req.gate!!.name, LinkedList<Request>())
                    gatedRequests.get(req.gate!!.name)!!.add(req)
                    req.gate!!.remaining.decrementAndGet() // todo is this right?
                    continue
                }

                var resp: IHttpRequestResponse?
                var time: Long
                if (req.endpointOverride != null) {
                    //Utils.out("URL: "+req.endpointOverride)
                    val overrideTarget = URL(req.endpointOverride)
                    val tempService = Utils.callbacks.helpers.buildHttpService(
                        overrideTarget.host,
                        overrideTarget.port,
                        overrideTarget.protocol == "https"
                    )
                    val bytes = Utils.helpers.stringToBytes(req.getRequest().replace("HTTP/2\r\n","HTTP/1.1\r\n"))
                    val startTime = System.nanoTime()
                    resp = Utils.callbacks.makeHttpRequest(tempService, bytes)
                    time = (System.nanoTime() - startTime) / 1000
                } else {
                    val pair = request(service, req)
                    resp = pair.first
                    time = pair.second
                    connections.incrementAndGet()
                    while (resp!!.response == null && shouldRetry(req)) {
                        Utils.out("Retrying ${req.words}")
                        resp = request(service, req).first
                        connections.incrementAndGet()
                        Utils.out("Retried ${req.words}")
                    }
                }

                req.time = time

                passToCallback(req, resp)

            } catch (ex: Exception) {
                ex.printStackTrace()
                Utils.err("Ignoring error: "+ex.toString())
                permaFails.getAndIncrement()
                // todo add null response to table
                continue
            }
        }
    }

    private fun passToCallback(req: Request, resp: IHttpRequestResponse?) {
        if(resp == null || resp.response == null) {
            req.response = "The server closed the connection without issuing a response."
            invokeCallback(req, true)
        }

        if (resp!!.response != null) {
            successfulRequests.getAndIncrement()
            val interesting = processResponse(req, resp.response)
            req.response = Utils.helpers.bytesToString(resp.response) // , StandardCharsets.UTF_8
            invokeCallback(req, interesting)
        }
    }

}