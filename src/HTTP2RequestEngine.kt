package burp
import burp.Request
import burp.RequestEngine
import burp.Utils
import java.lang.Exception
import java.net.URL
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

open class HTTP2RequestEngine(url: String, val threads: Int, maxQueueSize: Int, var requestsPerConnection: Int, override val maxRetriesPerRequest: Int, override val callback: (Request, Boolean) -> Boolean, override var readCallback: ((String) -> Boolean)?): RequestEngine() {

    val responseReadCount = AtomicInteger(0)

    private val connectionPool = ArrayList<Connection>(threads)

    init {
        requestQueue = if (maxQueueSize > 0) {
            LinkedBlockingQueue(maxQueueSize)
        }
        else {
            LinkedBlockingQueue()
        }

        target = URL(url)
        completedLatch = CountDownLatch(threads)

        for (j in 1..threads) {
            connections.incrementAndGet()
            connectionPool.add(Connection(target, responseReadCount, LinkedBlockingQueue(1), requestQueue, requestsPerConnection, this))
        }

        thread(priority = 1) {
            manageConnections()
        }
    }

    // just handles dead connections
    private fun manageConnections() {
        // fixme probably a bit racey
        while (attackState.get() < 3) {
            for (i in 1..threads) {
                val con = connectionPool[i - 1]

                // don't sit around waiting for recycling
                // todo re-enable and check effect on performance
//                if (con.state == Connection.HALFCLOSED) {
//                    connections[i - 1] = Connection(target, responseReadCount, requestQueue, requestsPerConnection)
//                    continue
//                }
                if (con.state == Connection.CLOSED) {
                    val inflight = con.getInflightRequests()
                    if (inflight.size > 0 || con.seedQueue.size > 0 || attackState.get() < 3) {
                        val seedQueue = LinkedBlockingQueue(inflight)
                        seedQueue.addAll(con.seedQueue)
                        if (inflight.size > 0) {
                            retries.getAndIncrement()
                            Utils.out("Connection died, re-queueing "+inflight.size+" unanswered requests.")
                        }
                        connections.incrementAndGet()
                        connectionPool[i - 1] = Connection(target, responseReadCount, seedQueue, requestQueue, requestsPerConnection, this)
                    }
                }
            }
            Thread.sleep(100)
        }
        connectionPool.map{it.close()}
        while (completedLatch.count > 0) {
            completedLatch.countDown()
        }
    }

//    fun complete() {
//        // todo should block?
//        while (requestQueue.size > 0) {
//            Thread.sleep(100)
//        }
//        fullyQueued = true
//
//        //connections.map{it.close()}
//    }

    override fun start(timeout: Int) {
        attackState.set(1)
        start = System.nanoTime()
    }

    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String?): Request {
        return Request(template, payloads, learnBoring?: 0, label)
    }


//    fun queue(request: ByteArray) {
//        if (fullyQueued) {
//            throw IllegalStateException("Cannot queue any more items - the attack has finished")
//        }
//        val queued = requestQueue.offer(request, 1, TimeUnit.SECONDS)
//        if (!queued) {
//            throw IllegalStateException("Timeout queuing request")
//        }
//    }
}
