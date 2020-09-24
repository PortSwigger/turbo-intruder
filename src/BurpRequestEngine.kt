package burp
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

open class BurpRequestEngine(url: String, threads: Int, maxQueueSize: Int, override val maxRetriesPerRequest: Int, override val callback: (Request, Boolean) -> Boolean, override var readCallback: ((String) -> Boolean)?): RequestEngine() {

    private val threadPool = ArrayList<Thread>()

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
        return Request(template.replace("Connection: keep-alive", "Connection: close"), payloads, learnBoring ?: 0, label)
    }


    private fun sendRequests(service: IHttpService) {
        while(attackState.get()<1) {
            Thread.sleep(10)
        }


        while(attackState.get() < 3 && !Utils.unloaded) {
            val req = requestQueue.poll(100, TimeUnit.MILLISECONDS)

            if(req == null) {
                if (attackState.get() == 2) {
                    completedLatch.countDown()
                    return
                }
                else {
                    continue
                }
            }

            var resp = Utils.callbacks.makeHttpRequest(service, req.getRequestAsBytes())
            connections.incrementAndGet()
            while (resp.response == null && shouldRetry(req)) {
                Utils.out("Retrying ${req.words}")
                resp = Utils.callbacks.makeHttpRequest(service, req.getRequestAsBytes())
                connections.incrementAndGet()
                Utils.out("Retried ${req.words}")
            }

            if(resp.response == null) {
                req.response = "The server closed the connection without issuing a response."
                invokeCallback(req, true)
            }

            if (resp.response != null) {
                successfulRequests.getAndIncrement()
                val interesting = processResponse(req, resp.response)
                req.response = String(resp.response) // , StandardCharsets.UTF_8
                invokeCallback(req, interesting)
            }

        }
    }

}