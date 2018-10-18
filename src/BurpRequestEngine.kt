package burp
import java.net.URL
import java.util.*
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReadWriteLock
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.thread
import kotlin.concurrent.write

class BurpRequestEngine(url: String, threads: Int, maxQueueSize: Int, val callback: (Request, Boolean) -> Boolean): RequestEngine() {

    private val threadPool = ArrayList<Thread>()

    init {
        if (maxQueueSize > 0) {
            requestQueue = LinkedBlockingQueue<Request>(maxQueueSize)
        }
        else {
            requestQueue = LinkedBlockingQueue<Request>()
        }

        completedLatch = CountDownLatch(threads)
        Utilities.out("Warming up...")
        val target = URL(url)
        val service = BurpExtender.callbacks.helpers.buildHttpService(target.host, target.port, true)

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


    override fun buildRequest(template: String, payload: String?, learnBoring: Int?): Request {
        return Request(template.replace("Connection: keep-alive", "Connection: close"), payload, learnBoring ?: 0)
    }


    private fun sendRequests(service: IHttpService) {
        while(attackState.get()<1) {
            Thread.sleep(10)
        }

        while(attackState.get() < 3 && !BurpExtender.unloaded) {
            val req = requestQueue.poll(100, TimeUnit.MILLISECONDS);

            if(req == null) {
                if (attackState.get() == 2) {
                    completedLatch.countDown()
                    return
                }
                else {
                    continue
                }
            }

            var resp = BurpExtender.callbacks.makeHttpRequest(service, req.getRawRequest())
            while (resp.response == null && shouldRetry(req)) {
                Utilities.out("Retrying "+req.word)
                resp = BurpExtender.callbacks.makeHttpRequest(service, req.getRawRequest())
                Utilities.out("Retried "+req.word)
            }

            if(resp.response == null) {
                req.response = "null"
                callback(req, true)
            }

            if (resp.response != null) {
                successfulRequests.getAndIncrement()
                val interesting = processResponse(req, resp.response)
                req.response = String(resp.response)
                callback(req, interesting)
            }
        }
    }

}