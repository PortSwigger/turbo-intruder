package burp
import java.net.URL
import java.util.*
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReadWriteLock
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.thread
import kotlin.concurrent.write

class BurpRequestEngine(url: String, threads: Int, val callback: (String, String, Boolean, String?) -> Boolean): RequestEngine() {

    private val threadPool = ArrayList<Thread>()
    private val requestQueue = ArrayBlockingQueue<Request>(1000000)

    init {
        completedLatch = CountDownLatch(threads)
        println("Warming up...")
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

    override fun queue(req: String) {
        queue(req, null, 0)
    }

    fun queue(template: String, payload: String?) {
        queue(template, payload, 0)
    }

    fun queue(template: String, payload: String?, learnBoring: Int?) {

        val request = Request(template.replace("Connection: keep-alive", "Connection: close"), payload, learnBoring ?: 0)

        val queued = requestQueue.offer(request, 10, TimeUnit.SECONDS)
        if (!queued) {
            println("Timeout queuing request. Aborting.")
            this.showStats(1)
        }
    }

    private fun sendRequests(service: IHttpService) {
        while(attackState.get()<1) {
            Thread.sleep(10)
        }

        while(!BurpExtender.unloaded) {
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

            val resp = BurpExtender.callbacks.makeHttpRequest(service, req.getRawRequest())
            if (resp.response != null) {
                successfulRequests.getAndIncrement()
                val interesting = processResponse(req, resp.response)
                callback(req.getRequest(), String(resp.response), interesting, req.word)
            }
            else {
                print("null response :(")
            }
        }
    }

}