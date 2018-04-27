package burp
import java.net.URL
import java.util.ArrayList
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class BurpRequestEngine(url: String, threads: Int, val callback: (String, String) -> Boolean): RequestEngine() {

    private val threadPool = ArrayList<Thread>()
    private val requestQueue = ArrayBlockingQueue<ByteArray>(8192)

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
        queue(req.replace("Connection: keep-alive", "Connection: close").toByteArray(Charsets.ISO_8859_1))
    }

    fun queue(req: ByteArray) {
        requestQueue.offer(req, 10, TimeUnit.SECONDS) // todo should this be synchronised?
    }

    private fun sendRequests(service: IHttpService) {
        while(attackState.get()<1) {
            Thread.sleep(10)
        }

        while(true) {
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

            val resp = BurpExtender.callbacks.makeHttpRequest(service, req)
            if (resp.response != null) {
                successfulRequests.getAndIncrement()
                callback(String(req), String(resp.response))
            }
            else {
                print("null response :(")
            }
        }
    }

}