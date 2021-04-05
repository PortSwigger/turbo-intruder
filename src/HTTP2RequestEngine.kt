import java.net.URL
import java.util.*
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

class Engine (val target: URL, val maxConnections: Int = 1, val requestsPerConnection: Int = 1){

    var complete = false
    var fullyQueued = false
    val responseReadCount = AtomicInteger(0)
    val requestQueue = LinkedBlockingQueue<ByteArray>(10)

    private val connections = ArrayList<Connection>(this.maxConnections)

    init {
        for (j in 1..this.maxConnections) {
            connections.add(Connection(target, responseReadCount, requestQueue, requestsPerConnection))
        }

        thread(priority = 1) {
            manageConnections()
        }
    }

    // just handles dead connections
    private fun manageConnections() {
        // fixme probably a bit racey
        while (!fullyQueued) {
            for (i in 1..this.maxConnections) {
                val con = connections[i - 1]

                // don't sit around waiting for recycling
//                if (con.state == Connection.HALFCLOSED) {
//                    connections[i - 1] = Connection(target, responseReadCount, requestQueue, requestsPerConnection)
//                    continue
//                }
                if (con.state == Connection.CLOSED) {
                    val inflight = con.getInflightRequests()
                    if (inflight.size > 0 || !fullyQueued) {
                        println("Replacing dead connection")
                        requestQueue.addAll(inflight)
                        connections[i - 1] = Connection(target, responseReadCount, requestQueue, requestsPerConnection)
                    }
                }
            }
            Thread.sleep(100)
        }
        connections.map{it.close()}
        println("Done!")
    }

    fun complete() {
        // todo should block?
        while (requestQueue.size > 0) {
            Thread.sleep(100)
        }
        fullyQueued = true

        //connections.map{it.close()}
    }

    fun queue(request: ByteArray) {
        if (fullyQueued) {
            throw IllegalStateException("Cannot queue any more items - the attack has finished")
        }
        val queued = requestQueue.offer(request, 1, TimeUnit.SECONDS)
        if (!queued) {
            throw IllegalStateException("Timeout queuing request")
        }
    }
}
