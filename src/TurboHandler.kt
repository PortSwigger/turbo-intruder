package burp

import org.apache.http.HttpException
import org.apache.http.HttpRequest
import org.apache.http.Header
import org.apache.http.entity.StringEntity
import org.apache.http.message.BasicHttpEntityEnclosingRequest
import org.apache.http.nio.ContentDecoder
import org.apache.http.nio.ContentEncoder
import org.apache.http.nio.NHttpClientConnection
import org.apache.http.nio.NHttpClientEventHandler
import java.io.IOException
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicInteger

class TurboHandler(var requestQueue: ArrayBlockingQueue<HttpRequest>, val requestsPerConnection: Int, val readFreq: Int, val successfulRequests: AtomicInteger, val callback: ((String, String) -> Boolean)?) : NHttpClientEventHandler {

    @Throws(IOException::class, HttpException::class)
    override fun connected(nHttpClientConnection: NHttpClientConnection, o: Any) {
        val inflight = ArrayDeque<HttpRequest>()
        nHttpClientConnection.context.setAttribute("inflight", inflight)
        nHttpClientConnection.context.setAttribute("total", 0)
        nHttpClientConnection.context.setAttribute("burst", 0)
        nHttpClientConnection.requestOutput()
        //System.out.println("Connected!");
    }

    @Throws(IOException::class, HttpException::class)
    @Suppress("UNCHECKED_CAST")
    override fun requestReady(nHttpClientConnection: NHttpClientConnection) {

        val context = nHttpClientConnection.context

        val inflight = context.getAttribute("inflight") as ArrayDeque<HttpRequest>

        if (requestQueue.isEmpty()) {
            //System.out.println("Queued everything - requesting responses now");
            if (inflight.isEmpty()) {
                nHttpClientConnection.close()
            }
        } else {
            val total = context.getAttribute("total") as Int
            var burst = context.getAttribute("burst") as Int
            if (inflight.isEmpty() && total < requestsPerConnection) {
                burst = 0
            }

            if (burst < readFreq && total < requestsPerConnection) { // inflight.size() < 100
                val req = requestQueue.poll()
                if (req != null) {
                    inflight.add(req)
                    context.setAttribute("total", total + 1)
                    context.setAttribute("burst", burst + 1)
                    nHttpClientConnection.submitRequest(req)
                }
            } else {

            }
        }
    }

    @Throws(IOException::class, HttpException::class)
    override fun responseReceived(nHttpClientConnection: NHttpClientConnection) {

    }

    @Throws(IOException::class, HttpException::class)
    @Suppress("UNCHECKED_CAST")
    override fun inputReady(nHttpClientConnection: NHttpClientConnection, contentDecoder: ContentDecoder) {

        if (contentDecoder.isCompleted) {
            return
        }


        var contentLengthHeader: Header? = nHttpClientConnection.httpResponse.getFirstHeader("Content-Length")
        val contentLength: Int
        if (contentLengthHeader == null) {
            // System.out.println("No content length") // probably chunked encoding
            contentLength = 2048
        }
        else {
            contentLength = contentLengthHeader.value.toInt()+8
        }
        val dst = ByteBuffer.allocate(contentLength)
        val bytesRead = contentDecoder.read(dst)

        // todo check contentDecoder.isCompleted - supported repeated calls with partial data

        if (bytesRead != -1 || contentDecoder.isCompleted) {

            val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>
            val req = inflight.pop()
            successfulRequests.getAndIncrement()

            val resp = nHttpClientConnection.httpResponse

            resp.entity = StringEntity(String(dst.array()))

            if (callback != null) {
                callback.invoke(AsyncRequestEngine.requestToString(req), AsyncRequestEngine.responseToString(resp))
            }

            if (inflight.isEmpty()) {
                val total = nHttpClientConnection.context.getAttribute("total") as Int
                if (total >= requestsPerConnection) {
                    nHttpClientConnection.close()
                }
            }
        }
    }

    @Throws(IOException::class, HttpException::class)
    @Suppress("UNCHECKED_CAST")
    override fun outputReady(nHttpClientConnection: NHttpClientConnection, contentEncoder: ContentEncoder) {
        if (nHttpClientConnection.isRequestSubmitted) {
            val content = (nHttpClientConnection.httpRequest as BasicHttpEntityEnclosingRequest).entity.content

            val contentLengthHeader: Header? = nHttpClientConnection.httpRequest.getFirstHeader("Content-Length")
            val expectedLength: Int
            if (contentLengthHeader == null) {
                expectedLength = 0
            }
            else {
                expectedLength = contentLengthHeader.value.toInt()
            }
            val dst = ByteArray(expectedLength+8)
            val i = content.read(dst)
            val buf = ByteBuffer.wrap(dst)
            buf.flip()
            contentEncoder.write(buf)

            val buffering = buf.hasRemaining()
            buf.compact()
            if (i == -1 && !buffering) {
                contentEncoder.complete()
            }

            // todo support repeated calls with partial data
            //nHttpClientConnection.suspendOutput();
            //nHttpClientConnection.requestInput();
        }
    }

    @Throws(IOException::class)
    @Suppress("UNCHECKED_CAST")
    override fun endOfInput(nHttpClientConnection: NHttpClientConnection) {
        val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>
        if (inflight.size > 0) {
            println("End of input lost " + inflight.size + " pending responses. Retry scheduled")
        }
        nHttpClientConnection.close()
    }

    @Throws(IOException::class, HttpException::class)
    @Suppress("UNCHECKED_CAST")
    override fun timeout(nHttpClientConnection: NHttpClientConnection) {
        val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>
        if (inflight.size > 0) {
            println("Timeout lost " + inflight.size + " pending responses. Retry scheduled.")
        }
        nHttpClientConnection.close()
    }

    @Suppress("UNCHECKED_CAST")
    override fun closed(nHttpClientConnection: NHttpClientConnection) {
        val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>

        while (!inflight.isEmpty()) {
            requestQueue.add(inflight.pop())
        }
    }

    @Suppress("UNCHECKED_CAST")
    override fun exception(nHttpClientConnection: NHttpClientConnection, e: Exception) {
        val inflight = nHttpClientConnection.context.getAttribute("inflight") as ArrayDeque<HttpRequest>
        if (inflight.size > 0) {
            println(e.message + " lost " + inflight.size + " pending responses. Retry scheduled.")
        }
        //e.printStackTrace();
    }
}