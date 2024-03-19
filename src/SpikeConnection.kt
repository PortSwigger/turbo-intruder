package burp

import burp.network.stack.http2.frame.DataFrame
import burp.network.stack.http2.frame.Frame
import burp.network.stack.http2.frame.HeaderFrame
import burp.network.stack.http2.frame.ResetStreamFrame
import net.hackxor.api.Http2Constants
import net.hackxor.api.StreamFrameProcessor
import java.io.ByteArrayOutputStream
import java.util.*
import java.util.concurrent.ConcurrentHashMap

class SpikeConnection(private val engine: SpikeEngine) : StreamFrameProcessor {

    var inflight: ConcurrentHashMap<Int, Request>
    private val dataFrames: MutableMap<Int, MutableList<DataFrame>> = ConcurrentHashMap()
    private val headerFrames: MutableMap<Int, MutableList<HeaderFrame>> = ConcurrentHashMap()
    private val gates: ConcurrentHashMap<String, Int> = ConcurrentHashMap()

    init {
        inflight = ConcurrentHashMap<Int, Request>()
    }

    override fun process(frame: Frame) {
        //System.out.println(frame.Q);
        try {

            if (frame is ResetStreamFrame) {
                val time = System.nanoTime()
                val req = inflight[frame.G] ?: return
                req.arrival = time
                if (req.gate != null) {
                    val gateName = req!!.gate!!.name
                    val seen = gates.getOrDefault(gateName, 0)
                    req.order = seen
                    gates[gateName] = seen + 1
                }
                prepareCallback(frame.G)
            } else if (frame is HeaderFrame) {
                val time = System.nanoTime()
                val req = inflight[frame.G]!!
                req.arrival = time
                if (req.gate != null) {
                    val gateName = req!!.gate!!.name
                    val seen = gates.getOrDefault(gateName, 0)
                    req.order = seen
                    gates[gateName] = seen + 1
                }
                if (frame is HeaderFrame) {
                    val newFrames = headerFrames.computeIfAbsent(frame.G) { id: Int? -> LinkedList() }
                    newFrames.add(frame)
                }
            } else if (frame is DataFrame) {
                val newFrames = dataFrames.computeIfAbsent(
                    frame.G
                ) { id: Int? -> LinkedList() }
                newFrames.add(frame)
            }

            if (frame.isFlagSet(Http2Constants.END_STREAM_FLAG) ) {
                prepareCallback(frame.G)
            }
        } catch (e: Exception) {
            Utils.out("Oh no: " + e.message)
            e.printStackTrace()
        }


//        if (frame instanceof HeaderFrame) {
//            List<Header> headers = ((HeaderFrame) frame).headers();
//            System.out.println(frame.Q);
//            for (Header header: headers) {
//                if (header.name().equals("x-time")) {
//                    long time =  Long.parseLong(header.value());
//                    if (recordedTime == 0) {
//                        recordedTime = time;
//                    } else {
//                        System.out.println(frame.Q+": " + (time - recordedTime)+"μs");
//                        recordedTime = 0;
//                    }
//                }
//            }
        //frame.isFlagSet(Http2Constants.END_HEADERS_FLAG)
        //((DataFrame) frame).data()
        //}
    }

    fun prepareCallback(streamID: Int) {
        val headers: List<HeaderFrame> = headerFrames.remove(streamID)?: emptyList()
        val data: List<DataFrame> = dataFrames.remove(streamID)?: emptyList()
        val resp = StringBuilder()
        for (frame in headers) {
            for (header in frame.headers()) {
                if (header.isPseudoHeader) {
                    resp.append("HTTP/2 ${header.value()} OK\r\n")
                } else {
                    resp.append(header.name()+": "+header.value())
                    resp.append("\r\n")
                }
            }
        }

        if (headers.isEmpty()){
            resp.append("null")
        } else {
            resp.append("\r\n")
        }

        val bodyBytes = ByteArrayOutputStream()
        for (frame in data) {
            bodyBytes.writeBytes(frame.data())
        }

        val bodyString = Utils.bytesToString(bodyBytes.toByteArray())
        resp.append(ThreadedRequestEngine.uncompressIfNecessary(resp.toString(), bodyString))

        val req = inflight.remove(streamID) ?: throw RuntimeException("Couldn't find "+streamID+ " in inflight: "+inflight.keys().asSequence())
        req.response = resp.toString()
        engine.responseQueue.put(req)
    }
}