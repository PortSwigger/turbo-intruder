package burp

import burp.network.stack.http2.frame.DataFrame
import burp.network.stack.http2.frame.Frame
import burp.network.stack.http2.frame.HeaderFrame
import net.hackxor.api.Http2Constants
import net.hackxor.api.StreamFrameProcessor
import java.util.*
import java.util.concurrent.ConcurrentHashMap

class SpikeConnection(private val engine: SpikeEngine) : StreamFrameProcessor {

    var inflight: ConcurrentHashMap<Int, Request>
    private val dataFrames: MutableMap<Int, MutableList<DataFrame>> = ConcurrentHashMap()
    private val headerFrames: MutableMap<Int, MutableList<HeaderFrame>> = ConcurrentHashMap()

    init {
        inflight = ConcurrentHashMap<Int, Request>()
    }

    override fun process(frame: Frame) {
        //System.out.println(frame.Q);
        try {
            if (frame is HeaderFrame) {
                val newFrames = headerFrames.computeIfAbsent(
                    frame.Q
                ) { id: Int? -> LinkedList() }
                newFrames.add(frame)
            } else if (frame is DataFrame) {
                val newFrames = dataFrames.computeIfAbsent(
                    frame.Q
                ) { id: Int? -> LinkedList() }
                newFrames.add(frame)
            }
            if (frame.isFlagSet(Http2Constants.END_STREAM_FLAG)) {
                prepareCallback(frame.Q)
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
        val headers: List<HeaderFrame> = headerFrames.remove(streamID)!!
        val data: List<DataFrame> = dataFrames.remove(streamID)!!
        val resp = StringBuilder()
        for (frame in headers) {
            for (header in frame.headers()) {
                if (header.isPseudoHeader) {
                    resp.append(
                        """HTTP/2 ${header.value()} OK
"""
                    )
                } else {
                    resp.append(header.http1Header())
                    resp.append("\r\n")
                }
            }
        }
        resp.append("\r\n")
        for (frame in data) {
            resp.append(String(frame.data()))
        }

        val req = inflight.remove(streamID) ?: throw RuntimeException("Couldn't find "+streamID+ " in inflight: "+inflight.keys().asSequence())
        engine.handleResponse(streamID, resp.toString(), req)
    }
}