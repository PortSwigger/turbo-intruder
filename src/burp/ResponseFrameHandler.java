package burp;

import burp.network.stack.http2.frame.DataFrame;
import burp.network.stack.http2.frame.Frame;
import burp.network.stack.http2.frame.Header;
import burp.network.stack.http2.frame.HeaderFrame;
import net.hackxor.api.Http2Constants;
import net.hackxor.api.StreamFrameProcessor;

import javax.xml.crypto.Data;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ResponseFrameHandler implements StreamFrameProcessor {

    private SpikeEngine engine;
    private final Map<Integer, List<DataFrame>> dataFrames = new ConcurrentHashMap<>();
    private final Map<Integer, List<HeaderFrame>> headerFrames = new ConcurrentHashMap<>();

    public ResponseFrameHandler(SpikeEngine engine) {
        this.engine = engine;
    }

    @Override
    public void process(Frame frame) {
        //System.out.println(frame.Q);
        try {
            if (frame instanceof HeaderFrame) {
                List<HeaderFrame> newFrames = this.headerFrames.computeIfAbsent(frame.Q, (id) -> new LinkedList<>());
                newFrames.add((HeaderFrame) frame);
            } else if (frame instanceof DataFrame) {
                List<DataFrame> newFrames = this.dataFrames.computeIfAbsent(frame.Q, (id) -> new LinkedList<>());
                newFrames.add((DataFrame) frame);
            }

            if (frame.isFlagSet(Http2Constants.END_STREAM_FLAG)) {
                prepareCallback(frame.Q);
            }
        } catch (Exception e) {
            Utils.out("Oh no: "+e.getMessage());
            e.printStackTrace();
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

    public void prepareCallback(int streamID) {
        List<HeaderFrame> headers = headerFrames.remove(streamID);
        List<DataFrame> data = dataFrames.remove(streamID);

        StringBuilder resp = new StringBuilder();
        for (HeaderFrame frame: headers) {
            for (Header header: frame.headers()) {
                if (header.isPseudoHeader()) {
                    resp.append("HTTP/2 "+header.value()+ " OK\r\n");
                }
                else {
                    resp.append(header.http1Header());
                    resp.append("\r\n");
                }
            }
        }
        resp.append("\r\n");
        for (DataFrame frame: data) {
            resp.append(new String(frame.data()));
        }

        engine.handleResponse(streamID, resp.toString());
    }
}
