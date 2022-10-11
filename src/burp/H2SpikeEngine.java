package burp;

import burp.network.stack.http2.frame.Frame;
import net.hackxor.api.*;
import net.hackxor.utils.*;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

public class H2SpikeEngine {
    private String host;
    SSLSocket socket;
    CountDownLatch streamCompleteLatch;
    ConnectionFactory connectionFactory;
    Connection connection;
    RequestFrameFactory frameFactory;
    DefaultThreadLauncher threadLauncher;
    SocketFactory socketFactory;
    //LinkedBlockingQueue<byte[]> requestQueue;


    public H2SpikeEngine(String host) throws IOException {

        //requestQueue = new LinkedBlockingQueue<>(10);

        this.host = host;
        threadLauncher = new DefaultThreadLauncher();
        socketFactory = new TrustAllSocketFactory();

        socket = socketFactory.create(host, 443);
        socket.setSoTimeout(10000);
        socket.setTcpNoDelay(false);

        streamCompleteLatch = new CountDownLatch(200);
        CountDownLatch connectionClosedLatch = new CountDownLatch(1);

        StreamFrameProcessor loggingStreamFrameProcessor = new ResponseFrameHandler();
        CompositeStreamFrameProcessor compositeStreamFrameProcessor = new CompositeStreamFrameProcessor(loggingStreamFrameProcessor);
        connectionFactory = ConnectionFactory.create(threadLauncher, compositeStreamFrameProcessor);
        connection = connectionFactory.createConnection(socket, connectionClosedLatch::countDown); // callback is invoked when connection is killed
        frameFactory = RequestFrameFactory.createDefaultRequestFrameFactory(connection.negotiatedMaximumFrameSize());
    }

    public void sendSynced(List<Header>... requests) throws IOException, InterruptedException {
        List<Frame> frames = new ArrayList<>();
        for (List<Header> headers: requests) {
            frames.addAll(frameFactory.framesFor(headers));
        }

        frames.sort(new FrameComparator());
        assert frames.size() == requests.length * 2;
        List<Frame> sublist = frames.subList(0, requests.length);
        List<Frame> endlist = frames.subList(requests.length, frames.size());

        socket.setTcpNoDelay(false);
        connection.sendFrames(sublist);
        Thread.sleep(500);
        socket.setTcpNoDelay(true);
        connection.sendFrames(endlist);
        //Thread.sleep(500);
        //socket.setTcpNoDelay(false);
        //responseCollectingStreamFrameProcessor.responses().forEach(System.out::println);
    }

    public void stop() {
        // latch blah
        connection.stop();
        threadLauncher.destroy();
    }

}
