package burp;
import kotlin.jvm.functions.Function2;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

class TurboHelper implements AutoCloseable {

    RequestEngine engine;
    private List<Resp> reqs = new LinkedList<>();

    public IHttpService getService() {
        return service;
    }

    private IHttpService service;
    private int requestTimeout;
    private int id = 0;

    TurboHelper(IHttpService service, boolean reuseConnection) {
        this(service, reuseConnection, 10, false);
    }

    TurboHelper(IHttpService service, boolean reuseConnection, int requestTimeout) {
        this(service, reuseConnection, requestTimeout, false);
    }

    TurboHelper(IHttpService service, boolean reuseConnection, int requestTimeout, boolean forceH2) {
        this.service = service;
        this.requestTimeout = requestTimeout;
        String url = service.getProtocol()+"://"+service.getHost()+":"+service.getPort();
        if (forceH2) {
            //this.engine = new SpikeEngine(url, 1, 20, 90, 0, 10, this::callback, null, true);
            this.engine = new BurpRequestEngine(url, 1, 20, 0, 0, this::callback, null, false);
        }
        else if (reuseConnection) {
            this.engine = new ThreadedRequestEngine(url, 1, 20, 1, 50, 0, 10, this::callback, requestTimeout, null, 1024, false, true);
        }
        else {
            this.engine = new BurpRequestEngine(url, 1, 20, 0, 0, this::callback, null, true);
        }
        engine.start(5);
    }

//    void setTimeout(int timeout) {
//        ((ThreadedRequestEngine)engine).setTimeout(timeout);
//    }

    void queue(byte[] req) {
        queue(Utilities.helpers.bytesToString(req));
    }

    void queue(String req) {
        queue(req, 0, 0);
    }

    void queue(String req, int pauseBefore, int pauseTime) {
        engine.queue(req, new ArrayList<>(), 0, null, null, null, pauseBefore, pauseTime, new ArrayList<>(), 0, null, null); // , Integer.toString(id++)
    }

    Resp blockingRequest(byte[] req) {
        return blockingRequest(req, 0, 0);
    }

    Resp blockingRequest(byte[] req, int pauseBefore, int pauseTime) {
        AtomicReference<Resp> resp = new AtomicReference<>();
        CountDownLatch responseLock = new CountDownLatch(1);
        engine.queue(Utilities.helpers.bytesToString(req), new ArrayList<>(), 0, new Function2<Request, Boolean, Boolean>() {
            @Override
            public Boolean invoke(Request req, Boolean interesting) {
                try {
                    resp.set(new Resp(new Req(req.getRequestAsBytes(), req.getResponseAsBytes(), service), System.currentTimeMillis() - req.getTime()));
                } catch (Exception e) {
                    Utils.err(e.getMessage());
                }
                responseLock.countDown();
                return false;
            }
        }, null, null, pauseBefore, pauseTime, new ArrayList<>(), 0, null, null);

        try {
            //Utils.err("Request queued, waiting "+ (requestTimeout+1) +"s for callback");
            boolean done = responseLock.await(requestTimeout+1, TimeUnit.SECONDS);
            if (!done) {
                waitFor(1);
                return dudResponse(req);
            }
        } catch (InterruptedException e) {
            waitFor(1);
            return dudResponse(req);
        }
        return resp.get();
    }

    private Resp dudResponse(byte[] req) {
        return new Resp(new Req(req, "null".getBytes(), service));
    }

    private boolean callback(Request req, boolean interesting) {
        reqs.add(new Resp(new Req(req.getRequestAsBytes(), req.getResponseAsBytes(), service), System.currentTimeMillis()-req.getTime()));
        return false;
    }

    List<Resp> waitFor() {
        return waitFor(65);
    }

    List<Resp> waitFor(int timeout) {
        //engine.start(10);
        engine.showStats(timeout);
        return reqs;
    }

    int getConnectionCount() {
        return engine.getConnections().get();
    }

    @Override
    public void close() throws IOException {
        waitFor();
    }
}