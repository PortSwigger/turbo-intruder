package burp;
import burp.api.montoya.MontoyaApi;
import kotlin.NotImplementedError;
import kotlin.jvm.functions.Function2;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

class TurboHelper implements AutoCloseable {

    RequestEngine engine;
    private List<Resp> reqs = new LinkedList<>();

    public IHttpService getService() {
        return service;
    }

    private int attacks = 0;

    private IHttpService service;
    private int requestTimeout;
    private int id = 0;

    static void setup(IBurpExtenderCallbacks callbacks, MontoyaApi api) {
        Utils.callbacks = callbacks;
        Utils.helpers = callbacks.getHelpers();
        Utils.montoyaApi = api;
    }

    TurboHelper(IHttpService service, boolean reuseConnection) {
        this(service, reuseConnection, 10, false);
    }

    TurboHelper(IHttpService service, boolean reuseConnection, int requestTimeout) {
        this(service, reuseConnection, requestTimeout, false);
    }

    TurboHelper(IHttpService service, boolean reuseConnection, int requestTimeout, boolean forceH2) {
        this(service, reuseConnection, requestTimeout, forceH2, false);
    }

    TurboHelper(IHttpService service, boolean reuseConnection, int requestTimeout, boolean forceH2, boolean useSpike) {
        this.service = service;
        this.requestTimeout = requestTimeout;
        String url = service.getProtocol()+"://"+service.getHost()+":"+service.getPort();
        if (forceH2) {
            if (useSpike) {
                throw new NotImplementedError("Spike engine not available");
                // this.engine = new SpikeEngine(url, 1, 20, 90, 0, 10, this::callback, null, true, false);
            } else {
                this.engine = new BurpRequestEngine(url, 1, 20, 0, 0, this::callback, null, false);
            }
        }
        else if (reuseConnection) {
            this.engine = new ThreadedRequestEngine(url, 1, 20, 1, 50, 0, requestTimeout*10, this::callback, requestTimeout, null, 1024, false, true);
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
        engine.queue(req, new ArrayList<>(), 0, null, null, "", pauseBefore, pauseTime, new ArrayList<>(), 0, null, null); // , Integer.toString(id++)
    }

    Resp blockingRequest(byte[] req) {
        return blockingRequest(req, 0, 0);
    }

    Resp blockingRequest(byte[] req, int pauseBefore, int pauseTime) {
        ArrayList<byte[]> reqs = new ArrayList<>();
        reqs.add(req);
        return blockingRequest(reqs, pauseBefore, pauseTime).get(0);
    }

    ArrayList<Resp> blockingRequest(ArrayList<byte[]> reqs, int pauseBefore, int pauseTime) {
        ArrayList<Resp> resps = new ArrayList<>(reqs.size());
        CountDownLatch responseLock = new CountDownLatch(reqs.size());
        String gateName = null;
        if (reqs.size() > 1) {
            gateName = String.valueOf(attacks);
            attacks += 1;
        }

        int index = 0;
        for (byte[] req: reqs) {
            resps.add(null);
            int finalI = index;
            engine.queue(Utilities.helpers.bytesToString(req), new ArrayList<>(), 0, new Function2<Request, Boolean, Boolean>() {
                @Override
                public Boolean invoke(Request req, Boolean interesting) {
                    try {
                        // fixme this messes up the responseTime, making req.failed() incorrect
                        resps.set(finalI, new Resp(new Req(req.getRequestAsBytes(), req.getResponseAsBytes(), service), System.currentTimeMillis() - req.getTime()));
                    } catch (Exception e) {
                        Utils.err(e.getMessage());
                    }
                    responseLock.countDown();
                    return false;
                }
            }, gateName, "", pauseBefore, pauseTime, new ArrayList<>(), 0, null, null);
            index += 1;
        }

        if (gateName != null) {
            engine.openGate(gateName);
        }

        try {
            //Utils.err("Request queued, waiting "+ (requestTimeout+1) +"s for callback");
            boolean done = responseLock.await(requestTimeout+1, TimeUnit.SECONDS);
            if (!done) {
                waitFor(1);
            }
        } catch (InterruptedException e) {
            waitFor(1);
        }

        for (int i=0; i<reqs.size(); i+=1) {
            if (resps.get(i) == null) {
                resps.set(i, dudResponse(reqs.get(0)));
            }
        }

        // todo put the responses in the order the requests were queued. use label as id?
        return resps;
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