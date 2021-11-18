package burp;
import kotlin.jvm.functions.Function2;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

class TurboHelper {

    RequestEngine engine;
    private List<Resp> reqs = new LinkedList<>();
    private IHttpService service;
    private int id = 0;

    TurboHelper(IHttpService service, boolean reuseConnection) {
        this.service = service;
        String url = service.getProtocol()+"://"+service.getHost()+":"+service.getPort();
        if (reuseConnection) {
            this.engine = new ThreadedRequestEngine(url, 1, 20, 1, 50, 0, this::callback, 10, null, 1024, false);
        }
        else {
            this.engine = new BurpRequestEngine(url, 1, 20, 0, this::callback, null, true);
        }
        engine.start(10);
    }

    void setTimeout(int timeout) {
        ((ThreadedRequestEngine)engine).setTimeout(timeout);
    }

    void queue(byte[] req) {
        queue(Utilities.helpers.bytesToString(req));
    }

    void queue(String req) {
        queue(req, 0, 0);
    }

    void queue(String req, int pauseBefore, int pauseTime) {
        engine.queue(req, new ArrayList<>(), 0, null, null, null, pauseBefore, pauseTime, new byte[0], null); // , Integer.toString(id++)
    }

//    void callbackTest(byte[] req) {
//        engine.queue(Utilities.helpers.bytesToString(req), new ArrayList<>(), 0, this::callbackTest, null, null, 0, 0, new byte[0], null); // , Integer.toString(id++)
//    }
//
//    boolean callbackTest(Request req, boolean interesting) {
//        Utilities.out("got callback");
//        return false;
//    }

    Resp blockingRequest(byte[] req) {
        AtomicReference<Resp> resp = new AtomicReference<>();
        CountDownLatch responseLock = new CountDownLatch(1);
        engine.queue(Utilities.helpers.bytesToString(req), new ArrayList<>(), 0, new Function2<Request, Boolean, Boolean>() {
            @Override
            public Boolean invoke(Request req, Boolean interesting) {
                resp.set(new Resp(new Req(req.getRequestAsBytes(), req.getResponseAsBytes(), service), System.currentTimeMillis()-req.getTime()));
                responseLock.countDown();
                return false;
            }
        }, null, null, 0, 0, new byte[0], null);

        try {
            responseLock.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {

        }
        return resp.get();
    }

    private boolean callback(Request req, boolean interesting) {
        reqs.add(new Resp(new Req(req.getRequestAsBytes(), req.getResponseAsBytes(), service), System.currentTimeMillis()-req.getTime()));
        return false;
    }

    List<Resp> waitFor() {
        //engine.start(10);
        engine.showStats(60);
        return reqs;
    }

    int getConnectionCount() {
        return engine.getConnections().get();
    }
}