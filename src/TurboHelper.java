package burp;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

class TurboHelper {

    private RequestEngine engine;
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
    }

    void queue(byte[] req) {
        queue(Utilities.helpers.bytesToString(req));
    }

    void queue(String req) {
        queue(req, 0, 0);
    }

    void queue(String req, int pauseBefore, int pauseTime) {
        engine.queue(req, new ArrayList<>(), 0, null, null, null, pauseBefore, pauseTime); // , Integer.toString(id++)
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