package burp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;

public class TurboLib {
    static MaxSizeHashMap<IHttpService, burp.TurboHelper> cachedConnections;

    static {
        cachedConnections = new MaxSizeHashMap<>(32);
    }

    static TurboHelper createConnectionIfRequired(IHttpService service, byte[] req) {
        TurboHelper connection;
        if (cachedConnections.containsKey(service) && !cachedConnections.get(service).engine.shouldAbandonAttack()) {
            connection = cachedConnections.get(service);
        } else {
            boolean forceH2 = Utilities.isHTTP2(req);
            connection = new burp.TurboHelper(service, true, 3, forceH2);
            cachedConnections.put(service, connection);
        }
        return connection;
    }

    static Resp request(IHttpService service, byte[] req) {
        synchronized (service) {
            TurboHelper connection = createConnectionIfRequired(service, req);
            return connection.blockingRequest(req);
        }
    }

    // fixme broken
    static List<HttpRequestResponse> requestGroup(List<HttpRequest> reqList) {
        HttpService montoyaService = reqList.get(0).httpService();
        IHttpService service = Utilities.helpers.buildHttpService(montoyaService.host(), montoyaService.port(), montoyaService.secure());
        synchronized (service) {
            ArrayList<byte[]> reqs = new ArrayList<>();
            for (HttpRequest req: reqList) {
                reqs.add(req.toByteArray().getBytes());
            }
            // TurboHelper connection = createConnectionIfRequired(service, reqList.get(0).toByteArray().getBytes());
            TurboHelper connection = new TurboHelper(service, true, 5, true, true);
            ArrayList<Resp> resps = connection.blockingRequest(reqs, 0, 0);
            List<HttpRequestResponse> montoyaResps = new ArrayList<>();
            for (Resp resp: resps) {
                montoyaResps.add(Utilities.buildMontoyaResp(resp));
            }
            return montoyaResps;
        }
    }


    static class MaxSizeHashMap<K, V> extends LinkedHashMap<K, V> {
        private final int maxSize;

        public MaxSizeHashMap(int maxSize) {
            super(maxSize, 0.75F, true);
            this.maxSize = maxSize;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            return size() > maxSize;
        }
    }
}
