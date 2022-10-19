package burp;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class TurboLib {
    static MaxSizeHashMap<IHttpService, burp.TurboHelper> cachedConnections;

    static {
        cachedConnections = new MaxSizeHashMap<>(32);
    }

    static Resp request(IHttpService service, byte[] req) {
        synchronized (service) {
            burp.TurboHelper connection;
            if (cachedConnections.containsKey(service)) {
                connection = cachedConnections.get(service);
            } else {
                boolean forceH2 = Utilities.isHTTP2(req);
                connection = new burp.TurboHelper(service, true, 3, forceH2);
                cachedConnections.put(service, connection);
            }
            return connection.blockingRequest(req);
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
