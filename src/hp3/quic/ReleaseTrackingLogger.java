package hp3.quic;

import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.packet.QuicPacket;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Marks an SDA bundle after Kwik's UDP socket send has returned. */
final class ReleaseTrackingLogger extends NullLogger {
    private final Set<AtomicStreamFrameBundle> pending = ConcurrentHashMap.newKeySet();

    Logger wrap(Logger delegate) {
        if (delegate == null) {
            return this;
        }
        return (Logger) Proxy.newProxyInstance(
                Logger.class.getClassLoader(),
                new Class<?>[] {Logger.class},
                (proxy, method, arguments) -> {
                    if (method.getName().equals("sent") && arguments != null && arguments.length == 2) {
                        markSentArgument(arguments[1]);
                    }
                    return method.invoke(delegate, arguments);
                });
    }

    void expect(AtomicStreamFrameBundle bundle) {
        pending.add(bundle);
    }

    void cancel(AtomicStreamFrameBundle bundle) {
        pending.remove(bundle);
    }

    @Override
    public void sent(Instant sent, QuicPacket packet) {
        markSent(List.of(packet));
    }

    @Override
    public void sent(Instant sent, List<QuicPacket> packets) {
        markSent(packets);
    }

    private void markSentArgument(Object packets) {
        if (packets instanceof QuicPacket packet) {
            markSent(List.of(packet));
        } else if (packets instanceof List<?> list) {
            markSent(list.stream().filter(QuicPacket.class::isInstance).map(QuicPacket.class::cast).toList());
        }
    }

    private void markSent(List<QuicPacket> packets) {
        if (pending.isEmpty()) {
            return;
        }
        long sentAtNanos = System.nanoTime();
        packets.stream()
                .flatMap(packet -> packet.getFrames().stream())
                .filter(AtomicStreamFrameBundle.class::isInstance)
                .map(AtomicStreamFrameBundle.class::cast)
                .filter(pending::remove)
                .forEach(bundle -> bundle.markSent(sentAtNanos));
    }
}
