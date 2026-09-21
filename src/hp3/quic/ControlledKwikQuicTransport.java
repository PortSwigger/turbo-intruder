package hp3.quic;

import tech.kwik.core.DatagramSocketFactory;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.cc.CongestionController;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.log.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public final class ControlledKwikQuicTransport implements SdaCapableQuicTransport {
    private static final long RELEASE_SEND_TIMEOUT_MILLIS = 5_000;

    interface AtomicBundleSender {
        int maxPacketSize();

        int maxShortHeaderPacketOverhead();

        void submit(AtomicStreamFrameBundle bundle, Consumer<QuicFrame> lostCallback)
                throws IOException;

        default void cancelConfirmation(AtomicStreamFrameBundle bundle) {
        }
    }

    private final QuicClientConnection connection;
    private final AtomicBundleSender bundleSender;

    /** Kwik's own count of bytes sent and not yet acknowledged, or null if it could not be found. */
    private final CongestionController congestionController;

    private ControlledKwikQuicTransport(
            QuicClientConnection connection,
            AtomicBundleSender bundleSender) {
        this.connection = connection;
        this.bundleSender = bundleSender;
        this.congestionController = findCongestionController(connection);
    }

    /**
     * Reaches Kwik's congestion controller, which counts the bytes in flight.
     *
     * <p>By reflection because the only route to it is {@code QuicConnectionImpl.getSender()},
     * which is protected. The two hops past it are public API on a public class and a public
     * interface, so this is one accessibility check rather than a walk through internals — but it
     * is still coupled to a method name in a dependency, so a failure to find it is not fatal.
     * Without it a gate falls back to the fixed wait it always used to take.
     *
     * <p>The alternative was Statistics.dataBytesSent(), which getStats() hands over publicly.
     * Measured, that is already at the batch's full staged total the instant the last stage()
     * returns — Kwik counts a byte when it packs it, not when the peer has it — so it cannot say
     * whether anything arrived. Bytes in flight can: on a 100-request batch it held at the staged
     * value for 17ms and then dropped to zero.
     */
    private static CongestionController findCongestionController(QuicClientConnection connection) {
        if (connection == null) {
            return null;
        }
        try {
            Method getSender = QuicConnectionImpl.class.getDeclaredMethod("getSender");
            getSender.setAccessible(true);
            SenderImpl sender = (SenderImpl) getSender.invoke(connection);
            return sender == null ? null : sender.getCongestionController();
        } catch (ReflectiveOperationException | RuntimeException failure) {
            return null;
        }
    }

    public static ControlledKwikQuicTransport connect(String host, int port, QuicConfig config)
            throws IOException {
        return connect(host, port, config, QuicSockets.highThroughput(), null);
    }

    static ControlledKwikQuicTransport connectForTest(
            String host,
            int port,
            QuicConfig config,
            DatagramSocketFactory socketFactory,
            Logger logger) throws IOException {
        return connect(host, port, config, socketFactory, logger);
    }

    private static ControlledKwikQuicTransport connect(
            String host,
            int port,
            QuicConfig config,
            DatagramSocketFactory socketFactory,
            Logger logger) throws IOException {
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder()
                .host(host)
                .port(port)
                .applicationProtocol("h3")
                .connectTimeout(config.handshakeTimeout())
                .maxIdleTimeout(config.idleTimeout())
                .maxOpenPeerInitiatedUnidirectionalStreams(16);
        ReleaseTrackingLogger releaseTracker = new ReleaseTrackingLogger();

        if (socketFactory != null) {
            builder.socketFactory(socketFactory);
        }
        builder.logger(releaseTracker.wrap(logger));

        if (!config.verifyCertificates()) {
            builder.noServerCertificateCheck();
        }

        QuicClientConnection connection = builder.build();
        connection.connect();
        QuicConnectionImpl implementation = (QuicConnectionImpl) connection;
        return new ControlledKwikQuicTransport(
                connection,
                new AtomicBundleSender() {
                    @Override
                    public int maxPacketSize() {
                        return implementation.getMaxPacketSize();
                    }

                    @Override
                    public int maxShortHeaderPacketOverhead() {
                        return implementation.getMaxShortHeaderPacketOverhead();
                    }

                    @Override
                    public void submit(
                            AtomicStreamFrameBundle bundle,
                            Consumer<QuicFrame> lostCallback) {
                        releaseTracker.expect(bundle);
                        try {
                            implementation.send(bundle, lostCallback, true);
                        } catch (RuntimeException | Error failure) {
                            releaseTracker.cancel(bundle);
                            throw failure;
                        }
                    }

                    @Override
                    public void cancelConfirmation(AtomicStreamFrameBundle bundle) {
                        releaseTracker.cancel(bundle);
                    }
                });
    }

    static ControlledKwikQuicTransport forTest(AtomicBundleSender bundleSender) {
        return new ControlledKwikQuicTransport(null, bundleSender);
    }

    /**
     * The largest packet the active path will carry, which is the ceiling any single-datagram
     * claim has to fit inside. Exposed so a test can assert against the connection's own limit
     * rather than a number copied from it.
     */
    public int maxPacketSize() {
        return bundleSender.maxPacketSize();
    }

    @Override
    public int singleDatagramFrameBudget(int maximumDatagramSize) {
        if (maximumDatagramSize < 1) {
            throw new IllegalArgumentException("maximumDatagramSize must be positive");
        }
        return Math.min(maximumDatagramSize, bundleSender.maxPacketSize())
                - bundleSender.maxShortHeaderPacketOverhead();
    }

    @Override
    public void sendSingleDatagram(
            List<StreamFragment> fragments,
            int maximumDatagramSize,
            int retransmissions) throws IOException {
        prepareSingleDatagram(fragments, maximumDatagramSize, retransmissions).send();
    }

    @Override
    public PreparedDatagram prepareSingleDatagram(
            List<StreamFragment> fragments,
            int maximumDatagramSize,
            int retransmissions) {
        if (retransmissions < 0) {
            throw new IllegalArgumentException("retransmissions must be non-negative");
        }

        AtomicStreamFrameBundle bundle = AtomicStreamFrameBundle.from(fragments);
        // The same number a batch reserved against while it was being staged, so a batch that was
        // allowed to grow to the edge is not refused at the edge.
        int frameBudget = singleDatagramFrameBudget(maximumDatagramSize);
        int packetLimit = Math.min(maximumDatagramSize, bundleSender.maxPacketSize());
        int overhead = bundleSender.maxShortHeaderPacketOverhead();
        if (bundle.getFrameLength() > frameBudget) {
            throw new IllegalArgumentException(
                    "SDA release requires " + (bundle.getFrameLength() + overhead)
                            + " bytes but limit is " + packetLimit
                            + ". This batch is too large for one datagram. Note that a batch costs"
                            + " more on every gate after the first on the same connection: each"
                            + " request carries its stream ID as a varint, and a varint grows at"
                            + " 64 and again at 16384: the first gate's IDs cost a byte each, the"
                            + " next twenty or so cost two, and past stream 16384 they cost four."
                            + " So a batch that fitted a moment ago can stop fitting. Use"
                            + " gateMode='qpack' to release on the QPACK encoder stream instead,"
                            + " which is bounded by the server's SETTINGS_QPACK_BLOCKED_STREAMS"
                            + " rather than by a datagram and needs the server to advertise that"
                            + " and QPACK_MAX_TABLE_CAPACITY, or queue a smaller batch.");
        }

        AtomicInteger remainingRetransmissions = new AtomicInteger(retransmissions);
        Consumer<QuicFrame> lostCallback = new Consumer<>() {
            @Override
            public void accept(QuicFrame ignored) {
                int previous = remainingRetransmissions.getAndUpdate(value -> value > 0 ? value - 1 : 0);
                if (previous > 0) {
                    try {
                        bundleSender.submit(bundle, this);
                    } catch (IOException exception) {
                        throw new UncheckedIOException(exception);
                    }
                }
            }
        };
        // All that is left for the instant the gate opens.
        return () -> {
            bundleSender.submit(bundle, lostCallback);
            try {
                return bundle.awaitSent(RELEASE_SEND_TIMEOUT_MILLIS);
            } catch (IOException failure) {
                bundleSender.cancelConfirmation(bundle);
                throw failure;
            }
        };
    }

    @Override
    public QuicStream openBidirectionalStream() throws IOException {
        return new KwikStream(requireConnection().createStream(true));
    }

    @Override
    public QuicStream openUnidirectionalStream() throws IOException {
        return new KwikStream(requireConnection().createStream(false));
    }

    @Override
    public void onPeerStream(Consumer<QuicStream> handler) {
        requireConnection().setPeerInitiatedStreamCallback(
                stream -> handler.accept(new KwikStream(stream)));
    }

    @Override
    public Long unackedBytes() {
        return congestionController == null ? null : congestionController.getBytesInFlight();
    }

    @Override
    public boolean isConnected() {
        return connection != null && connection.isConnected();
    }

    @Override
    public void close(long errorCode, String reason) {
        requireConnection().close(errorCode, reason);
    }

    @Override
    public void close() {
        if (connection != null) {
            connection.close();
        }
    }

    private QuicClientConnection requireConnection() {
        if (connection == null) {
            throw new IllegalStateException("test transport has no QUIC connection");
        }
        return connection;
    }

    private record KwikStream(tech.kwik.core.QuicStream delegate) implements QuicStream {
        @Override
        public long id() {
            return delegate.getStreamId();
        }

        @Override
        public InputStream input() {
            return delegate.getInputStream();
        }

        @Override
        public OutputStream output() {
            return delegate.getOutputStream();
        }

        @Override
        public boolean isUnidirectional() {
            return delegate.isUnidirectional();
        }

        @Override
        public void finishSending() throws IOException {
            delegate.getOutputStream().close();
        }

        @Override
        public void resetStream(long errorCode) {
            delegate.resetStream(errorCode);
        }

        @Override
        public void stopSending(long errorCode) {
            delegate.abortReading(errorCode);
        }
    }
}
