package hp3.quic;

import java.io.IOException;
import java.util.function.Consumer;

/**
 * The QUIC connection HTTP/3 runs over, reduced to what HTTP/3 actually needs.
 *
 * <p>This interface is the seam that keeps the choice of QUIC library replaceable. Kwik implements
 * it today; reaching below the transport for phase 2 work — malformed packets, illegal transport
 * parameters, flow-control abuse — means changing one implementation class rather than the codec.
 * It is also what the in-memory test double implements.
 */
public interface QuicTransport extends AutoCloseable {

    /** Opens a client-initiated bidirectional stream, used for requests. */
    QuicStream openBidirectionalStream() throws IOException;

    /** Opens a client-initiated unidirectional stream, used for control and QPACK. */
    QuicStream openUnidirectionalStream() throws IOException;

    /**
     * Registers a handler for streams the peer opens. HTTP/3 servers open unidirectional streams
     * for their own control and QPACK channels.
     */
    void onPeerStream(Consumer<QuicStream> handler);

    boolean isConnected();

    /**
     * Bytes this connection has sent and the peer has not acknowledged, or {@code null} from a
     * transport that cannot tell.
     *
     * <p>Read by a gate that has staged its batch and needs to know whether the batch has actually
     * arrived before it fires the release after it. Zero means it has; null means this transport
     * cannot say, which is not the same answer and must not be read as zero.
     */
    default Long unackedBytes() {
        return null;
    }

    /** Closes the connection with an application error code, e.g. an {@code H3_*} value. */
    void close(long errorCode, String reason);

    @Override
    void close();
}
