package hp3.quic;

import java.io.IOException;
import java.util.List;

public interface SdaCapableQuicTransport extends QuicTransport {
    /** A release with everything but the send already done. */
    @FunctionalInterface
    interface PreparedDatagram {
        /** Sends the release and returns a monotonic timestamp taken after its UDP send. */
        long send() throws IOException;
    }

    void sendSingleDatagram(
            List<StreamFragment> fragments,
            int maximumDatagramSize,
            int retransmissions) throws IOException;

    /**
     * Works out everything {@link #sendSingleDatagram} can work out in advance, and hands back
     * what is left.
     *
     * <p>Whatever a release does before its send is time the gate spends holding a batch the
     * target already has, and the window being aimed at is orders of magnitude finer than that
     * work. So building the frames, sizing them against the path and deciding they fit all happen
     * here, before the gate is opened, rather than in the instant it is opened in.
     *
     * <p>Preparing also fails here rather than at the instant. A batch that only discovers it is
     * too large once the release is fired has already been staged against the target.
     *
     * <p>The default simply defers the whole thing, for a transport with nothing to hoist.
     */
    default PreparedDatagram prepareSingleDatagram(
            List<StreamFragment> fragments,
            int maximumDatagramSize,
            int retransmissions) {
        return () -> {
            sendSingleDatagram(fragments, maximumDatagramSize, retransmissions);
            return System.nanoTime();
        };
    }

    /**
     * The most stream-frame bytes {@link #sendSingleDatagram} will carry, given a caller's own
     * ceiling and whatever this connection's path allows.
     *
     * <p>Asked before a batch is staged rather than discovered when the release is refused. A gate
     * races as tightly as the number of requests it releases together, so the size that fits is
     * the size worth building — and a batch that only finds out at release time has already put
     * every one of its requests on the wire for a race that will never be sent.
     *
     * <p>{@link Integer#MAX_VALUE} from a transport that cannot say, which bounds nothing.
     */
    default int singleDatagramFrameBudget(int maximumDatagramSize) {
        return Integer.MAX_VALUE;
    }
}
