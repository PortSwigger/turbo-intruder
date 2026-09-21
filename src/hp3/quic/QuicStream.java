package hp3.quic;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * A single QUIC stream, exposed as raw bytes in both directions.
 *
 * <p>Deliberately no HTTP/3 knowledge. Everything above this reads and writes frames itself, which
 * is what makes it possible to put arbitrary bytes on a stream.
 */
public interface QuicStream {

    long id();

    InputStream input();

    OutputStream output();

    boolean isUnidirectional();

    /** Closes our sending half, which is how HTTP/3 signals the end of a message. */
    void finishSending() throws java.io.IOException;

    /** Abruptly terminates the sending half with an application error code (RESET_STREAM). */
    void resetStream(long errorCode);

    /** Asks the peer to stop sending, with an application error code (STOP_SENDING). */
    void stopSending(long errorCode);
}
