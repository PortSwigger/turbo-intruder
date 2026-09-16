package hp3.h3.qpack;

import hp3.h3.Http3Exception;

/** A QPACK decoding failure. Carries {@code QPACK_DECOMPRESSION_FAILED} by default. */
public class QpackException extends Http3Exception {

    public QpackException(String message) {
        super(QPACK_DECOMPRESSION_FAILED, message);
    }

    public QpackException(long errorCode, String message) {
        super(errorCode, message);
    }
}
