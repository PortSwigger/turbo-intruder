package http3

import hp3.h3.Http3FrameType
import hp3.h3.Http3FrameWriter
import hp3.h3.Http3Request
import hp3.h3.qpack.QpackEncoder

data class SdaStagingPlan(
    val stagedBytes: ByteArray,
    val releaseOffset: Long,
    val releaseBytes: ByteArray,
    val fin: Boolean = true,
)

object SdaStagingPlanner {
    /**
     * Splits a request into the bytes staged ahead of the gate and the bytes released in the
     * single datagram.
     *
     * The withheld bytes have to be ones the server's parser actually needs, otherwise it can
     * answer from the staged prefix alone and the gate stops gating. For a request with a body
     * that means the tail of the DATA frame; for a bodyless request it means the tail of the
     * HEADERS frame, because a complete HEADERS frame is a complete request and servers do not
     * wait for the FIN before answering one. finalBytes = 0 withholds the FIN alone, which only
     * gates a server that does wait for it; the engine does not use it, and no script may ask for
     * it. See [SdaOptions.finalBytes].
     */
    @JvmStatic
    fun plan(request: Http3Request, finalBytes: Int): SdaStagingPlan {
        require(finalBytes >= 0) { "finalBytes must be non-negative" }
        val body = request.body()

        val headers = Http3FrameWriter.toBytes(
            Http3FrameType.HEADERS,
            QpackEncoder.encodeFieldSection(request.fields()),
        )
        if (body.isEmpty()) {
            require(finalBytes <= headers.size) {
                "finalBytes ($finalBytes) exceeds HEADERS frame length (${headers.size})"
            }
            val stagedLength = headers.size - finalBytes
            return SdaStagingPlan(
                headers.copyOfRange(0, stagedLength),
                stagedLength.toLong(),
                headers.copyOfRange(stagedLength, headers.size),
            )
        }

        require(finalBytes <= body.size) {
            "finalBytes ($finalBytes) exceeds body length (${body.size})"
        }
        val dataFrame = Http3FrameWriter.toBytes(Http3FrameType.DATA, body)
        val dataHeaderLength = dataFrame.size - body.size
        val stagedBodyLength = body.size - finalBytes
        val stagedDataLength = dataHeaderLength + stagedBodyLength
        val staged = headers + dataFrame.copyOfRange(0, stagedDataLength)
        val release = body.copyOfRange(stagedBodyLength, body.size)
        return SdaStagingPlan(staged, staged.size.toLong(), release)
    }
}
