package burp
import java.io.ByteArrayInputStream
import java.lang.StringBuilder
import com.twitter.hpack.HeaderListener



open class Frame(val type: Byte, val flags: Byte, val streamID: Int, val payload: ByteArray) {
    var die: Boolean = false

    fun asBytes(): ByteArray {
        val length = HTTP2Utils.intToThreeBytes(payload.size)
//        Connection.debug("Real size: "+payload.size)
//        Connection.debug("Reversed size: "+threeByteInt(length))
//        Connection.debug("Reversed raw size: "+length.asList())
        //checkUnsigned(intToFourBytes(streamID))
        return length + type + flags + HTTP2Utils.intToFourBytes(streamID) + payload
    }

    fun checkUnsigned(bytes: ByteArray) {
        for (byte in bytes) {
            if (byte.toString() != byte.toUByte().toString()) {
                throw Exception("sign problems!: $byte | ${byte.toUByte()}")
            }
        }
    }
}

class HeaderFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray, stream: Stream): Frame(type, flags, streamID, payload) {

    val headerString: String

    init {
        //Connection.debug("Parsing headers")
        if ((flags.toInt() and 1) == 1) {
            Connection.debug("Frame has set END_STREAM")
            die = true
        }

        val `in` = ByteArrayInputStream(payload)
        val headers = StringBuilder()
        val listener = HeaderListener { name, value, sensitive ->
            headers.append(String(name))
            headers.append(": ")
            headers.append(String(value))
            headers.append("\r\n")
            //Connection.debug("Got header "+String(name) + "="+String(value))
        }
        // decode header list from header block
        //val decoder = Decoder(4096, 4096)
        val decoder = stream.connection.decoder
        decoder.decode(`in`, listener)
        decoder.endHeaderBlock()
        headerString = headers.toString()
    }
}

class DataFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {
    val body: String


    init {
        //Connection.debug("Parsing data frame")
        // fixme don't use exact matching on a bloody flag!!
        if ((flags.toInt() and 1) == 1) {
            Connection.debug("Frame has set END_STREAM")
            die = true
        }

        body = String(payload, Charsets.ISO_8859_1)

    }
}

class SettingsFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {

    var maxConcurrentStreams = 0

    init {
        Connection.debug("Parsing settings...")
        // fixme is their double-settings response blowing things up

        if (payload.size == 0) {
            Connection.debug("Just an ack")
        } else {

            var head = 0
            while (head < payload.size) {
                val key = HTTP2Utils.twoByteInt(payload.slice(head..head + 1).toByteArray())
                val value = HTTP2Utils.fourByteInt(payload.slice(head + 2..head + 5).toByteArray())
                when (key) {
                    1 -> Connection.debug("HEADER_TABLE_SIZE = $value")
                    2 -> Connection.debug("ENABLE_PUSH = $value")
                    3 -> {
                        // todo this is actually maxConcurrentStreams
                        Connection.debug("MAX_CONCURRENT_STREAMS = $value")
                        maxConcurrentStreams = value

                    }
                    4 -> Connection.debug("INITIAL_WINDOW_SIZE = $value")
                    5 -> Connection.debug("MAX_FRAME_SIZE = $value")
                    6 -> Connection.debug("Max headers = $value")
                    else -> Connection.debug("Unrecognised setting $key=$value")
                }

                head += 6
            }
        }
    }
}

class PingFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {
    val data: List<Byte>

    init {
        Connection.debug("Parsing PING")
        Connection.debug("Data: "+payload.asList())
        data = payload.asList()
    }
}

class WindowFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {


    init {
        Connection.debug("Parsing WINDOW_UPDATE")
        Connection.debug("Increment window size by "+payload.asList())
    }
}

class RstStreamFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {
    init {
        //Utils.out("Parsing RST_STREAM")
    }
}

class GoAwayFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {

    init {
        Utils.out("Parsing GOAWAY")
        Utils.out("Last stream ID: "+payload.sliceArray(0..3).asList())
        Utils.out("Error code: "+payload.sliceArray(4..7).asList())
        val error = payload[7].toInt()
        val error_message = when (error) {
            0 -> "NO_ERROR"
            1 -> "PROTOCOL_ERROR"
            2 -> "INTERNAL_ERROR"
            3 -> "FLOW_CONTROL_ERROR"
            4 -> "SETTINGS_TIMEOUT"
            5 -> "STREAM_CLOSED"
            6 -> "FRAME_SIZE_ERROR"
            else -> "unknown error code"
        }
        Connection.debug(error_message)
        if (payload.size > 8) {
            Connection.debug("Debug data: " + payload.sliceArray(8..payload.size-1).asList())
        }
    }
}

class HTTP2Utils {
    companion object {
        fun twoByteInt(raw: ByteArray): Int {
            val b1 = raw[0].toInt()
            val b2 = raw[1].toInt()
            return (b1 and 0xFF shl 8) or (b2 and 0xFF)
        }


        fun threeByteInt(raw: ByteArray): Int {
            val b1 = raw[0].toInt()
            val b2 = raw[1].toInt()
            val b3 = raw[2].toInt()
            return (b1 and 0xFF shl 16) or (b2 and 0xFF shl 8) or (b3 and 0xFF)
        }

        fun fourByteInt(raw: ByteArray): Int {
            val b1 = raw[0].toInt()
            val b2 = raw[1].toInt()
            val b3 = raw[2].toInt()
            val b4 = raw[3].toInt()
            return (b1 and 0xFF shl 24) or (b2 and 0xFF shl 16) or (b3 and 0xFF shl 8) or (b4 and 0xFF)
        }

        fun intToThreeBytes(num: Int): ByteArray {
            val s1 = num
            val s2 = num shr 8
            val s3 = num shr 16
            return byteArrayOf(s3.toByte(), s2.toByte(), s1.toByte())
        }

        fun intToFourBytes(num: Int): ByteArray {
            val s1 = num
            val s2 = num shr 8
            val s3 = num shr 16
            val s4 = num shr 24
            return byteArrayOf(s4.toByte(), s3.toByte(), s2.toByte(), s1.toByte())
        }
    }
}

