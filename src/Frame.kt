import com.twitter.hpack.Decoder
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
        Connection.debug("Parsing headers")

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
        Connection.debug("Parsing data frame")
        body = String(payload)
        if (flags.toInt() == 1) {
            Connection.debug("Data frame has set END_STREAM")
            die = true
        }
    }
}

class SettingsFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {

    var maxStreams = 0

    init {
        Connection.debug("Parsing settings...")
        // fixme is their double-settings response blowing things up

        if (payload.size == 0) {
            Connection.debug("Just an ack")
        } else {

            var head = 0
            while (head < payload.size) {
                val key = payload.slice(head..head + 1)
                val value = payload.slice(head + 2..head + 5)
                if (HTTP2Utils.twoByteInt(key.toByteArray()) == 3) {
                    maxStreams = HTTP2Utils.fourByteInt(value.toByteArray())
                }
                Connection.debug(""+key + " = " + value)
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
        println("Parsing RST_STREAM")
    }
}

class GoAwayFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {

    init {
        println("Parsing GOAWAY")
        println("Last stream ID: "+payload.sliceArray(0..3).asList())
        println("Error code: "+payload.sliceArray(4..7).asList())
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

