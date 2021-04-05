import com.twitter.hpack.Encoder
import java.io.ByteArrayOutputStream

class HeaderEncoder {

    val encoder = Encoder(65536) // 65536 4096
    val headers = ByteArrayOutputStream()

    fun addHeader(name: String, value: String) {
        //Connection.debug("$name=$value")
        encoder.encodeHeader(headers, name.toByteArray(), value.toByteArray(), false)
    }
}