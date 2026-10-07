package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import java.net.Socket
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter

/**
 * Tests for DNS rebinding protection via Host header validation.
 */
class HostValidationTest {

    private lateinit var server: TurboMcpServer
    private val testPort = 31340  // Use different port to avoid conflicts

    @BeforeEach
    fun setup() {
        server = TurboMcpServer(port = testPort)
        server.start()
        Thread.sleep(500)  // Give server time to start
    }

    @AfterEach
    fun teardown() {
        server.stop()
    }

    private fun sendRequestWithHost(host: String): Int {
        Socket("127.0.0.1", testPort).use { socket ->
            val writer = PrintWriter(socket.getOutputStream(), true)
            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))

            // Send minimal HTTP request
            writer.print("GET / HTTP/1.1\r\n")
            writer.print("Host: $host\r\n")
            writer.print("Content-Type: application/json\r\n")
            writer.print("Connection: close\r\n")
            writer.print("\r\n")
            writer.flush()

            // Read status line
            val statusLine = reader.readLine() ?: return -1
            // Parse "HTTP/1.1 403 Forbidden" -> 403
            val parts = statusLine.split(" ")
            return if (parts.size >= 2) parts[1].toIntOrNull() ?: -1 else -1
        }
    }

    @Test
    fun `blocks requests with Host localhost and no port`() {
        val statusCode = sendRequestWithHost("localhost")
        assertEquals(403, statusCode, "Host: localhost without the server port should be blocked")
    }

    @Test
    fun `blocks requests with Host 127_0_0_1 and no port`() {
        val statusCode = sendRequestWithHost("127.0.0.1")
        assertEquals(403, statusCode, "Host: 127.0.0.1 without the server port should be blocked")
    }

    @Test
    fun `allows requests with Host localhost and port`() {
        val statusCode = sendRequestWithHost("localhost:$testPort")
        assertNotEquals(403, statusCode, "Host: localhost:port should be allowed")
    }

    @Test
    fun `allows requests with Host 127_0_0_1 and port`() {
        val statusCode = sendRequestWithHost("127.0.0.1:$testPort")
        assertNotEquals(403, statusCode, "Host: 127.0.0.1:port should be allowed")
    }

    @Test
    fun `blocks requests with external Host header`() {
        val statusCode = sendRequestWithHost("evil.com")
        assertEquals(403, statusCode, "Host: evil.com should be blocked")
    }

    @Test
    fun `blocks requests with external Host header and port`() {
        val statusCode = sendRequestWithHost("evil.com:31338")
        assertEquals(403, statusCode, "Host: evil.com:port should be blocked")
    }

    @Test
    fun `blocks requests with IP address other than localhost`() {
        val statusCode = sendRequestWithHost("192.168.1.1")
        assertEquals(403, statusCode, "Host: 192.168.1.1 should be blocked")
    }

    @Test
    fun `blocks DNS rebinding style attack with subdomain`() {
        val statusCode = sendRequestWithHost("localhost.evil.com")
        assertEquals(403, statusCode, "Host: localhost.evil.com should be blocked")
    }

    @Test
    fun `Host header check is case insensitive`() {
        val statusCode = sendRequestWithHost("LOCALHOST:$testPort")
        assertNotEquals(403, statusCode, "Host: LOCALHOST should be allowed (case insensitive)")
    }
}
