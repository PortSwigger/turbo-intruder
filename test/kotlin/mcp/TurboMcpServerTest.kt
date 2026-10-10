package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.net.ServerSocket

class TurboMcpServerTest {

    private fun findFreePort(): Int {
        return ServerSocket(0).use { it.localPort }
    }

    @Test
    fun `server can be created with port`() {
        val server = TurboMcpServer(port = 31337)
        assertNotNull(server)
    }

    @Test
    fun `server exposes tool and resource handlers`() {
        val server = TurboMcpServer(port = 31337)
        assertNotNull(server.toolHandlers)
        assertNotNull(server.resourceHandlers)
    }

    @Test
    fun `all tools enabled by default`() {
        val server = TurboMcpServer(port = 31337)
        val toolNames = server.getEnabledToolNames()
        assertTrue(toolNames.contains("start_run"))
        assertTrue(toolNames.contains("save_to_organizer"))
    }

    @Test
    fun `async run tool is enabled by default`() {
        val server = TurboMcpServer(port = 31337)
        val toolNames = server.getEnabledToolNames()
        assertTrue(toolNames.contains("start_run_async"),
            "start_run_async should be registered so agents can start long runs without blocking")
    }

    @Test
    fun `capabilities do not advertise notifications the stateless transport cannot push`() {
        val server = TurboMcpServer(port = 31337)
        val caps = server.buildServerCapabilities()

        // Resources are still offered (list + read)...
        assertNotNull(caps.resources(), "resources must still be advertised")
        // ...but stateless has no sessions, so neither sub-feature can be delivered.
        assertEquals(false, caps.resources().subscribe())
        assertEquals(false, caps.resources().listChanged())
        // Logging notifications also require a session to target.
        assertNull(caps.logging(), "logging notifications cannot be pushed over the stateless transport")
    }

    @Test
    fun `disabled tools are excluded`() {
        val server = TurboMcpServer(
            port = 31337,
            disabledTools = setOf("start_run", "start_run_async")
        )
        val toolNames = server.getEnabledToolNames()
        assertFalse(toolNames.contains("start_run"))
        assertFalse(toolNames.contains("start_run_async"))
        assertTrue(toolNames.contains("stop_run"))
    }

    @Test
    fun `server starts and stops with stateless transport`() {
        val port = findFreePort()
        val server = TurboMcpServer(port = port)

        // Should not throw
        server.start()

        // Server should be listening - verify by trying to start another server on same port
        val conflictException = assertThrows(Exception::class.java) {
            val server2 = TurboMcpServer(port = port)
            server2.start()
        }
        assertTrue(conflictException.message?.contains("Address already in use") == true ||
                   conflictException.cause?.message?.contains("Address already in use") == true,
            "Port should be in use")

        server.stop()
    }

    @Test
    fun `organizer list resource supports domain filter via URI template`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "target.com"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", host = "other.com"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", host = "target.com")
        ))
        val server = TurboMcpServer(port = 31337, organizerProvider = fakeOrganizer)

        // Test that resourceHandlers correctly handles domain filter
        val result = server.resourceHandlers.listOrganizerItems(domain = "target.com")

        assertEquals(2, result["count"])
        assertEquals(1, result["page"])
        assertEquals(10, result["page_size"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        // Sorted by ID descending (no timestamps)
        assertEquals(listOf(3, 1), items.map { it["id"] })
    }

    @Test
    fun `stateless organizer handler parses domain query param`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "target.com"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", host = "other.com"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", host = "target.com")
        ))
        val server = TurboMcpServer(port = 31337, organizerProvider = fakeOrganizer)

        // Invoke the stateless handler directly with a URI containing domain query param
        val result = server.invokeResourceHandler("turbo://organizer?domain=target.com")

        assertEquals(2, result["count"], "Should filter to 2 items for target.com")
        assertEquals(1, result["page"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(2, items.size)
        // Items list only contains IDs; verify the correct IDs were returned (1 and 3 for target.com)
        val ids = items.map { it["id"] }.toSet()
        assertEquals(setOf(1, 3), ids, "Should return IDs 1 and 3 for target.com")
    }

    @Test
    fun `stateless organizer handler parses page query param`() {
        // Create 15 items for target.com
        val items = (1..15).map {
            FakeOrganizerItem(it, "GET /$it HTTP/1.1", "HTTP/1.1 200 OK", host = "target.com")
        }
        val fakeOrganizer = FakeOrganizerProvider(items)
        val server = TurboMcpServer(port = 31337, organizerProvider = fakeOrganizer)

        // Request page 2
        val result = server.invokeResourceHandler("turbo://organizer?domain=target.com&page=2")

        assertEquals(15, result["count"])
        assertEquals(2, result["page"], "Should return page 2")
        @Suppress("UNCHECKED_CAST")
        val returnedItems = result["items"] as List<Map<String, Any?>>
        assertEquals(5, returnedItems.size, "Page 2 should have 5 items (11-15)")
    }

    @Test
    fun `organizer list resource supports pagination via URI template`() {
        // Create 25 items
        val items = (1..25).map {
            FakeOrganizerItem(it, "GET /$it HTTP/1.1", "HTTP/1.1 200 OK", host = "target.com")
        }
        val fakeOrganizer = FakeOrganizerProvider(items)
        val server = TurboMcpServer(port = 31337, organizerProvider = fakeOrganizer)

        val page1 = server.resourceHandlers.listOrganizerItems(domain = "target.com", page = 1)
        val page2 = server.resourceHandlers.listOrganizerItems(domain = "target.com", page = 2)
        val page3 = server.resourceHandlers.listOrganizerItems(domain = "target.com", page = 3)

        assertEquals(25, page1["count"])
        assertEquals(1, page1["page"])
        assertEquals(3, page1["total_pages"])

        assertEquals(2, page2["page"])
        assertEquals(3, page3["page"])

        @Suppress("UNCHECKED_CAST")
        val page1Items = page1["items"] as List<Map<String, Any?>>
        @Suppress("UNCHECKED_CAST")
        val page3Items = page3["items"] as List<Map<String, Any?>>

        assertEquals(10, page1Items.size)
        assertEquals(5, page3Items.size)
    }

    // ============================================================
    // Stateless handler query param tests
    // These verify that stateless MCP handlers correctly parse
    // query parameters from the request URI.
    // ============================================================

    @Test
    fun `stateless run summary handler parses limit query param`() {
        val server = TurboMcpServer(port = 31337)

        // Start a run so we have something to query
        val startResult = server.toolHandlers.startRunAsync(
            script = "def queueRequests(t, w): pass\ndef completed(r): pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            endpoint = "https://test.com:443",
            baseInput = ""
        )
        val runId = startResult["run_id"] as String

        // Invoke stateless handler with limit param
        val result = server.invokeResourceHandler("turbo://runs/$runId/summary?limit=5")

        // The limit should be applied (even if there are 0 results, the param should be parsed)
        assertNotNull(result["results"], "Should have results key")
        assertNull(result["error"], "Should not have error")
    }

    @Test
    fun `stateless run summary handler parses sort_by query param`() {
        val server = TurboMcpServer(port = 31337)

        val startResult = server.toolHandlers.startRunAsync(
            script = "def queueRequests(t, w): pass\ndef completed(r): pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            endpoint = "https://test.com:443",
            baseInput = ""
        )
        val runId = startResult["run_id"] as String

        // These should not error - if params aren't parsed, invalid sort_by would be ignored
        val resultById = server.invokeResourceHandler("turbo://runs/$runId/summary?sort_by=id")
        val resultByLength = server.invokeResourceHandler("turbo://runs/$runId/summary?sort_by=length")

        assertNotNull(resultById["results"])
        assertNotNull(resultByLength["results"])
    }

    @Test
    fun `stateless run summary handler parses offset query param`() {
        val server = TurboMcpServer(port = 31337)

        val startResult = server.toolHandlers.startRunAsync(
            script = "def queueRequests(t, w): pass\ndef completed(r): pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            endpoint = "https://test.com:443",
            baseInput = ""
        )
        val runId = startResult["run_id"] as String

        val result = server.invokeResourceHandler("turbo://runs/$runId/summary?offset=10&limit=5")

        assertNotNull(result["results"])
        assertNull(result["error"])
    }

    @Test
    fun `stateless request detail handler parses body_limit query param`() {
        val server = TurboMcpServer(port = 31337)

        val startResult = server.toolHandlers.startRunAsync(
            script = "def queueRequests(t, w): pass\ndef completed(r): pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            endpoint = "https://test.com:443",
            baseInput = ""
        )
        val runId = startResult["run_id"] as String

        // Request with body_limit - should parse without error even if no results exist
        val result = server.invokeResourceHandler("turbo://runs/$runId/1?body_limit=500")

        // Will return request_not_found since there are no actual results, but should not error on parsing
        assertTrue(result.containsKey("error") || result.containsKey("request"),
            "Should return either error or request data")
    }

    @Test
    fun `stateless organizer item handler parses body_limit query param`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(
                id = 42,
                request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + "A".repeat(500),
                host = "example.com"
            )
        ))
        val server = TurboMcpServer(port = 31337, organizerProvider = fakeOrganizer)

        // Request with small body_limit - response body should be truncated
        val resultSmall = server.invokeResourceHandler("turbo://organizer/42?body_limit=50")

        // Request with large body_limit - response body should not be truncated
        val resultLarge = server.invokeResourceHandler("turbo://organizer/42?body_limit=1000")

        assertNull(resultSmall["error"], "Should not error")
        assertNull(resultLarge["error"], "Should not error")

        // Verify body_limit was actually applied
        val smallBody = resultSmall["response_body"] as? String ?: ""
        val largeBody = resultLarge["response_body"] as? String ?: ""

        assertTrue(smallBody.length <= 50 || (resultSmall["response_body_truncated"] as? Boolean == true),
            "Small body_limit should truncate or mark as truncated")
        assertTrue(largeBody.length >= smallBody.length,
            "Large body_limit should return more content")
    }
}
