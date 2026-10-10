package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*
import java.io.File

class McpResourceHandlersTest {

    private lateinit var manager: RunManager
    private lateinit var handlers: McpResourceHandlers

    @BeforeEach
    fun setup() {
        manager = RunManager()
        handlers = McpResourceHandlers(manager)
    }

    @Test
    fun `clampWait bounds the long-poll duration`() {
        assertEquals(0L, McpResourceHandlers.clampWait(0))
        assertEquals(0L, McpResourceHandlers.clampWait(-5))
        assertEquals(1000L, McpResourceHandlers.clampWait(1000))
        assertEquals(McpResourceHandlers.MAX_WAIT_MS, McpResourceHandlers.clampWait(Long.MAX_VALUE))
        assertEquals(McpResourceHandlers.MAX_WAIT_MS, McpResourceHandlers.clampWait(McpResourceHandlers.MAX_WAIT_MS + 1))
    }

    @Test
    fun `getRunStatus returns error for nonexistent run`() {
        val result = handlers.getRunStatus("nonexistent")

        assertEquals("not_found", result["error"])
    }

    @Test
    fun `getRunStatus returns evicted for evicted run`() {
        val manager = RunManager(maxCompletedRuns = 1)
        val handlers = McpResourceHandlers(manager)
        val run1 = manager.startRun()
        run1.handler.markScriptCompleted()
        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()
        // run1 is now over the cap; starting run3 triggers eviction
        manager.startRun()

        val result = handlers.getRunStatus(run1.id)

        assertEquals("evicted", result["error"])
    }

    @Test
    fun `getRunStatus returns run info with status field`() {
        val run = manager.startRun()

        val result = handlers.getRunStatus(run.id)

        assertNotNull(result["run_id"])
        assertEquals("running", result["status"])
        assertFalse(result.containsKey("running"), "Should not contain 'running' boolean")
        assertFalse(result.containsKey("finished"), "Should not contain 'finished' boolean")
        assertNotNull(result["result_count"])
        assertEquals(0, result["fails"])
    }

    @Test
    fun `getRunStatus includes summary when run is finished`() {
        val run = manager.startRun()

        // Add some results
        val req1 = burp.Request("GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req1.anomalyRank = 100

        val req2 = burp.Request("GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.response = "HTTP/1.1 404 Not Found\r\n\r\nnot found"
        req2.anomalyRank = 50

        run.store.add(req1)
        run.store.add(req2)

        // Mark run as finished (no engine created, so markScriptCompleted will trigger status=completed)
        run.handler.markScriptCompleted()

        val result = handlers.getRunStatus(run.id)

        assertEquals("completed", result["status"])
        // Should include summary when not running
        @Suppress("UNCHECKED_CAST")
        val summary = result["summary"] as? List<Map<String, Any?>>
        assertNotNull(summary, "Status should include summary when run is finished")
        assertEquals(2, summary!!.size)
        // Summary should be sorted by anomaly_rank descending
        assertEquals(100, summary[0]["anomaly_rank"])
        assertEquals(50, summary[1]["anomaly_rank"])
    }

    @Test
    fun `getRunStatus does not include summary when run is still running`() {
        val run = manager.startRun()

        // Add a result but don't mark as finished
        val req = burp.Request("GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.id = 1
        req.response = "HTTP/1.1 200 OK\r\n\r\nok"
        run.store.add(req)

        val result = handlers.getRunStatus(run.id)

        assertEquals("running", result["status"])
        assertNull(result["summary"], "Status should NOT include summary when run is still running")
    }

    @Test
    fun `getRunScript returns script for run`() {
        val run = manager.startRun()
        run.handler.code = "def queueRequests(target, wordlists):\n    pass"

        val result = handlers.getRunScript(run.id)

        assertEquals("def queueRequests(target, wordlists):\n    pass", result["script"])
    }

    @Test
    fun `getRunScript returns error for nonexistent run`() {
        val result = handlers.getRunScript("nonexistent")
        assertEquals("not_found", result["error"])
    }

    @Test
    fun `getResults returns empty list when no results`() {
        val run = manager.startRun()

        val result = handlers.getResults(run.id, "id", true, 100, 0)

        assertEquals(0, result["total_count"])
        assertTrue((result["results"] as List<*>).isEmpty())
    }

    @Test
    fun `getRequestDetail returns error for invalid request`() {
        val run = manager.startRun()

        val result = handlers.getRequestDetail(run.id, 999)

        assertEquals("request_not_found", result["error"])
    }

    @Test
    fun `getRequestDetail returns headers and truncated body by default`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
            "A".repeat(500)  // 500-char body
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 100)

        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", result["response_headers"])
        assertEquals("A".repeat(100), result["response_body"])
        assertEquals(200, result["status"])
    }

    @Test
    fun `getRequestDetail respects custom body_limit`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\n" + "B".repeat(1000)
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 250)

        assertEquals("B".repeat(250), result["response_body"])
    }

    @Test
    fun `getRequestDetail returns full body when shorter than limit`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nshort"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 100)

        assertEquals("short", result["response_body"])
    }

    @Test
    fun `getRequestDetail includes truncation metadata when truncated`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\n" + "A".repeat(500)
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 100)

        assertEquals(true, result["response_body_truncated"])
        assertEquals(500, result["response_body_total_length"])
    }

    @Test
    fun `getRequestDetail truncation metadata shows false when not truncated`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nshort"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 100)

        assertEquals(false, result["response_body_truncated"])
        assertEquals(5, result["response_body_total_length"])
    }

    @Test
    fun `getRequestDetail with exportFile writes response to file and returns path`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        val fullResponse = "HTTP/1.1 200 OK\r\n\r\n" + "X".repeat(1000)
        request.response = fullResponse
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, exportFile = true)

        assertNotNull(result["response_file"])
        val filePath = result["response_file"] as String
        val fileContent = java.io.File(filePath).readText()
        assertEquals(fullResponse, fileContent)
        // Should not include inline body when exporting to file
        assertNull(result["response_body"])
    }

    @Test
    fun `getRequestDetail with exportFile also exports request`() {
        val run = manager.startRun()
        val request = burp.Request("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nok"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, exportFile = true)

        assertNotNull(result["request_file"])
        val filePath = result["request_file"] as String
        val fileContent = java.io.File(filePath).readText()
        assertTrue(fileContent.contains("GET /test HTTP/1.1"))
    }

    @Test
    fun `getRequestDetail respects body_limit parameter`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\n" + "Z".repeat(500)
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 50)

        assertEquals("Z".repeat(50), result["response_body"])
    }

    @Test
    fun `getRequestDetail respects exportFile parameter`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\ndata"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, exportFile = true)

        assertNotNull(result["response_file"])
        assertNull(result["response_body"])
    }

    @Test
    fun `getResults includes anomaly_rank in results`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nok"
        request.anomalyRank = 42
        run.store.add(request)

        val result = handlers.getResults(run.id,"id", true, 100, 0)

        val results = result["results"] as List<Map<String, Any?>>
        assertEquals(1, results.size)
        assertEquals(42, results[0]["anomaly_rank"])
    }

    @Test
    fun `getResults includes ttfb and ttlb instead of time`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nok"
        request.ttfb = 500L
        request.ttlb = 1000L
        run.store.add(request)

        val result = handlers.getResults(run.id, "id", true, 100, 0)

        @Suppress("UNCHECKED_CAST")
        val results = result["results"] as List<Map<String, Any?>>
        assertEquals(500L, results[0]["ttfb"])
        assertEquals(1000L, results[0]["ttlb"])
        assertFalse(results[0].containsKey("time"))
    }

    @Test
    fun `getRequestDetail returns result by id for current run`() {
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 36
        request.response = "HTTP/1.1 200 OK\r\n\r\ntest body"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,36)

        assertEquals("test body", result["response_body"])
        assertEquals(200, result["status"])
    }

    @Test
    fun `getResults can sort by anomaly_rank descending`() {
        val run = manager.startRun()

        val req1 = burp.Request("GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req1.anomalyRank = 10

        val req2 = burp.Request("GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req2.anomalyRank = 100

        val req3 = burp.Request("GET /3 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req3.id = 3
        req3.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req3.anomalyRank = 50

        run.store.add(req1)
        run.store.add(req2)
        run.store.add(req3)

        // Call getResults with anomaly_rank sorting
        val result = handlers.getResults(run.id,"anomaly_rank", true, 100, 0)

        @Suppress("UNCHECKED_CAST")
        val results = result["results"] as List<Map<String, Any?>>
        assertEquals(3, results.size)
        // Should be sorted by anomaly_rank descending: 100, 50, 10
        assertEquals(100, results[0]["anomaly_rank"])
        assertEquals(50, results[1]["anomaly_rank"])
        assertEquals(10, results[2]["anomaly_rank"])
    }

    // Organizer resource tests

    @Test
    fun `listOrganizerItems returns all items`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems()

        assertEquals(3, result["count"])
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(listOf(1, 2, 3), items.map { it["id"] })
    }

    @Test
    fun `listOrganizerItems returns empty list when no items`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems()

        assertEquals(0, result["count"])
        assertEquals(emptyList<Any>(), result["items"])
    }

    @Test
    fun `listOrganizerItems returns items`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(42, "GET /test HTTP/1.1", "HTTP/1.1 200 OK")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems()

        assertEquals(1, result["count"])
    }

    @Test
    fun `getOrganizerItem returns item by id`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(100, "GET /page1 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nbody", "Test notes")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(100)

        assertEquals(100, result["id"])
        assertEquals("GET /page1 HTTP/1.1", result["request"])
        assertEquals("HTTP/1.1 200 OK", result["response_headers"])
        assertEquals("body", result["response_body"])
        assertEquals("Test notes", result["notes"])
    }

    @Test
    fun `getOrganizerItem returns error for non-existent item`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(999)

        assertEquals("not_found", result["error"])
    }

    @Test
    fun `getOrganizerItem retrieves item by id`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(42, "GET /test HTTP/1.1", "HTTP/1.1 200 OK")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(42)

        assertEquals(42, result["id"])
        assertEquals("GET /test HTTP/1.1", result["request"])
    }

    @Test
    fun `getOrganizerItem returns http service info`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(
                id = 100,
                request = "GET /page1 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Test",
                host = "example.com",
                port = 443,
                secure = true
            )
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(100)

        assertEquals("example.com", result["host"])
        assertEquals(443, result["port"])
        assertEquals(true, result["secure"])
    }

    @Test
    fun `getOrganizerItem splits response into headers and body`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(
                id = 100,
                request = "GET /page HTTP/1.1",
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>"
            )
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(100)

        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", result["response_headers"])
        assertEquals("<html>body</html>", result["response_body"])
        assertNull(result["response"])  // Old field should be gone
    }

    @Test
    fun `getOrganizerItem truncates body by default`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(
                id = 100,
                request = "GET /page HTTP/1.1",
                response = "HTTP/1.1 200 OK\r\n\r\n" + "X".repeat(500)
            )
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(100)

        assertEquals("X".repeat(100), result["response_body"])
        assertEquals(true, result["response_body_truncated"])
        assertEquals(500, result["response_body_total_length"])
    }

    @Test
    fun `getOrganizerItem respects custom body_limit`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(
                id = 100,
                request = "GET /page HTTP/1.1",
                response = "HTTP/1.1 200 OK\r\n\r\n" + "Y".repeat(500)
            )
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(100, bodyLimit = 200)

        assertEquals("Y".repeat(200), result["response_body"])
        assertEquals(true, result["response_body_truncated"])
    }

    @Test
    fun `getOrganizerItem returns full body when limit is zero`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(
                id = 100,
                request = "GET /page HTTP/1.1",
                response = "HTTP/1.1 200 OK\r\n\r\n" + "Z".repeat(500)
            )
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(100, bodyLimit = 0)

        assertEquals("Z".repeat(500), result["response_body"])
        assertEquals(false, result["response_body_truncated"])
    }

    @Test
    fun `getOrganizerItem respects body_limit parameter`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(
                id = 42,
                request = "GET /test HTTP/1.1",
                response = "HTTP/1.1 200 OK\r\n\r\n" + "Q".repeat(500)
            )
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItem(42, bodyLimit = 150)

        assertEquals("Q".repeat(150), result["response_body"])
        assertEquals(true, result["response_body_truncated"])
    }

    @Test
    fun `getResults includes status_codes field with all unique status codes`() {
        val run = manager.startRun()

        val req200a = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req200a.id = 1
        req200a.response = "HTTP/1.1 200 OK\r\n\r\nok"

        val req200b = burp.Request("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req200b.id = 2
        req200b.response = "HTTP/1.1 200 OK\r\n\r\nok"

        val req404 = burp.Request("GET /c HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req404.id = 3
        req404.response = "HTTP/1.1 404 Not Found\r\n\r\nnot found"

        val req500 = burp.Request("GET /d HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req500.id = 4
        req500.response = "HTTP/1.1 500 Error\r\n\r\nerror"

        run.store.add(req200a)
        run.store.add(req200b)
        run.store.add(req404)
        run.store.add(req500)

        val result = handlers.getResults(run.id,"id", true, 100, 0)

        @Suppress("UNCHECKED_CAST")
        val statusCodes = result["status_codes"] as Set<Int>
        assertEquals(setOf(200, 404, 500), statusCodes)
    }

    @Test
    fun `getOrganizerItems returns multiple items by ids`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nbody1"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nbody2"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nbody3")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItems(setOf(1, 3))

        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(2, items.size)
        assertEquals(setOf(1, 3), items.map { it["id"] }.toSet())
    }

    @Test
    fun `getOrganizerItems respects body_limit`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\n" + "X".repeat(500))
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItems(setOf(1), bodyLimit = 50)

        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals("X".repeat(50), items[0]["response_body"])
        assertEquals(true, items[0]["response_body_truncated"])
    }

    @Test
    fun `getOrganizerItems retrieves multiple items by ids`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(10, "GET /10 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nten"),
            FakeOrganizerItem(20, "GET /20 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\ntwenty")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.getOrganizerItems(setOf(10, 20))

        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(2, items.size)
    }

    // Desync mode Connection header stripping tests

    @Test
    fun `getRequestDetail strips Connection header when desync mode enabled`() {
        val handlersWithDesync = McpResourceHandlers(manager, desyncMode = { true })
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html\r\n\r\nbody"
        run.store.add(request)

        val result = handlersWithDesync.getRequestDetail(run.id,1)

        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", result["response_headers"])
    }

    @Test
    fun `getRequestDetail preserves Connection header when desync mode disabled`() {
        val handlersNoDesync = McpResourceHandlers(manager, desyncMode = { false })
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html\r\n\r\nbody"
        run.store.add(request)

        val result = handlersNoDesync.getRequestDetail(run.id,1)

        assertEquals("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html", result["response_headers"])
    }

    @Test
    fun `getRequestDetail strips Connection header case-insensitively`() {
        val handlersWithDesync = McpResourceHandlers(manager, desyncMode = { true })
        val run = manager.startRun()
        val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\nconnection: close\r\nContent-Type: text/html\r\n\r\nbody"
        run.store.add(request)

        val result = handlersWithDesync.getRequestDetail(run.id,1)

        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", result["response_headers"])
    }

    @Test
    fun `getOrganizerItem strips Connection header when desync mode enabled`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK\r\nConnection: close\r\nX-Custom: value\r\n\r\nbody")
        ))
        val handlersWithDesync = McpResourceHandlers(manager, fakeOrganizer, desyncMode = { true })

        val result = handlersWithDesync.getOrganizerItem(1)

        assertEquals("HTTP/1.1 200 OK\r\nX-Custom: value", result["response_headers"])
    }

    // Domain filtering tests

    @Test
    fun `listOrganizerItems with domain filter returns only matching items`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", host = "other.com"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "example.com")

        assertEquals(2, result["count"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        // Sorted by ID descending (timestamps are null)
        assertEquals(listOf(3, 1), items.map { it["id"] })
    }

    @Test
    fun `listOrganizerItems with domain filter paginates 10 per page`() {
        // Create 25 items for example.com
        val items = (1..25).map {
            FakeOrganizerItem(it, "GET /$it HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com")
        }
        val fakeOrganizer = FakeOrganizerProvider(items)
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "example.com")

        assertEquals(25, result["count"])
        assertEquals(1, result["page"])
        assertEquals(10, result["page_size"])
        assertEquals(3, result["total_pages"])
        @Suppress("UNCHECKED_CAST")
        val returnedItems = result["items"] as List<Map<String, Any?>>
        assertEquals(10, returnedItems.size)
    }

    @Test
    fun `listOrganizerItems with domain filter supports page parameter`() {
        // Create 25 items for example.com
        val items = (1..25).map {
            FakeOrganizerItem(it, "GET /$it HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com")
        }
        val fakeOrganizer = FakeOrganizerProvider(items)
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "example.com", page = 3)

        assertEquals(25, result["count"])
        assertEquals(3, result["page"])
        assertEquals(3, result["total_pages"])
        @Suppress("UNCHECKED_CAST")
        val returnedItems = result["items"] as List<Map<String, Any?>>
        assertEquals(5, returnedItems.size)  // Last page has only 5 items
    }

    @Test
    fun `listOrganizerItems with domain filter sorts by timestamp descending`() {
        val now = java.time.ZonedDateTime.now()
        val items = listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com", timeRequestSent = now.minusHours(2)),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com", timeRequestSent = now),  // Most recent
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com", timeRequestSent = now.minusHours(1))
        )
        val fakeOrganizer = FakeOrganizerProvider(items)
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "example.com")

        @Suppress("UNCHECKED_CAST")
        val returnedItems = result["items"] as List<Map<String, Any?>>
        // Should be sorted: most recent first (2, 3, 1)
        assertEquals(listOf(2, 3, 1), returnedItems.map { it["id"] })
    }

    @Test
    fun `listOrganizerItems with domain filter sorts nulls last then by ID descending`() {
        val now = java.time.ZonedDateTime.now()
        val items = listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com", timeRequestSent = null),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com", timeRequestSent = now),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com", timeRequestSent = null),
            FakeOrganizerItem(4, "GET /4 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com", timeRequestSent = now.minusHours(1))
        )
        val fakeOrganizer = FakeOrganizerProvider(items)
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "example.com")

        @Suppress("UNCHECKED_CAST")
        val returnedItems = result["items"] as List<Map<String, Any?>>
        // Items with timestamps first (2, 4), then nulls sorted by ID descending (3, 1)
        assertEquals(listOf(2, 4, 3, 1), returnedItems.map { it["id"] })
    }

    @Test
    fun `listOrganizerItems filters by domain`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", host = "other.com"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "example.com")

        assertEquals(2, result["count"])
        assertEquals(1, result["page"])
    }

    @Test
    fun `listOrganizerItems supports domain and page parameters`() {
        // Create 15 items for example.com
        val items = (1..15).map {
            FakeOrganizerItem(it, "GET /$it HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com")
        }
        val fakeOrganizer = FakeOrganizerProvider(items)
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "example.com", page = 2)

        assertEquals(15, result["count"])
        assertEquals(2, result["page"])
        @Suppress("UNCHECKED_CAST")
        val returnedItems = result["items"] as List<Map<String, Any?>>
        assertEquals(5, returnedItems.size)  // Page 2 has 5 items (11-15)
    }

    @Test
    fun `listOrganizerItems without filter returns no pagination metadata`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", host = "other.com")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems()

        assertEquals(2, result["count"])
        assertFalse(result.containsKey("page"))
        assertFalse(result.containsKey("page_size"))
        assertFalse(result.containsKey("total_pages"))
    }

    @Test
    fun `listOrganizerItems with non-matching domain returns empty paginated result`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "nonexistent.com")

        assertEquals(0, result["count"])
        assertEquals(1, result["page"])
        assertEquals(0, result["total_pages"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertTrue(items.isEmpty())
    }

    @Test
    fun `listOrganizerItems domain filter is case-sensitive`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", host = "Example.com"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", host = "example.com")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(domain = "example.com")

        assertEquals(1, result["count"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(listOf(2), items.map { it["id"] })
    }

    // Search parameter tests

    @Test
    fun `listOrganizerItems with searchNotes returns only items with matching notes`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", notes = "important finding"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", notes = "nothing here"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", notes = "another important item")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(searchNotes = "important")

        assertEquals(2, result["count"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(setOf(1, 3), items.map { it["id"] }.toSet())
    }

    @Test
    fun `listOrganizerItems with searchRequest returns only items with matching request`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /api/users HTTP/1.1\r\nHost: example.com", "HTTP/1.1 200 OK"),
            FakeOrganizerItem(2, "POST /api/login HTTP/1.1\r\nHost: example.com", "HTTP/1.1 200 OK"),
            FakeOrganizerItem(3, "GET /api/users/123 HTTP/1.1\r\nHost: example.com", "HTTP/1.1 200 OK")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(searchRequest = "/api/users")

        assertEquals(2, result["count"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(setOf(1, 3), items.map { it["id"] }.toSet())
    }

    @Test
    fun `listOrganizerItems with searchResponse returns only items with matching response`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\n{\"error\": \"not found\"}"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\n{\"success\": true}"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 500 Error\r\n\r\n{\"error\": \"server error\"}")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(searchResponse = "error")

        assertEquals(2, result["count"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(setOf(1, 3), items.map { it["id"] }.toSet())
    }

    @Test
    fun `listOrganizerItems search is case-insensitive`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", notes = "IMPORTANT"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", notes = "important"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", notes = "nothing")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(searchNotes = "Important")

        assertEquals(2, result["count"])
    }

    @Test
    fun `listOrganizerItems combines search filters with AND`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /api HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nsecret", notes = "important"),
            FakeOrganizerItem(2, "POST /api HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\npublic", notes = "important"),
            FakeOrganizerItem(3, "GET /api HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nsecret", notes = "trivial")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(
            searchNotes = "important",
            searchResponse = "secret"
        )

        assertEquals(1, result["count"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(listOf(1), items.map { it["id"] })
    }

    @Test
    fun `listOrganizerItems combines search with domain filter`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET /1 HTTP/1.1", "HTTP/1.1 200 OK", notes = "important", host = "example.com"),
            FakeOrganizerItem(2, "GET /2 HTTP/1.1", "HTTP/1.1 200 OK", notes = "important", host = "other.com"),
            FakeOrganizerItem(3, "GET /3 HTTP/1.1", "HTTP/1.1 200 OK", notes = "nothing", host = "example.com")
        ))
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(
            domain = "example.com",
            searchNotes = "important"
        )

        assertEquals(1, result["count"])
        @Suppress("UNCHECKED_CAST")
        val items = result["items"] as List<Map<String, Any?>>
        assertEquals(listOf(1), items.map { it["id"] })
    }

    @Test
    fun `listOrganizerItems with search enables pagination`() {
        val items = (1..15).map {
            FakeOrganizerItem(it, "GET /$it HTTP/1.1", "HTTP/1.1 200 OK", notes = "match")
        }
        val fakeOrganizer = FakeOrganizerProvider(items)
        val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.listOrganizerItems(searchNotes = "match")

        assertEquals(15, result["count"])
        assertEquals(1, result["page"])
        assertEquals(10, result["page_size"])
        assertEquals(2, result["total_pages"])
    }

    // Long-poll tests

    @Test
    fun `getRunStatus with waitMs returns immediately when run is finished`() {
        val run = manager.startRun()
        run.handler.markScriptCompleted()

        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus(run.id, waitMs = 5000)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("completed", result["status"])
        assertTrue(elapsed < 1000, "Should return immediately for finished run, took ${elapsed}ms")
    }

    @Test
    fun `getRunStatus with waitMs blocks until run finishes`() {
        val run = manager.startRun()

        Thread {
            Thread.sleep(200)
            run.handler.markScriptCompleted()
        }.start()

        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus(run.id, waitMs = 5000)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("completed", result["status"])
        assertNotNull(result["summary"], "Should include summary when run finishes during wait")
        assertTrue(elapsed in 100..2000, "Should return shortly after run finishes, took ${elapsed}ms")
    }

    @Test
    fun `getRunStatus with waitMs times out if run does not finish`() {
        val run = manager.startRun()

        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus(run.id, waitMs = 300)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("running", result["status"])
        assertNull(result["summary"], "Should not include summary when still running")
        assertTrue(elapsed in 200..1000, "Should return after timeout, took ${elapsed}ms")
    }

    @Test
    fun `getRunStatus without waitMs returns immediately for in-progress run`() {
        val run = manager.startRun()

        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus(run.id)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("running", result["status"])
        assertTrue(elapsed < 500, "Should return immediately without wait, took ${elapsed}ms")
    }

    @Test
    fun `getRunStatus with waitMs returns not_found immediately for missing run`() {
        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus("nonexistent", waitMs = 5000)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("not_found", result["error"])
        assertTrue(elapsed < 500, "Should return immediately for missing run, took ${elapsed}ms")
    }

    // Example script resource tests

    @Test
    fun `listExamples returns list of available example scripts`() {
        val result = handlers.listExamples()

        @Suppress("UNCHECKED_CAST")
        val examples = result["examples"] as List<Map<String, Any?>>
        assertTrue(examples.isNotEmpty())
        // Check that basic.py is in the list
        assertTrue(examples.any { it["name"] == "basic" })
    }

    @Test
    fun `listExamples returns name for each example`() {
        val result = handlers.listExamples()

        @Suppress("UNCHECKED_CAST")
        val examples = result["examples"] as List<Map<String, Any?>>
        val basic = examples.find { it["name"] == "basic" }
        assertNotNull(basic)
    }

    @Test
    fun `getExample returns script content for valid example`() {
        val result = handlers.getExample("basic")

        assertNotNull(result["content"])
        val content = result["content"] as String
        assertTrue(content.contains("def queueRequests"))
    }

    @Test
    fun `getExample returns error for unknown example`() {
        val result = handlers.getExample("nonexistent-script")

        assertEquals("not_found", result["error"])
    }

    @Test
    fun `listExamples auto-discovers all py files in examples directory`() {
        val result = handlers.listExamples()

        @Suppress("UNCHECKED_CAST")
        val examples = result["examples"] as List<Map<String, Any?>>
        val names = examples.map { it["name"] }

        // These are actual files in resources/examples/ - includes ones NOT in any hardcoded list
        assertTrue(names.contains("basic"), "Should discover basic.py")
        assertTrue(names.contains("timing"), "Should discover timing.py")
        assertTrue(names.contains("customSortOrder"), "Should discover customSortOrder.py")
        assertTrue(names.contains("pinwheel"), "Should discover pinwheel.py")
        assertTrue(names.contains("email-link-extraction"), "Should discover email-link-extraction.py")
        // Should NOT include __init__.py
        assertFalse(names.contains("__init__"), "Should not include __init__.py")
    }

    @Test
    fun `getRequestDetail indicates when response was stripped`() {
        val run = manager.startRun()
        val req = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.id = 1
        req.response = "HTTP/1.1 200 OK\r\n\r\nBody"
        run.store.add(req)

        // Strip
        run.store.stripResponseBodies()
        run.responsesStripped = true

        val handlers = McpResourceHandlers(manager)
        val result = handlers.getRequestDetail(run.id, 1)

        assertTrue(result.containsKey("warning"))
        assertTrue((result["warning"] as String).contains("stripped"))
        // Metadata should still be present
        assertEquals(200, result["status"])
    }

    @Test
    fun `hardcoded example list matches files in resources examples directory`() {
        val dir = File("resources/examples")
        assertTrue(dir.exists(), "resources/examples directory should exist")

        val filesOnDisk = dir.listFiles()!!
            .filter { it.extension == "py" && it.name != "__init__.py" }
            .map { it.nameWithoutExtension }
            .toSet()

        @Suppress("UNCHECKED_CAST")
        val listed = (handlers.listExamples()["examples"] as List<Map<String, Any?>>)
            .map { it["name"] as String }
            .toSet()

        val missing = filesOnDisk - listed
        val extra = listed - filesOnDisk

        assertTrue(missing.isEmpty(), "Examples on disk but not in hardcoded list: $missing")
        assertTrue(extra.isEmpty(), "Examples in hardcoded list but not on disk: $extra")
    }
}
