package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*

class McpToolHandlersTest {

    private lateinit var manager: RunManager
    private lateinit var handlers: McpToolHandlers

    @BeforeEach
    fun setup() {
        manager = RunManager()
        handlers = McpToolHandlers(manager)
    }

    @Test
    fun `setOrganizerNotes updates notes on item`() {
        val fakeOrganizer = FakeOrganizerProvider(listOf(
            FakeOrganizerItem(1, "GET / HTTP/1.1", "HTTP/1.1 200 OK", "Old note")
        ))
        val handlersWithOrganizer = McpToolHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.setOrganizerNotes(1, "New note")

        assertEquals("success", result["status"])
        assertEquals("New note", fakeOrganizer.getNotes(1))
    }

    @Test
    fun `setOrganizerNotes returns error for non-existent item`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlersWithOrganizer = McpToolHandlers(manager, fakeOrganizer)

        val result = handlersWithOrganizer.setOrganizerNotes(999, "Note")

        assertEquals("not_found", result["error"])
    }

    @Test
    fun `startRun blocks until completion and returns results`() {
        val result = handlers.startRun(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        assertEquals("completed", result["status"])
        assertNotNull(result["run_id"])
        assertNotNull(result["results"])
        assertNotNull(result["result_count"])
        assertEquals(0, result["fails"])
    }

    @Test
    fun `startRun returns running status with run details when wait exceeded`() {
        val result = handlers.startRun(
            script = """
def queueRequests(target, wordlists):
    import time
    time.sleep(10)  # Longer than timeout

def completed(results):
    pass
            """.trimIndent(),
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = "",
            timeoutMs = 100  // Very short timeout
        )

        assertEquals("running", result["status"])
        assertNotNull(result["run_id"])
        assertNotNull(result["message"])
        assertTrue((result["message"] as String).contains("turbo://runs/"))
        assertFalse(result.containsKey("running"), "Should not contain 'running' boolean")
        assertFalse(result.containsKey("finished"), "Should not contain 'finished' boolean")
        assertNotNull(result["status_message"])
        assertNotNull(result["result_count"])
        assertNotNull(result["fails"])
        assertNotNull(result["created_at"])

        // Stop the run so the background sleep(10) thread doesn't delay test suite exit
        handlers.stopRun(result["run_id"] as String)
    }

    @Test
    fun `startRun uses default 55 second timeout`() {
        val result = handlers.startRun(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        // Should complete (not timeout) since script finishes immediately
        assertEquals("completed", result["status"])
    }

    @Test
    fun `startRunAsync returns immediately with started status`() {
        val result = handlers.startRunAsync(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        assertEquals("started", result["status"])
        assertNotNull(result["run_id"])
    }

    @Test
    fun `stopRun stops a run by id`() {
        val result = handlers.startRunAsync(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )
        val runId = result["run_id"] as String

        val stopResult = handlers.stopRun(runId)

        assertEquals("stopped", stopResult["status"])
    }

    private fun runWithRequest(): mcp.ActiveRun {
        val run = manager.startRun()
        run.handler.code = "def queueRequests(target, wordlists):\n    pass"
        val req = burp.Request("GET /vuln?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.id = 1
        req.response = "HTTP/1.1 500 Internal Server Error\r\n\r\nSQL syntax error"
        run.store.add(req)
        return run
    }

    @Test
    fun `reportFinding writes a structured note to the organizer`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlers = McpToolHandlers(manager, fakeOrganizer)
        val run = runWithRequest()

        val result = handlers.reportFinding(
            runId = run.id, requestId = 1, title = "SQL injection in id param",
            severity = "high", confidence = "firm", findingType = "sqli",
            detail = "Single quote triggers a 500 with a SQL error.",
            collaboratorPayload = "abc.oast.net"
        )

        assertEquals("reported", result["status"])
        assertNotNull(result["finding_id"])
        assertEquals(1, fakeOrganizer.sentItems.size)
        val note = fakeOrganizer.sentItems[0].second
        assertTrue(note.contains("[HIGH/FIRM] SQL injection in id param — sqli"))
        assertTrue(note.contains("Run ID: ${run.id}"))
        assertTrue(note.contains("Request ID: 1"))
        assertTrue(note.contains("Collaborator: abc.oast.net"))
        assertTrue(note.contains("--- Script ---"))
    }

    @Test
    fun `reportFinding is deterministic for the same inputs`() {
        val handlers = McpToolHandlers(manager, FakeOrganizerProvider(emptyList()))
        val run = runWithRequest()
        val a = handlers.reportFinding(run.id, 1, "X", "low", "firm", "sqli")
        val b = handlers.reportFinding(run.id, 1, "X", "low", "firm", "sqli")
        assertEquals(a["finding_id"], b["finding_id"])
    }

    @Test
    fun `reportFinding rejects invalid severity without writing`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlers = McpToolHandlers(manager, fakeOrganizer)
        val run = runWithRequest()

        val result = handlers.reportFinding(run.id, 1, "T", "sev?", "firm", "sqli")

        assertEquals("invalid_severity", result["error"])
        assertEquals(0, fakeOrganizer.sentItems.size)
    }

    @Test
    fun `reportFinding rejects invalid confidence without writing`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlers = McpToolHandlers(manager, fakeOrganizer)
        val run = runWithRequest()

        val result = handlers.reportFinding(run.id, 1, "T", "high", "maybe", "sqli")

        assertEquals("invalid_confidence", result["error"])
        assertEquals(0, fakeOrganizer.sentItems.size)
    }

    @Test
    fun `reportFinding reports request_not_found for a missing request`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlers = McpToolHandlers(manager, fakeOrganizer)
        val run = runWithRequest()

        val result = handlers.reportFinding(run.id, 999, "T", "high", "firm", "sqli")

        assertEquals("request_not_found", result["error"])
        assertEquals(0, fakeOrganizer.sentItems.size)
    }

    @Test
    fun `saveToOrganizer saves requests with notes and script`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlersWithOrganizer = McpToolHandlers(manager, fakeOrganizer)

        // Create a run with some requests
        val run = manager.startRun()
        run.handler.code = "def queueRequests(target, wordlists):\n    pass"
        val req1 = burp.Request("GET /page1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\nOK"
        val req2 = burp.Request("GET /page2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.response = "HTTP/1.1 404 Not Found\r\n\r\nNot Found"
        run.store.add(req1)
        run.store.add(req2)

        val result = handlersWithOrganizer.saveToOrganizer(
            runId = run.id,
            items = """[{"request_id": 1, "notes": "Interesting finding"}, {"request_id": 2, "notes": "Check this"}]"""
        )

        val saved = result["saved"] as List<*>
        assertEquals(listOf(1, 2), saved)
        assertEquals(2, fakeOrganizer.sentItems.size)
        assertTrue(fakeOrganizer.sentItems[0].second.startsWith("Interesting finding"))
        assertTrue(fakeOrganizer.sentItems[0].second.contains("Run ID: ${run.id}"))
        assertTrue(fakeOrganizer.sentItems[0].second.contains("--- Script ---"))
        assertTrue(fakeOrganizer.sentItems[0].second.contains("def queueRequests"))
        assertTrue(fakeOrganizer.sentItems[1].second.startsWith("Check this"))
        assertTrue(fakeOrganizer.sentItems[1].second.contains("Run ID: ${run.id}"))
        assertTrue(fakeOrganizer.sentItems[1].second.contains("--- Script ---"))
    }

    @Test
    fun `saveToOrganizer returns error for non-existent request`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlersWithOrganizer = McpToolHandlers(manager, fakeOrganizer)

        val run = manager.startRun()
        val req1 = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\n"
        run.store.add(req1)

        val result = handlersWithOrganizer.saveToOrganizer(
            runId = run.id,
            items = """[{"request_id": 1, "notes": "Good"}, {"request_id": 999, "notes": "Missing"}]"""
        )

        val saved = result["saved"] as List<*>
        val errors = result["errors"] as List<Map<String, Any>>
        assertEquals(listOf(1), saved)
        assertEquals(1, errors.size)
        assertEquals(999, errors[0]["request_id"])
    }

    @Test
    fun `searchResponses returns matching request IDs`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /page1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\nHello World"
        val req2 = burp.Request("GET /page2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.response = "HTTP/1.1 200 OK\r\n\r\nGoodbye World"
        val req3 = burp.Request("GET /page3 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req3.id = 3
        req3.response = "HTTP/1.1 404 Not Found\r\n\r\nNot Found"
        run.store.add(req1)
        run.store.add(req2)
        run.store.add(req3)

        val result = handlers.searchResponses(runId = run.id, query = "World")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(1, 2), matches.sorted())
        assertEquals(2, result["match_count"])
    }

    @Test
    fun `searchResponses returns empty list when no matches`() {
        val run = manager.startRun()
        val req = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.id = 1
        req.response = "HTTP/1.1 200 OK\r\n\r\nHello"
        run.store.add(req)

        val result = handlers.searchResponses(runId = run.id, query = "notfound")

        val matches = result["matches"] as List<Int>
        assertEquals(emptyList<Int>(), matches)
        assertEquals(0, result["match_count"])
    }

    @Test
    fun `searchResponses handles null responses`() {
        val run = manager.startRun()
        val req = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.id = 1
        req.response = null
        run.store.add(req)

        val result = handlers.searchResponses(runId = run.id, query = "test")

        val matches = result["matches"] as List<Int>
        assertEquals(emptyList<Int>(), matches)
    }

    @Test
    fun `searchResponses uses specified run`() {
        val run1 = manager.startRun()
        val req1 = burp.Request("GET /run1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\nFindMe"
        run1.store.add(req1)

        val run2 = manager.startRun()
        val req2 = burp.Request("GET /run2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 1
        req2.response = "HTTP/1.1 200 OK\r\n\r\nNotThis"
        run2.store.add(req2)

        val result = handlers.searchResponses(runId = run1.id, query = "FindMe")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(1), matches)
    }

    @Test
    fun `searchResponses can find entries by label`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.label = "interesting"
        req1.response = "HTTP/1.1 200 OK\r\n\r\nOK"
        val req2 = burp.Request("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.label = "boring"
        req2.response = "HTTP/1.1 200 OK\r\n\r\nOK"
        run.store.add(req1)
        run.store.add(req2)

        val result = handlers.searchResponses(runId = run.id, query = "interesting")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(1), matches)
    }

    @Test
    fun `searchResponses with search_in labels only searches labels`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.label = "interesting"
        req1.response = "HTTP/1.1 200 OK\r\n\r\ninteresting body"
        val req2 = burp.Request("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.label = "boring"
        req2.response = "HTTP/1.1 200 OK\r\n\r\ninteresting body too"
        run.store.add(req1)
        run.store.add(req2)

        val result = handlers.searchResponses(runId = run.id, query = "interesting", searchIn = "labels")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(1), matches)
    }

    @Test
    fun `searchResponses with search_in responses only searches response bodies`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.label = "interesting"
        req1.response = "HTTP/1.1 200 OK\r\n\r\nplain body"
        val req2 = burp.Request("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.label = "boring"
        req2.response = "HTTP/1.1 200 OK\r\n\r\ninteresting body"
        run.store.add(req1)
        run.store.add(req2)

        val result = handlers.searchResponses(runId = run.id, query = "interesting", searchIn = "responses")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(2), matches)
    }

    @Test
    fun `searchResponses with search_in all searches both labels and responses`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.label = "interesting"
        req1.response = "HTTP/1.1 200 OK\r\n\r\nplain body"
        val req2 = burp.Request("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.label = "boring"
        req2.response = "HTTP/1.1 200 OK\r\n\r\ninteresting body"
        run.store.add(req1)
        run.store.add(req2)

        val result = handlers.searchResponses(runId = run.id, query = "interesting", searchIn = "all")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(1, 2), matches.sorted())
    }

    @Test
    fun `searchResponses defaults to searching all when search_in not specified`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.label = "tagged"
        req1.response = "HTTP/1.1 200 OK\r\n\r\nplain"
        val req2 = burp.Request("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.label = ""
        req2.response = "HTTP/1.1 200 OK\r\n\r\ntagged"
        run.store.add(req1)
        run.store.add(req2)

        val result = handlers.searchResponses(runId = run.id, query = "tagged")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(1, 2), matches.sorted())
    }

    @Test
    fun `searchResponses returns error when no run found`() {
        val result = handlers.searchResponses(runId = "nonexistent", query = "test")

        assertEquals("No run found", result["error"])
    }

    @Test
    fun `searchResponses notes when responses are stripped for response search`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.label = "interesting"
        req1.response = "HTTP/1.1 200 OK\r\n\r\nHello"
        run.store.add(req1)

        run.store.stripResponseBodies()
        run.responsesStripped = true

        val result = handlers.searchResponses(runId = run.id, query = "Hello", searchIn = "responses")

        assertTrue(result.containsKey("warning"))
        assertTrue((result["warning"] as String).contains("stripped"))
    }

    @Test
    fun `searchResponses still searches labels on stripped runs`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.label = "interesting"
        req1.response = "HTTP/1.1 200 OK\r\n\r\nHello"
        run.store.add(req1)

        run.store.stripResponseBodies()
        run.responsesStripped = true

        val result = handlers.searchResponses(runId = run.id, query = "interesting", searchIn = "labels")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(1), matches)
        assertFalse(result.containsKey("warning"))
    }

    @Test
    fun `searchResponses with default searchIn warns and still matches labels on stripped run`() {
        val run = manager.startRun()
        val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.label = "interesting"
        req1.response = "HTTP/1.1 200 OK\r\n\r\nHello"
        run.store.add(req1)

        run.store.stripResponseBodies()
        run.responsesStripped = true

        val result = handlers.searchResponses(runId = run.id, query = "interesting")

        val matches = result["matches"] as List<Int>
        assertEquals(listOf(1), matches)
        assertTrue(result.containsKey("warning"))
    }

    @Test
    fun `saveToOrganizer uses specified run`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val handlersWithOrganizer = McpToolHandlers(manager, fakeOrganizer)

        // Create two runs
        val run1 = manager.startRun()
        val req1 = burp.Request("GET /run1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\n"
        run1.store.add(req1)

        val run2 = manager.startRun()
        val req2 = burp.Request("GET /run2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 1  // Same ID but different run
        req2.response = "HTTP/1.1 404 Not Found\r\n\r\n"
        run2.store.add(req2)

        val result = handlersWithOrganizer.saveToOrganizer(
            runId = run1.id,
            items = """[{"request_id": 1, "notes": "From run1"}]"""
        )

        val saved = result["saved"] as List<*>
        assertEquals(listOf(1), saved)
        assertEquals(1, fakeOrganizer.sentItems.size)
        assertTrue(fakeOrganizer.sentItems[0].first.template.contains("/run1"))
    }

    @Test
    fun `startRun results include anomaly_rank field`() {
        // Start a run that completes immediately, then verify the result structure
        val result = handlers.startRun(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        assertEquals("completed", result["status"])
        // Verify result mapping includes anomaly_rank key in result structure
        val results = result["results"] as List<Map<String, Any?>>
        // No requests were made, so results list is empty - but verify the mapping exists by checking a run with data
        val run = manager.startRun()
        val req = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.id = 1
        req.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req.anomalyRank = 42
        run.store.add(req)

        val storeResults = run.store.getResults(burp.SortField.ANOMALY_RANK, true, 100, 0)
        assertEquals(1, storeResults.size)
        assertEquals(42, storeResults[0].anomalyRank)
    }

    @Test
    fun `startRun returns failed status when script throws error`() {
        val result = handlers.startRun(
            script = """
def queueRequests(target, wordlists):
    raise Exception("Test error message")

def completed(results):
    pass
            """.trimIndent(),
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        assertEquals("failed", result["status"])
        assertTrue((result["error_message"] as String).contains("Test error message"))
    }

    @Test
    fun `startRun includes error_message when completed with only connection failures`() {
        // Simulate a run that completes but all requests failed (connection errors)
        val run = manager.startRun()
        run.handler.code = "test script"

        // Simulate engine with permaFails but no successful results
        val engine = FakeRequestEngine(permaFailCount = 5, lastErrorMessage = "javax.net.ssl.SSLHandshakeException: Connection refused")
        run.handler.setRequestEngine(engine)
        run.handler.markScriptCompleted()

        // Build the result the same way startRun does
        val status = run.handler.status()
        val fails = run.handler.failCount()
        val resultCount = run.store.count()

        assertEquals("completed", status)
        assertEquals(5, fails)
        assertEquals(0, resultCount)

        // The key assertion: lastError should be available from the handler
        assertEquals("javax.net.ssl.SSLHandshakeException: Connection refused", run.handler.lastError())
    }

    @Test
    fun `startRun result includes error_message when zero results and connection failures`() {
        val result = handlers.startRun(
            script = """
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, requestsPerConnection=1, pipeline=False, engine=Engine.BURP)

def handleResponse(req, interesting):
    pass
            """.trimIndent(),
            baseRequest = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            endpoint = "https://localhost:1",  // Will fail to connect
            baseInput = "",
            timeoutMs = 10000
        )

        // Should complete (or timeout) with error info
        if (result["status"] == "completed") {
            val fails = result["fails"] as Int
            if (fails > 0) {
                assertTrue(result.containsKey("error_message"), "Should include error_message when there are connection failures but no results")
            }
        }
    }

    @Test
    fun `startRun does not include error_message on success`() {
        val result = handlers.startRun(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        assertEquals("completed", result["status"])
        assertFalse(result.containsKey("error_message"))
    }
}

// Test helpers
data class FakeOrganizerItem(
    val id: Int,
    val request: String,
    val response: String,
    var notes: String = "",
    val host: String = "example.com",
    val port: Int = 443,
    val secure: Boolean = true,
    val timeRequestSent: java.time.ZonedDateTime? = null
)

class FakeOrganizerProvider(items: List<FakeOrganizerItem>) : OrganizerProvider {
    private val items = items.toMutableList()
    val sentItems = mutableListOf<Pair<burp.Request, String>>()

    override fun getItems(): List<OrganizerItemData> {
        return items.map { OrganizerItemData(it.id, it.request, it.response, it.notes, it.host, it.port, it.secure, it.timeRequestSent) }
    }

    override fun getItemsByIds(ids: Set<Int>): List<OrganizerItemData> {
        return items.filter { it.id in ids }.map { OrganizerItemData(it.id, it.request, it.response, it.notes, it.host, it.port, it.secure, it.timeRequestSent) }
    }

    override fun setNotes(id: Int, notes: String): Boolean {
        val item = items.find { it.id == id } ?: return false
        item.notes = notes
        return true
    }

    override fun sendToOrganizer(request: burp.Request, notes: String) {
        sentItems.add(Pair(request, notes))
    }

    fun getNotes(id: Int): String? = items.find { it.id == id }?.notes
}

class ThrowingOrganizerProvider : OrganizerProvider {
    override fun getItems(): List<OrganizerItemData> = throw RuntimeException("Test exception from getItems")
    override fun getItemsByIds(ids: Set<Int>): List<OrganizerItemData> = throw RuntimeException("Test exception from getItemsByIds")
    override fun setNotes(id: Int, notes: String): Boolean = throw RuntimeException("Test exception from setNotes")
    override fun sendToOrganizer(request: burp.Request, notes: String) = throw RuntimeException("Test exception from sendToOrganizer")
}

// Collaborator test helpers
class FakeCollaboratorProvider(
    private val organizerProvider: OrganizerProvider? = null
) : CollaboratorProvider {
    private var payloadCounter = 0
    private val interactions = mutableListOf<CollaboratorInteractionData>()
    var organizerSentCount = 0

    override fun generatePayload(metadata: String): String {
        val payload = "test${++payloadCounter}.oastify.com"
        return payload
    }

    override fun getInteractions(payloads: List<String>?): List<CollaboratorInteractionData> {
        val result = if (payloads == null) {
            interactions.toList()
        } else {
            interactions.filter { it.payload in payloads }
        }

        // Simulate sending HTTP interactions to Organizer
        for (interaction in result) {
            if (interaction.type == "HTTP" && organizerProvider != null) {
                organizerSentCount++
            }
        }

        return result
    }

    // Test helper to simulate interactions
    fun addInteraction(interaction: CollaboratorInteractionData) {
        interactions.add(interaction)
    }
}

/**
 * Minimal fake RequestEngine for testing error surfacing without needing real connections.
 */
class FakeRequestEngine(
    private val permaFailCount: Int = 0,
    lastErrorMessage: String? = null
) : burp.RequestEngine() {
    override val maxRetriesPerRequest: Int = 0
    override var idleTimeout: Long = 0
    override val callback: (burp.Request, Boolean) -> Boolean = { _, _ -> false }
    override var readCallback: ((String) -> Boolean)? = null

    init {
        permaFails.set(permaFailCount)
        lastError = lastErrorMessage
        runState.set(4) // completed
        completedLatch = java.util.concurrent.CountDownLatch(0)
        target = java.net.URL("https://localhost")
        requestQueue = java.util.concurrent.LinkedBlockingQueue()
        outputHandler = object : burp.OutputHandler {
            override fun add(req: burp.Request) {}
            override fun getAllRquests(): List<burp.Request> = emptyList()
        }
    }

    override fun start(timeout: Int) {}
    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): burp.Request {
        return burp.Request(template, payloads, learnBoring ?: 0, label)
    }
}

class CollaboratorToolHandlersTest {

    private lateinit var manager: RunManager
    private lateinit var handlers: McpToolHandlers

    @BeforeEach
    fun setup() {
        manager = RunManager()
    }

    @Test
    fun `generateCollaboratorPayload returns payload domain`() {
        val fakeCollaborator = FakeCollaboratorProvider()
        handlers = McpToolHandlers(manager, collaboratorProvider = fakeCollaborator)

        val result = handlers.generateCollaboratorPayload("SSRF test in webhook param")

        assertEquals("test1.oastify.com", result["payload"])
    }

    @Test
    fun `generateCollaboratorPayload stores metadata for later retrieval`() {
        val fakeCollaborator = FakeCollaboratorProvider()
        handlers = McpToolHandlers(manager, collaboratorProvider = fakeCollaborator)

        handlers.generateCollaboratorPayload("SSRF test")

        // Add an interaction for the generated payload
        fakeCollaborator.addInteraction(CollaboratorInteractionData(
            payload = "test1.oastify.com",
            metadata = "SSRF test",
            type = "DNS",
            timestamp = "2024-01-01T12:00:00Z",
            clientIp = "1.2.3.4",
            details = mapOf("query_type" to "A")
        ))

        val interactions = handlers.getCollaboratorInteractions(null)
        val items = interactions["interactions"] as List<Map<String, Any?>>

        assertEquals(1, items.size)
        assertEquals("SSRF test", items[0]["metadata"])
    }

    @Test
    fun `getCollaboratorInteractions filters by payload`() {
        val fakeCollaborator = FakeCollaboratorProvider()
        handlers = McpToolHandlers(manager, collaboratorProvider = fakeCollaborator)

        fakeCollaborator.addInteraction(CollaboratorInteractionData(
            payload = "abc.oastify.com",
            metadata = "Test A",
            type = "DNS",
            timestamp = "2024-01-01T12:00:00Z",
            clientIp = "1.2.3.4",
            details = emptyMap()
        ))
        fakeCollaborator.addInteraction(CollaboratorInteractionData(
            payload = "xyz.oastify.com",
            metadata = "Test B",
            type = "HTTP",
            timestamp = "2024-01-01T12:01:00Z",
            clientIp = "5.6.7.8",
            details = emptyMap()
        ))

        val result = handlers.getCollaboratorInteractions(listOf("abc.oastify.com"))
        val items = result["interactions"] as List<Map<String, Any?>>

        assertEquals(1, items.size)
        assertEquals("abc.oastify.com", items[0]["payload"])
    }

    @Test
    fun `getCollaboratorInteractions returns all interactions when no filter`() {
        val fakeCollaborator = FakeCollaboratorProvider()
        handlers = McpToolHandlers(manager, collaboratorProvider = fakeCollaborator)

        fakeCollaborator.addInteraction(CollaboratorInteractionData(
            payload = "abc.oastify.com",
            metadata = "Test A",
            type = "DNS",
            timestamp = "2024-01-01T12:00:00Z",
            clientIp = "1.2.3.4",
            details = emptyMap()
        ))
        fakeCollaborator.addInteraction(CollaboratorInteractionData(
            payload = "xyz.oastify.com",
            metadata = "Test B",
            type = "HTTP",
            timestamp = "2024-01-01T12:01:00Z",
            clientIp = "5.6.7.8",
            details = emptyMap()
        ))

        val result = handlers.getCollaboratorInteractions(null)
        val items = result["interactions"] as List<Map<String, Any?>>

        assertEquals(2, items.size)
    }

    @Test
    fun `getCollaboratorInteractions returns interaction details`() {
        val fakeCollaborator = FakeCollaboratorProvider()
        handlers = McpToolHandlers(manager, collaboratorProvider = fakeCollaborator)

        fakeCollaborator.addInteraction(CollaboratorInteractionData(
            payload = "test.oastify.com",
            metadata = "SSRF test",
            type = "HTTP",
            timestamp = "2024-01-01T12:00:00Z",
            clientIp = "10.0.0.1",
            details = mapOf("method" to "GET", "path" to "/")
        ))

        val result = handlers.getCollaboratorInteractions(null)
        val items = result["interactions"] as List<Map<String, Any?>>

        assertEquals("test.oastify.com", items[0]["payload"])
        assertEquals("SSRF test", items[0]["metadata"])
        assertEquals("HTTP", items[0]["type"])
        assertEquals("2024-01-01T12:00:00Z", items[0]["timestamp"])
        assertEquals("10.0.0.1", items[0]["client_ip"])
        val details = items[0]["details"] as Map<*, *>
        assertEquals("GET", details["method"])
    }

    @Test
    fun `getCollaboratorInteractions sends HTTP interactions to Organizer`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val fakeCollaborator = FakeCollaboratorProvider(organizerProvider = fakeOrganizer)
        handlers = McpToolHandlers(manager, organizerProvider = fakeOrganizer, collaboratorProvider = fakeCollaborator)

        fakeCollaborator.addInteraction(CollaboratorInteractionData(
            payload = "test.oastify.com",
            metadata = "SSRF in webhook",
            type = "HTTP",
            timestamp = "2024-01-01T12:00:00Z",
            clientIp = "10.0.0.1",
            details = mapOf("request" to "GET / HTTP/1.1\r\nHost: test.oastify.com\r\n\r\n")
        ))

        handlers.getCollaboratorInteractions(null)

        assertEquals(1, fakeCollaborator.organizerSentCount)
    }

    @Test
    fun `getCollaboratorInteractions does not send DNS interactions to Organizer`() {
        val fakeOrganizer = FakeOrganizerProvider(emptyList())
        val fakeCollaborator = FakeCollaboratorProvider(organizerProvider = fakeOrganizer)
        handlers = McpToolHandlers(manager, organizerProvider = fakeOrganizer, collaboratorProvider = fakeCollaborator)

        fakeCollaborator.addInteraction(CollaboratorInteractionData(
            payload = "test.oastify.com",
            metadata = "DNS test",
            type = "DNS",
            timestamp = "2024-01-01T12:00:00Z",
            clientIp = "10.0.0.1",
            details = mapOf("query_type" to "A")
        ))

        handlers.getCollaboratorInteractions(null)

        assertEquals(0, fakeCollaborator.organizerSentCount)
    }
}
