package mcp

import burp.Request
import burp.SortField
import java.io.File
import kotlin.io.path.createTempDirectory

fun Request.toSummaryMap(): Map<String, Any?> = mapOf(
    "id" to id,
    "status" to code,
    "length" to length,
    "ttfb" to ttfb,
    "ttlb" to ttlb,
    // Microseconds from the start of the run, unlike ttfb/ttlb which each engine measures from
    // its own idea of "sent", so it is the one field two requests can be compared on directly.
    "arrival" to arrival,
    "wordcount" to wordcount,
    "words" to words,
    "label" to label,
    "anomaly_rank" to anomalyRank,
    // Null unless the request went through an HTTP/3 gate. Which gate released it is not
    // cosmetic: it is what separates a real behavioural difference between two runs from the
    // engine having released them differently.
    "gate_mode" to gateMode
)

class McpResourceHandlers(
    private val manager: RunManager,
    private val organizerProvider: OrganizerProvider? = null,
    private val desyncMode: () -> Boolean = { false }
) {

    val docTopics = mapOf(
        "api-quickstart" to "Quick reference for scripting",
        "engines" to "Engine types (AUTO, THREADED, BURP, BURP2, HTTP3)",
        "settings" to "Complete parameter reference",
        "race-conditions" to "Race condition testing with gates",
        "response-processing" to "Handling and filtering responses",
        "decorators" to "Response decorator reference",
        "misc" to "Wordlists and utilities"
    )

    // Auto-discovered from resources/examples/
    private val discoveredExamples: Set<String> = setOf(
        "0cl-exploit", "0cl-find-offset", "0cl-poc",
        "apis", "basic", "benchmark-h1-race", "benchmark-h2-race",
        "burpIntegration", "customSortOrder", "debug", "default", "desync-gadget-hunter",
        "email-link-extraction", "http2", "http3", "infinite", "micro-crawl",
        "misc", "multiHost", "multipleParameters", "outputToFile",
        "partialReadCallback", "pinwheel", "race-multi-endpoint",
        "race-http3",
        "race-single-packet-attack",
        "ratelimit", "recursive",
        "specialWordlists", "test", "timing", "timingAttackWithState"
    )

    private fun runNotFoundError(runId: String): Map<String, Any?> {
        val error = if (manager.isEvicted(runId)) "evicted" else "not_found"
        return mapOf("error" to error)
    }

    fun getRunStatus(runId: String, waitMs: Long = 0): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return runNotFoundError(runId)

        if (waitMs > 0 && run.handler.status() == "running") {
            val deadline = System.currentTimeMillis() + waitMs
            while (run.handler.status() == "running" && System.currentTimeMillis() < deadline) {
                Thread.sleep(100)
            }
        }

        val status = run.handler.status()
        val baseStatus = mapOf(
            "run_id" to run.id,
            "status" to status,
            "status_message" to run.handler.statusString(),
            "result_count" to run.store.count(),
            "fails" to run.handler.failCount(),
            "created_at" to run.createdAt
        )

        // Include summary when run is not running
        if (status != "running") {
            val results = run.store.getResults(SortField.ANOMALY_RANK, true, 20, 0)
            val summary = results.map { it.toSummaryMap() }
            return baseStatus + mapOf("summary" to summary)
        }

        return baseStatus
    }

    fun getRunScript(runId: String): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return runNotFoundError(runId)
        return mapOf("script" to run.handler.code)
    }

    fun getResults(
        runId: String,
        sortBy: String,
        descending: Boolean,
        limit: Int,
        offset: Int
    ): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return runNotFoundError(runId)

        val sortField = try {
            SortField.valueOf(sortBy.uppercase())
        } catch (e: IllegalArgumentException) {
            SortField.ID
        }

        val results = run.store.getResults(sortField, descending, limit, offset)

        return mapOf(
            "results" to results.map { it.toSummaryMap() },
            "total_count" to run.store.count(),
            "status_codes" to run.store.getUniqueStatusCodes()
        )
    }

    fun getRequestDetail(
        runId: String,
        requestId: Int,
        bodyLimit: Int = 100,
        exportFile: Boolean = false
    ): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return runNotFoundError(runId)

        val request = run.store.getRequest(requestId)
            ?: return mapOf("error" to "request_not_found")

        if (run.responsesStripped && request.response == null) {
            return mapOf(
                "warning" to "Response body was stripped from this run to free memory. Metadata is still available.",
                "request" to request.getRequest(),
                "status" to request.code,
                "length" to request.length,
                "ttfb" to request.ttfb,
                "ttlb" to request.ttlb,
                "wordcount" to request.wordcount,
                "words" to request.words,
                "label" to request.label,
                "anomaly_rank" to request.anomalyRank
            )
        }

        if (exportFile) {
            val tempDir = createTempDirectory("turbo-${run.id}-").toFile()
            val requestFile = File(tempDir, "request-$requestId.txt")
            val responseFile = File(tempDir, "response-$requestId.txt")

            requestFile.writeText(request.getRequest())
            request.response?.let { responseFile.writeText(it) }

            return mapOf(
                "request_file" to requestFile.absolutePath,
                "response_file" to responseFile.absolutePath,
                "status" to request.code,
                "length" to request.length,
                "ttfb" to request.ttfb,
                "ttlb" to request.ttlb,
                "words" to request.words
            )
        }

        val response = request.response
        val (headers, body) = splitResponse(response)
        val truncatedBody = TruncatedHttpBody(body, bodyLimit)

        return mapOf(
            "request" to request.getRequest(),
            "response_headers" to filterHeaders(headers),
            "status" to request.code,
            "length" to request.length,
            "ttfb" to request.ttfb,
            "ttlb" to request.ttlb,
            "words" to request.words
        ) + truncatedBody.toResponseFields()
    }

    private fun splitResponse(response: String?): Pair<String, String> {
        if (response == null) return Pair("", "")

        val separatorIndex = response.indexOf("\r\n\r\n")
        return if (separatorIndex != -1) {
            Pair(
                response.substring(0, separatorIndex),
                response.substring(separatorIndex + 4)
            )
        } else {
            Pair(response, "")
        }
    }

    private fun filterHeaders(headers: String): String {
        if (!desyncMode()) return headers
        return headers.split("\r\n")
            .filterNot { it.startsWith("Connection:", ignoreCase = true) }
            .joinToString("\r\n")
    }

    // Organizer resources

    fun listOrganizerItems(
        domain: String? = null,
        page: Int = 1,
        searchNotes: String? = null,
        searchRequest: String? = null,
        searchResponse: String? = null
    ): Map<String, Any> {
        val allItems = organizerProvider?.getItems() ?: emptyList()
        var filteredItems = allItems

        // Apply domain filter
        if (domain != null) {
            filteredItems = filteredItems.filter { it.host == domain }
        }

        // Apply search filters (case-insensitive)
        if (searchNotes != null) {
            filteredItems = filteredItems.filter { it.notes.contains(searchNotes, ignoreCase = true) }
        }
        if (searchRequest != null) {
            filteredItems = filteredItems.filter { it.request.contains(searchRequest, ignoreCase = true) }
        }
        if (searchResponse != null) {
            filteredItems = filteredItems.filter { it.response.contains(searchResponse, ignoreCase = true) }
        }

        val hasFilters = domain != null || searchNotes != null || searchRequest != null || searchResponse != null

        // Apply sorting and pagination only when filtering
        return if (hasFilters) {
            // Sort by timestamp descending (nulls last), then by ID descending as tiebreaker
            val sortedItems = filteredItems.sortedWith(
                compareByDescending<OrganizerItemData> { it.timeRequestSent }
                    .thenByDescending { it.id }
            )

            val pageSize = 10
            val totalPages = (sortedItems.size + pageSize - 1) / pageSize
            val startIndex = (page - 1) * pageSize
            val pagedItems = sortedItems.drop(startIndex).take(pageSize)

            mapOf(
                "count" to sortedItems.size,
                "page" to page,
                "page_size" to pageSize,
                "total_pages" to totalPages,
                "items" to pagedItems.map { mapOf("id" to it.id) }
            )
        } else {
            mapOf(
                "count" to filteredItems.size,
                "items" to filteredItems.map { mapOf("id" to it.id) }
            )
        }
    }

    fun getOrganizerItem(id: Int, bodyLimit: Int = 100): Map<String, Any?> {
        val items = organizerProvider?.getItemsByIds(setOf(id)) ?: emptyList()
        val item = items.firstOrNull()
            ?: return mapOf("error" to "not_found")

        val (headers, body) = splitResponse(item.response)
        val truncatedBody = TruncatedHttpBody(body, bodyLimit)

        return mapOf(
            "id" to item.id,
            "request" to item.request,
            "response_headers" to filterHeaders(headers),
            "notes" to item.notes,
            "host" to item.host,
            "port" to item.port,
            "secure" to item.secure
        ) + truncatedBody.toResponseFields()
    }

    fun getOrganizerItems(ids: Set<Int>, bodyLimit: Int = 100): Map<String, Any?> {
        val items = organizerProvider?.getItemsByIds(ids) ?: emptyList()

        return mapOf(
            "items" to items.map { item ->
                val (headers, body) = splitResponse(item.response)
                val truncatedBody = TruncatedHttpBody(body, bodyLimit)

                mapOf(
                    "id" to item.id,
                    "request" to item.request,
                    "response_headers" to filterHeaders(headers),
                    "notes" to item.notes,
                    "host" to item.host,
                    "port" to item.port,
                    "secure" to item.secure
                ) + truncatedBody.toResponseFields()
            }
        )
    }

    // Documentation resources

    fun getDoc(topic: String): Map<String, Any?> {
        if (!docTopics.containsKey(topic)) {
            return mapOf("error" to "unknown_topic", "available_topics" to docTopics.keys.toList())
        }

        val content = loadDocContent(topic)
            ?: return mapOf("error" to "doc_not_found")

        return mapOf(
            "topic" to topic,
            "content" to content
        )
    }

    private fun loadDocContent(topic: String): String? =
        loadResourceFile("/$topic.md", listOf("docs/$topic.md", "../docs/$topic.md", "../../docs/$topic.md"))

    // Example script resources

    fun listExamples(): Map<String, Any> {
        return mapOf(
            "examples" to discoveredExamples.sorted().map { name ->
                mapOf("name" to name)
            }
        )
    }

    fun getExample(name: String): Map<String, Any?> {
        if (!discoveredExamples.contains(name)) {
            return mapOf("error" to "not_found", "available_examples" to discoveredExamples.sorted())
        }

        val content = loadExampleContent(name)
            ?: return mapOf("error" to "not_found")

        return mapOf(
            "name" to name,
            "content" to content
        )
    }

    private fun loadExampleContent(name: String): String? =
        loadResourceFile("/examples/$name.py", listOf(
            "resources/examples/$name.py", "../resources/examples/$name.py", "../../resources/examples/$name.py"
        ))

    private fun loadResourceFile(classpathPath: String, filesystemPaths: List<String>): String? {
        javaClass.getResourceAsStream(classpathPath)?.use { return it.bufferedReader().readText() }
        for (path in filesystemPaths) {
            val file = File(path)
            if (file.exists()) return file.readText()
        }
        return null
    }
}
