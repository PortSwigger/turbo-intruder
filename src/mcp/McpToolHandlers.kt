package mcp

import burp.Utils
import burp.evalJython
import com.fasterxml.jackson.databind.ObjectMapper
import kotlin.concurrent.thread

class McpToolHandlers(
    private val manager: RunManager,
    private val organizerProvider: OrganizerProvider = BurpOrganizerProvider(),
    private val collaboratorProvider: CollaboratorProvider? = null
) {

    fun setOrganizerNotes(id: Int, notes: String): Map<String, String> {
        val success = organizerProvider.setNotes(id, notes)
        return if (success) {
            mapOf("status" to "success")
        } else {
            mapOf("error" to "not_found")
        }
    }

    fun generateCollaboratorPayload(metadata: String): Map<String, Any?> {
        val provider = collaboratorProvider
            ?: return mapOf("error" to "Collaborator requires Burp Suite connection")
        val payload = provider.generatePayload(metadata)
        return mapOf("payload" to payload)
    }

    fun getCollaboratorInteractions(payloads: List<String>?): Map<String, Any> {
        val provider = collaboratorProvider
            ?: return mapOf("error" to "Collaborator requires Burp Suite connection", "interactions" to emptyList<Any>())
        val interactions = provider.getInteractions(payloads)
        return mapOf(
            "interactions" to interactions.map { interaction ->
                mapOf(
                    "payload" to interaction.payload,
                    "metadata" to interaction.metadata,
                    "type" to interaction.type,
                    "timestamp" to interaction.timestamp,
                    "client_ip" to interaction.clientIp,
                    "details" to interaction.details
                )
            }
        )
    }

    private fun runNotFoundMessage(runId: String): String {
        return if (manager.isEvicted(runId)) "Run was evicted to free memory" else "No run found"
    }

    fun saveToOrganizer(runId: String, items: String): Map<String, Any> {
        val run = manager.getRun(runId)
            ?: return mapOf("saved" to emptyList<Int>(), "errors" to listOf(mapOf("error" to runNotFoundMessage(runId))))

        val mapper = ObjectMapper()
        val itemList = mapper.readTree(items)

        val saved = mutableListOf<Int>()
        val errors = mutableListOf<Map<String, Any>>()

        val runIdSection = "\n\nRun ID: ${run.id}"

        val scriptSection = if (run.handler.code.isNotBlank()) {
            "\n\n--- Script ---\n${run.handler.code}"
        } else ""

        for (item in itemList) {
            val requestId = item.get("request_id").asInt()
            val notes = item.get("notes").asText()
            val request = run.store.getRequest(requestId)
            if (request == null) {
                errors.add(mapOf("request_id" to requestId, "error" to "Request not found"))
                continue
            }
            organizerProvider.sendToOrganizer(request, notes + runIdSection + scriptSection)
            saved.add(requestId)
        }

        return mapOf("saved" to saved, "errors" to errors)
    }

    fun startRun(
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String,
        timeoutMs: Long = 55000,
        normalizeLineEndings: Boolean = true
    ): Map<String, Any?> {
        val normalized = normalizeScriptLineEndings(script, normalizeLineEndings)
        val run = manager.startRun()
        launchRun(run, normalized.script, baseRequest, endpoint, baseInput)

        // Wait for completion or timeout
        val startTime = System.currentTimeMillis()
        while (run.handler.status() == "running") {
            if (System.currentTimeMillis() - startTime > timeoutMs) {
                val result = mutableMapOf<String, Any?>(
                    "status" to "running",
                    "message" to "The run is still executing. Read turbo://runs/${run.id}?wait=true to long-poll until completion.",
                    "run_id" to run.id,
                    "status_message" to run.handler.statusString(),
                    "result_count" to run.store.count(),
                    "fails" to run.handler.failCount(),
                    "created_at" to run.createdAt
                )
                normalized.warning?.let { result["warning"] = it }
                return result
            }
            Thread.sleep(50)
        }

        // Get results sorted by anomaly rank descending
        val status = run.handler.status()
        val results = run.store.getResults(burp.SortField.ANOMALY_RANK, true, 100, 0)
        val result = mutableMapOf<String, Any?>(
            "status" to status,
            "run_id" to run.id,
            "result_count" to run.store.count(),
            "fails" to run.handler.failCount(),
            "results" to results.map { it.toSummaryMap() }
        )
        if (status == "failed") {
            result["error_message"] = run.handler.statusString()
        } else if (run.store.count() == 0 && run.handler.failCount() > 0) {
            // The engine composes this so that a client here and a user watching the GUI status
            // line are told the same thing: an HTTP/3 run that never got a handshake through says
            // so, rather than both layers spelling out a connection error their own way.
            result["error_message"] = run.handler.failureSummary()
                ?: "All ${run.handler.failCount()} requests failed with connection errors"
        }
        normalized.warning?.let { result["warning"] = it }
        return result
    }

    fun startRunAsync(
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String,
        normalizeLineEndings: Boolean = true
    ): Map<String, Any?> {
        val normalized = normalizeScriptLineEndings(script, normalizeLineEndings)
        val run = manager.startRun()
        launchRun(run, normalized.script, baseRequest, endpoint, baseInput)
        val result = mutableMapOf<String, Any?>("status" to "started", "run_id" to run.id)
        normalized.warning?.let { result["warning"] = it }
        return result
    }

    fun stopRun(runId: String): Map<String, String> {
        return mapOf("status" to manager.stopRun(runId))
    }

    fun deleteRun(runId: String): Map<String, String> {
        return mapOf("status" to manager.deleteRun(runId))
    }

    fun searchResponses(runId: String, query: String, searchIn: String = "all"): Map<String, Any> {
        val run = manager.getRun(runId)
            ?: return mapOf("error" to runNotFoundMessage(runId))

        val matches = run.store.getAllRquests()
            .filter { req ->
                when (searchIn) {
                    "labels" -> req.label.contains(query)
                    "responses" -> req.response?.contains(query) == true
                    else -> req.response?.contains(query) == true || req.label.contains(query)
                }
            }
            .map { it.id }

        val result = mutableMapOf<String, Any>(
            "matches" to matches,
            "match_count" to matches.size
        )

        if (run.responsesStripped && searchIn != "labels") {
            result["warning"] = "Response bodies have been stripped from this run to free memory. Only label search is available."
        }

        return result
    }

    private fun launchRun(
        run: ActiveRun,
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String
    ) {
        val host = endpoint
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore(":")
            .substringBefore("/")

        val normalizedRequest = Utils.normalizeLineEndings(baseRequest)

        thread {
            try {
                evalJython(
                    code = script,
                    baseRequest = normalizedRequest,
                    rawRequest = normalizedRequest.toByteArray(Charsets.ISO_8859_1),
                    endpoint = endpoint,
                    host = host,
                    baseInput = baseInput,
                    store = run.store,
                    handler = run.handler,
                    reqs = null,
                    requestTable = null
                )
            } catch (e: Exception) {
                System.err.println("Run ${run.id} failed: ${e.message}")
            } finally {
                run.handler.markScriptCompleted()
            }
        }
    }
}
