package mcp

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper
import io.modelcontextprotocol.json.schema.jackson.JacksonJsonSchemaValidatorSupplier
import io.modelcontextprotocol.server.McpServer
import io.modelcontextprotocol.server.McpStatelessServerFeatures
import io.modelcontextprotocol.server.transport.HttpServletStatelessServerTransport
import io.modelcontextprotocol.spec.McpSchema
import jakarta.servlet.DispatcherType
import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import mcp.resource.QueryParamAwareUriTemplateManagerFactory
import mcp.resource.ResourceRegistry
import mcp.resource.createResourceDefinitions
import org.eclipse.jetty.ee10.servlet.FilterHolder
import org.eclipse.jetty.ee10.servlet.ServletContextHandler
import org.eclipse.jetty.ee10.servlet.ServletHolder
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import java.io.PrintWriter
import java.io.StringWriter
import java.util.EnumSet

/**
 * Formats an exception into a map containing the error message and full stack trace.
 * This is used to provide debugging information in MCP error responses.
 */
fun formatErrorWithStackTrace(e: Exception): Map<String, Any?> {
    val stackTrace = StringWriter().also { sw ->
        e.printStackTrace(PrintWriter(sw))
    }.toString()
    return mapOf(
        "error" to (e.message ?: "Unknown error"),
        "stack_trace" to stackTrace
    )
}

private const val ENABLE_ASYNC_RUN = false

class TurboMcpServer(
    private val port: Int = 31338,
    private val disabledTools: Set<String> = emptySet(),
    private val collaboratorProvider: CollaboratorProvider? = null,
    private val organizerProvider: OrganizerProvider = BurpOrganizerProvider(),
    private val desyncMode: () -> Boolean = { false }
) {
    val manager = RunManager()
    val toolHandlers = McpToolHandlers(manager, organizerProvider, collaboratorProvider)
    val resourceHandlers = McpResourceHandlers(manager, organizerProvider, desyncMode)

    // Resource registry with all resource definitions
    private val resourceRegistry by lazy {
        ResourceRegistry(ObjectMapper()).apply {
            register(*createResourceDefinitions(resourceHandlers).toTypedArray())
        }
    }

    /**
     * Test helper: invoke a resource handler by URI and parse the JSON result.
     */
    fun invokeResourceHandler(uri: String): Map<String, Any?> {
        val def = resourceRegistry.findResource(uri)
            ?: return mapOf("error" to "resource_not_found")
        val params = def.parseParams(uri)
        return def.handler(params)
    }

    private var statelessServer: io.modelcontextprotocol.server.McpStatelessSyncServer? = null
    private var jettyServer: Server? = null
    private val jsonMapper = JacksonMcpJsonMapper(ObjectMapper().apply {
        configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    })

    /**
     * Wraps a tool handler action with error handling that includes stack traces.
     */
    private fun <T> executeToolWithErrorHandling(action: () -> T): McpSchema.CallToolResult {
        return try {
            val result = action()
            McpSchema.CallToolResult.builder()
                .content(listOf(McpSchema.TextContent(jsonMapper.writeValueAsString(result))))
                .isError(false)
                .build()
        } catch (e: Exception) {
            val errorResult = formatErrorWithStackTrace(e)
            McpSchema.CallToolResult.builder()
                .content(listOf(McpSchema.TextContent(jsonMapper.writeValueAsString(errorResult))))
                .isError(true)
                .build()
        }
    }

    fun start() {
        // Fix classloader for ServiceLoader in Burp's environment
        val originalClassLoader = Thread.currentThread().contextClassLoader
        Thread.currentThread().contextClassLoader = this::class.java.classLoader
        try {
            startInternal()
        } finally {
            Thread.currentThread().contextClassLoader = originalClassLoader
        }
    }

    private fun startInternal() {
        // Create Jetty server on specified port
        val jetty = Server()
        val connector = ServerConnector(jetty)
        connector.host = "127.0.0.1"
        connector.port = port
        jetty.addConnector(connector)

        // Set up servlet context
        val context = ServletContextHandler(ServletContextHandler.SESSIONS)
        context.contextPath = "/"

        // Add Host header validation filter to prevent DNS rebinding attacks
        context.addFilter(
            FilterHolder(HostValidationFilter()),
            "/*",
            EnumSet.of(DispatcherType.REQUEST)
        )

        // Stateless HTTP transport - no sessions, simpler client compatibility
        val transport = HttpServletStatelessServerTransport.builder()
            .jsonMapper(jsonMapper)
            .messageEndpoint("/")
            .build()

        context.addServlet(ServletHolder(transport), "/*")
        jetty.handler = context
        jetty.start()
        jettyServer = jetty

        statelessServer = McpServer.sync(transport)
            .jsonMapper(jsonMapper)
            .jsonSchemaValidator(JacksonJsonSchemaValidatorSupplier().get())
            .serverInfo("turbo-simulator", "1.0.0")
            .uriTemplateManagerFactory(QueryParamAwareUriTemplateManagerFactory())
            .capabilities(McpSchema.ServerCapabilities.builder()
                .tools(true)  // listChanged
                .resources(true, true)  // subscribe, listChanged
                .logging()
                .build())
            .tools(buildStatelessToolSpecifications())
            .resources(resourceRegistry.buildStatelessSpecs())
            .build()
    }

    fun stop() {
        statelessServer?.close()
        statelessServer = null
        jettyServer?.stop()
        jettyServer = null
        // The monitor is a daemon, so leaving it running does not hold the JVM open - but it does
        // hold this RunManager, its stored runs, and the classloader that defined the thread's body
        // reachable for ever. One per extension load: fourteen had accumulated in a Burp that was
        // running metaspace at 98.7% full and doing full collections to cope.
        manager.stopMemoryMonitor()
    }

    private val allStatelessTools by lazy {
        listOfNotNull(
            buildStatelessStartRunTool(),
            if (ENABLE_ASYNC_RUN) buildStatelessStartRunAsyncTool() else null,
            buildStatelessStopRunTool(),
            buildStatelessDeleteRunTool(),
            buildStatelessSaveToOrganizerTool(),
            buildStatelessGenerateCollaboratorPayloadTool(),
            buildStatelessGetCollaboratorInteractionsTool(),
            buildStatelessSearchResponsesTool()
        )
    }

    private fun buildStatelessToolSpecifications(): List<McpStatelessServerFeatures.SyncToolSpecification> {
        return allStatelessTools.filter { it.tool().name() !in disabledTools }
    }

    // Stateless tool builders

    private fun buildStatelessStartRunTool(): McpStatelessServerFeatures.SyncToolSpecification {
        val tool = McpSchema.Tool.builder()
            .name("start_run")
            .description("Start a new run and wait for completion. Returns results when complete or on timeout.")
            .inputSchema(jsonMapper, """
            {
                "type": "object",
                "properties": {
                    "script": { "type": "string", "description": "Python script code that controls the run" },
                    "base_request": { "type": "string", "description": "The base HTTP request template with injection points marked as %s" },
                    "endpoint": { "type": "string", "description": "Target endpoint URL (e.g., https://example.com)" },
                    "base_input": { "type": "string", "description": "Input data to feed into the script (e.g., wordlist content)" },
                    "timeout_ms": { "type": "integer", "description": "Timeout in milliseconds (default: 55000). If exceeded, returns run_id for manual polling." },
                    "normalize_line_endings": { "type": "boolean", "description": "Whether to normalize mixed line endings (\\n and \\r\\n) to \\r\\n. Default: true" }
                },
                "required": ["script", "base_request", "endpoint"]
            }
            """.trimIndent())
            .build()

        return McpStatelessServerFeatures.SyncToolSpecification(tool) { _, request ->
            executeToolWithErrorHandling {
                val args = request.arguments()
                toolHandlers.startRun(
                    script = args["script"] as? String ?: "",
                    baseRequest = args["base_request"] as? String ?: "",
                    endpoint = args["endpoint"] as? String ?: "",
                    baseInput = args["base_input"] as? String ?: "",
                    timeoutMs = (args["timeout_ms"] as? Number)?.toLong() ?: 55000,
                    normalizeLineEndings = (args["normalize_line_endings"] as? Boolean) ?: true
                )
            }
        }
    }

    private fun buildStatelessStartRunAsyncTool(): McpStatelessServerFeatures.SyncToolSpecification {
        val tool = McpSchema.Tool.builder()
            .name("start_run_async")
            .description("Start a new run and return immediately. Use turbo://runs/{run_id} resource to poll for status and results.")
            .inputSchema(jsonMapper, """
            {
                "type": "object",
                "properties": {
                    "script": { "type": "string", "description": "Python script code that controls the run" },
                    "base_request": { "type": "string", "description": "The base HTTP request template with injection points marked as %s" },
                    "endpoint": { "type": "string", "description": "Target endpoint URL (e.g., https://example.com)" },
                    "base_input": { "type": "string", "description": "Input data to feed into the script (e.g., wordlist content)" },
                    "normalize_line_endings": { "type": "boolean", "description": "Whether to normalize mixed line endings (\\n and \\r\\n) to \\r\\n. Default: true" }
                },
                "required": ["script", "base_request", "endpoint"]
            }
            """.trimIndent())
            .build()

        return McpStatelessServerFeatures.SyncToolSpecification(tool) { _, request ->
            executeToolWithErrorHandling {
                val args = request.arguments()
                toolHandlers.startRunAsync(
                    script = args["script"] as? String ?: "",
                    baseRequest = args["base_request"] as? String ?: "",
                    endpoint = args["endpoint"] as? String ?: "",
                    baseInput = args["base_input"] as? String ?: "",
                    normalizeLineEndings = (args["normalize_line_endings"] as? Boolean) ?: true
                )
            }
        }
    }

    private fun buildStatelessStopRunTool(): McpStatelessServerFeatures.SyncToolSpecification {
        val tool = McpSchema.Tool.builder()
            .name("stop_run")
            .description("Stop a run. Aborts the run but preserves the results.")
            .inputSchema(jsonMapper, """
            {
                "type": "object",
                "properties": {
                    "run_id": { "type": "string" }
                },
                "required": ["run_id"]
            }
            """.trimIndent())
            .build()

        return McpStatelessServerFeatures.SyncToolSpecification(tool) { _, request ->
            executeToolWithErrorHandling {
                toolHandlers.stopRun(request.arguments()["run_id"] as String)
            }
        }
    }

    private fun buildStatelessDeleteRunTool(): McpStatelessServerFeatures.SyncToolSpecification {
        val tool = McpSchema.Tool.builder()
            .name("delete_run")
            .description("Delete a run and all its results. Also stops the run if it's still executing.")
            .inputSchema(jsonMapper, """
            {
                "type": "object",
                "properties": {
                    "run_id": { "type": "string" }
                },
                "required": ["run_id"]
            }
            """.trimIndent())
            .build()

        return McpStatelessServerFeatures.SyncToolSpecification(tool) { _, request ->
            executeToolWithErrorHandling {
                toolHandlers.deleteRun(request.arguments()["run_id"] as String)
            }
        }
    }

    private fun buildStatelessSaveToOrganizerTool(): McpStatelessServerFeatures.SyncToolSpecification {
        val tool = McpSchema.Tool.builder()
            .name("save_to_organizer")
            .description("Save requests from a run to Burp's Organizer with custom notes.")
            .inputSchema(jsonMapper, """
            {
                "type": "object",
                "properties": {
                    "run_id": { "type": "string" },
                    "items": { "type": "string", "description": "JSON array of objects with request_id (int) and notes (string)" }
                },
                "required": ["run_id", "items"]
            }
            """.trimIndent())
            .build()

        return McpStatelessServerFeatures.SyncToolSpecification(tool) { _, request ->
            executeToolWithErrorHandling {
                val args = request.arguments()
                toolHandlers.saveToOrganizer(
                    runId = args["run_id"] as String,
                    items = args["items"] as? String ?: "[]"
                )
            }
        }
    }

    private fun buildStatelessGenerateCollaboratorPayloadTool(): McpStatelessServerFeatures.SyncToolSpecification {
        val tool = McpSchema.Tool.builder()
            .name("generate_collaborator_payload")
            .description("Generate a Burp Collaborator payload for out-of-band testing. Returns a unique domain that will capture DNS/HTTP/SMTP interactions.")
            .inputSchema(jsonMapper, """
            {
                "type": "object",
                "properties": {
                    "metadata": { "type": "string", "description": "Description of what this payload tests for (e.g., 'SSRF in webhook URL parameter')" }
                },
                "required": ["metadata"]
            }
            """.trimIndent())
            .build()

        return McpStatelessServerFeatures.SyncToolSpecification(tool) { _, request ->
            executeToolWithErrorHandling {
                val args = request.arguments()
                toolHandlers.generateCollaboratorPayload(
                    metadata = args["metadata"] as? String ?: ""
                )
            }
        }
    }

    private fun buildStatelessGetCollaboratorInteractionsTool(): McpStatelessServerFeatures.SyncToolSpecification {
        val tool = McpSchema.Tool.builder()
            .name("get_collaborator_interactions")
            .description("Retrieve Collaborator interactions (DNS lookups, HTTP requests, etc.) for generated payloads. Returns interaction details including type, timestamp, client IP, and protocol-specific data.")
            .inputSchema(jsonMapper, """
            {
                "type": "object",
                "properties": {
                    "payloads": { "type": "array", "items": { "type": "string" }, "description": "Filter to specific payload domains. Omit to get all interactions from this session." }
                }
            }
            """.trimIndent())
            .build()

        return McpStatelessServerFeatures.SyncToolSpecification(tool) { _, request ->
            executeToolWithErrorHandling {
                val args = request.arguments()
                @Suppress("UNCHECKED_CAST")
                val payloads = args["payloads"] as? List<String>
                toolHandlers.getCollaboratorInteractions(payloads)
            }
        }
    }

    private fun buildStatelessSearchResponsesTool(): McpStatelessServerFeatures.SyncToolSpecification {
        val tool = McpSchema.Tool.builder()
            .name("search_responses")
            .description("Search all responses in a run for a specific string. Returns IDs that can be fetched via turbo://runs/{run_id}/{id}")
            .inputSchema(jsonMapper, """
            {
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "run_id": { "type": "string" },
                    "search_in": { "type": "string", "enum": ["all", "labels", "responses"], "description": "Default: all" }
                },
                "required": ["query", "run_id"]
            }
            """.trimIndent())
            .build()

        return McpStatelessServerFeatures.SyncToolSpecification(tool) { _, request ->
            executeToolWithErrorHandling {
                val args = request.arguments()
                toolHandlers.searchResponses(
                    runId = args["run_id"] as String,
                    query = args["query"] as? String ?: "",
                    searchIn = args["search_in"] as? String ?: "all"
                )
            }
        }
    }

    fun getEnabledToolNames(): Set<String> {
        return allStatelessTools
            .filter { it.tool().name() !in disabledTools }
            .map { it.tool().name() }
            .toSet()
    }

}

/**
 * Filter that validates the Host header to prevent DNS rebinding attacks.
 * Only allows requests with Host header set to localhost or 127.0.0.1.
 */
private class HostValidationFilter : Filter {
    companion object {
        private val ALLOWED_HOSTS = setOf(
            "localhost",
            "127.0.0.1"
        )
    }

    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        val httpRequest = request as HttpServletRequest
        val httpResponse = response as HttpServletResponse

        val host = httpRequest.getHeader("Host")?.lowercase()?.substringBefore(":") ?: ""

        if (host in ALLOWED_HOSTS) {
            chain.doFilter(request, response)
        } else {
            httpResponse.status = HttpServletResponse.SC_FORBIDDEN
            httpResponse.writer.write("Forbidden: Invalid Host header")
        }
    }
}

