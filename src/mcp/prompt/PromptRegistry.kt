package mcp.prompt

import io.modelcontextprotocol.server.McpStatelessServerFeatures
import io.modelcontextprotocol.spec.McpSchema

/** A single prompt argument the client can fill in. */
data class PromptArg(val name: String, val description: String, val required: Boolean)

/**
 * A guided workflow exposed as an MCP prompt. [render] turns the supplied arguments into a
 * ready-to-use instruction (typically a filled-in start_run invocation) that the agent reviews
 * and submits. Prompts work on the stateless transport, so no session is required.
 */
class PromptDefinition(
    val name: String,
    val description: String,
    val arguments: List<PromptArg>,
    val render: (args: Map<String, Any?>) -> String
)

class PromptRegistry {
    private val prompts = mutableListOf<PromptDefinition>()

    fun register(vararg definitions: PromptDefinition) {
        prompts.addAll(definitions)
    }

    fun definitions(): List<PromptDefinition> = prompts.toList()

    fun names(disabled: Set<String> = emptySet()): List<String> =
        prompts.map { it.name }.filter { it !in disabled }

    fun buildStatelessSpecs(
        disabled: Set<String> = emptySet()
    ): List<McpStatelessServerFeatures.SyncPromptSpecification> =
        prompts.filter { it.name !in disabled }.map { def ->
            val prompt = McpSchema.Prompt(
                def.name,
                null,
                def.description,
                def.arguments.map { McpSchema.PromptArgument(it.name, null, it.description, it.required) }
            )
            McpStatelessServerFeatures.SyncPromptSpecification(prompt) { _, request ->
                val text = def.render(request.arguments())
                McpSchema.GetPromptResult(
                    def.description,
                    listOf(McpSchema.PromptMessage(McpSchema.Role.USER, McpSchema.TextContent(text))),
                    null
                )
            }
        }
}
