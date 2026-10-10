package mcp.prompt

import mcp.McpResourceHandlers
import mcp.RunManager
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class PromptRegistryTest {

    private fun handlers() = McpResourceHandlers(RunManager())

    @Test
    fun `registry builds specs and honours disabled set`() {
        val registry = PromptRegistry().apply {
            register(*createPromptDefinitions(handlers()).toTypedArray())
        }

        val all = registry.names()
        assertTrue(all.contains("fuzz_parameter"))
        assertTrue(all.contains("race_condition_test"))

        val specs = registry.buildStatelessSpecs(disabled = setOf("fuzz_parameter"))
        val names = specs.map { it.prompt().name() }
        assertFalse(names.contains("fuzz_parameter"))
        assertTrue(names.contains("race_condition_test"))
    }

    @Test
    fun `fuzz_parameter renders the endpoint, parameter and a real example script`() {
        val def = createPromptDefinitions(handlers()).first { it.name == "fuzz_parameter" }

        val text = def.render(mapOf("endpoint" to "https://target.test:443", "param" to "userId"))

        assertTrue(text.contains("https://target.test:443"))
        assertTrue(text.contains("userId"))
        // Sourced from the vetted default example, so it carries the real script entry point.
        assertTrue(text.contains("def queueRequests"))
        assertTrue(text.contains("start_run"))
    }

    @Test
    fun `required arguments are declared`() {
        val def = createPromptDefinitions(handlers()).first { it.name == "fuzz_parameter" }
        val required = def.arguments.filter { it.required }.map { it.name }
        assertTrue(required.contains("endpoint"))
        assertTrue(required.contains("param"))
    }
}
