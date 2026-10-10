package mcp.prompt

import mcp.McpResourceHandlers

/**
 * Built-in prompts. Each renders a ready-to-use start_run plan whose script is one of the vetted
 * examples under resources/examples/, fetched through [resourceHandlers] so a prompt and the
 * turbo://examples/{name} resource can never drift apart.
 */
fun createPromptDefinitions(resourceHandlers: McpResourceHandlers): List<PromptDefinition> {

    fun exampleScript(name: String): String =
        (resourceHandlers.getExample(name)["content"] as? String)
            ?: "# Example '$name' not found; see turbo://examples for the current list."

    fun plan(endpoint: String, injectionNote: String, script: String): String = buildString {
        append("Call the start_run tool (or start_run_async for a long run) with:\n\n")
        append("- endpoint: $endpoint\n")
        append("- base_request: a raw HTTP request to the target. $injectionNote\n")
        append("- script: the Python below.\n\n")
        append("```python\n")
        append(script.trimEnd())
        append("\n```\n\n")
        append("Then read turbo://runs/current/summary for the ranked results, and use ")
        append("report_finding to record anything confirmed.")
    }

    return listOf(
        PromptDefinition(
            name = "fuzz_parameter",
            description = "Fuzz a single request parameter with a wordlist and surface anomalous responses.",
            arguments = listOf(
                PromptArg("endpoint", "Target endpoint, e.g. https://example.com:443", true),
                PromptArg("param", "Name of the parameter to fuzz", true)
            ),
            render = { args ->
                val endpoint = (args["endpoint"] as? String)?.ifBlank { null } ?: "https://example.com:443"
                val param = (args["param"] as? String)?.ifBlank { null } ?: "q"
                plan(
                    endpoint,
                    "Mark the value of the `$param` parameter with %s as the injection point.",
                    exampleScript("default")
                )
            }
        ),
        PromptDefinition(
            name = "race_condition_test",
            description = "Run a single-packet-attack race-condition test, sending many requests as close to simultaneously as possible.",
            arguments = listOf(
                PromptArg("endpoint", "Target endpoint, e.g. https://example.com:443", true),
                PromptArg("requests", "How many requests to race (default 20)", false)
            ),
            render = { args ->
                val endpoint = (args["endpoint"] as? String)?.ifBlank { null } ?: "https://example.com:443"
                plan(
                    endpoint,
                    "Use the state-changing request you want to race; no %s injection point is required.",
                    exampleScript("race-single-packet-attack")
                )
            }
        )
    )
}
