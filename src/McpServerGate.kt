package burp

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Decides when the MCP server runs.
 *
 * The server is an unauthenticated local endpoint that lets any process on the machine drive
 * requests through Turbo Intruder, so it stays off until someone asks for it. Keeping the decision
 * here — rather than inline in extension startup — is also what makes it testable without Burp.
 */
class McpServerGate(
    private val enabled: () -> Boolean,
    private val start: () -> Unit,
    private val stop: () -> Unit,
    private val reportFailure: (String, Exception) -> Unit = { _, _ -> },
) {
    companion object {
        const val SETTING = "enable unsafe MCP server"
        const val DESCRIPTION =
            "UNSAFE: exposes an unauthenticated MCP server on http://localhost:31337 that lets " +
                "any local process run scripts and drive arbitrary HTTP requests through Turbo Intruder. " +
                "Off by default."
    }

    private val lifecycleLock = Any()
    private val desiredRunning = AtomicReference<Boolean?>(null)
    private val shutdownRequested = AtomicBoolean(false)
    private var running = false

    /** Applies whatever the setting says at extension load. */
    fun applyInitialState() {
        desiredRunning.compareAndSet(null, enabled())
        reconcileState()
    }

    /** Responds to the setting being toggled while Burp is running. */
    fun settingChanged(value: String?) {
        desiredRunning.set(value == "true")
        reconcileState()
    }

    /** Stops the server during extension unload through the same serialized lifecycle. */
    fun shutdown() {
        shutdownRequested.set(true)
        desiredRunning.set(false)
        reconcileState()
    }

    private fun reconcileState() {
        synchronized(lifecycleLock) {
            val shouldRun = !shutdownRequested.get() && desiredRunning.get() == true
            if (shouldRun == running) {
                return
            }

            try {
                if (shouldRun) {
                    start()
                    running = true
                } else {
                    stop()
                    running = false
                }
            } catch (e: Exception) {
                runCatching {
                    reportFailure(
                        if (shouldRun) "Failed to start MCP server" else "Failed to stop MCP server",
                        e,
                    )
                }
            }
        }
    }
}
