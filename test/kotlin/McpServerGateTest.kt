package burp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class McpServerGateTest {

    @Test
    fun `isRunning tracks start and stop, and state changes are notified`() {
        val states = mutableListOf<Boolean>()
        val gate = McpServerGate(
            enabled = { false },
            start = {},
            stop = {},
            onStateChange = { states.add(it) }
        )

        gate.applyInitialState()
        assertFalse(gate.isRunning())

        gate.settingChanged("true")
        assertTrue(gate.isRunning())

        gate.settingChanged("false")
        assertFalse(gate.isRunning())

        assertEquals(listOf(true, false), states)
    }

    @Test
    fun `a failed start leaves the server stopped, reports, and does not notify a state change`() {
        val states = mutableListOf<Boolean>()
        var reported = false
        val gate = McpServerGate(
            enabled = { true },
            start = { throw RuntimeException("port busy") },
            stop = {},
            reportFailure = { _, _ -> reported = true },
            onStateChange = { states.add(it) }
        )

        gate.applyInitialState()

        assertFalse(gate.isRunning())
        assertTrue(reported)
        assertTrue(states.isEmpty())
    }

    @Test
    fun `toggling to the same state does not restart or re-notify`() {
        var startCount = 0
        val states = mutableListOf<Boolean>()
        val gate = McpServerGate(
            enabled = { true },
            start = { startCount++ },
            stop = {},
            onStateChange = { states.add(it) }
        )

        gate.applyInitialState()
        gate.settingChanged("true")

        assertEquals(1, startCount)
        assertEquals(listOf(true), states)
    }
}
