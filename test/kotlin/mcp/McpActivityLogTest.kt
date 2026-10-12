package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class McpActivityLogTest {

    @Test
    fun `log is bounded to capacity, dropping oldest`() {
        val log = McpActivityLog(capacity = 10)
        repeat(50) { log.record("m$it") }

        assertEquals(10, log.size())
        val snap = log.snapshot()
        assertEquals("m40", snap.first().message)
        assertEquals("m49", snap.last().message)
    }

    @Test
    fun `concurrent appends never exceed capacity`() {
        val log = McpActivityLog(capacity = 100)
        val threads = (1..8).map { t ->
            Thread { repeat(1000) { log.record("t$t-$it") } }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        assertEquals(100, log.size())
    }

    @Test
    fun `listeners receive recorded entries`() {
        val log = McpActivityLog()
        val received = mutableListOf<String>()
        log.addListener { received.add(it.message) }

        log.record("start_run run=1")

        assertEquals(listOf("start_run run=1"), received)
    }
}
