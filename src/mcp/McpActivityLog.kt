package mcp

/** One recorded MCP activity line (tool call, lifecycle event). */
data class ActivityEntry(val timestamp: Long, val message: String)

/**
 * A bounded, thread-safe log of recent MCP activity for the control UI. Handler threads append
 * from any thread; the oldest entries are dropped past [capacity] so this can never grow unbounded
 * (the run manager already guards heap elsewhere, and this must not reintroduce a leak).
 */
class McpActivityLog(private val capacity: Int = 500) {
    private val entries = ArrayDeque<ActivityEntry>()
    private val lock = Any()
    private val listeners = mutableListOf<(ActivityEntry) -> Unit>()

    fun record(message: String) {
        val entry = ActivityEntry(System.currentTimeMillis(), message)
        synchronized(lock) {
            entries.addLast(entry)
            while (entries.size > capacity) entries.removeFirst()
        }
        // Snapshot listeners under the lock, invoke outside it.
        val current = synchronized(lock) { listeners.toList() }
        current.forEach { runCatching { it(entry) } }
    }

    fun snapshot(): List<ActivityEntry> = synchronized(lock) { entries.toList() }

    fun size(): Int = synchronized(lock) { entries.size }

    fun addListener(listener: (ActivityEntry) -> Unit) {
        synchronized(lock) { listeners.add(listener) }
    }

    fun clear() {
        synchronized(lock) { entries.clear() }
    }
}
