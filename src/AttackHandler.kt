package burp


class AttackHandler {
    private var running = false
    private lateinit var engine: RequestEngine

    fun isRunning(): Boolean {
        return running
    }

    fun setRequestEngine(engine: RequestEngine) {
        running = true
        this.engine = engine
    }

    fun abort() {
        running = false
        this.engine.cancel()
    }
}