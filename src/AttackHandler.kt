package burp


class AttackHandler {
    private var running = false
    private var engine: RequestEngine? = null

    fun isRunning(): Boolean {
        return running
    }

    fun hasFinished(): Boolean {
        if (engine == null) {
            return false
        }
        return engine!!.attackState.get() >= 3
    }

    fun setRequestEngine(engine: RequestEngine) {
        running = true
        this.engine = engine
    }

    fun statusString(): String {
        if (engine != null) {
            return engine!!.statusString()
        }
        else {
            return "Engine warming up..."
        }
    }

    fun abort() {
        running = false
        this.engine!!.cancel()
    }
}