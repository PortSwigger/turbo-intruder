package burp


class RunHandler (){
    private var running = false
    private var engine: RequestEngine? = null
    private var statusOverride: String? = null
    private var errorFlag: Boolean = false
    @Volatile private var scriptCompleted = false
    var msg: String = ""
    var code: String = ""
    var baseRequest: String = ""
    var rawRequest: ByteArray = "".toByteArray()

    fun hasError(): Boolean = errorFlag

    fun failCount(): Int = engine?.permaFails?.get() ?: 0

    fun lastError(): String? = engine?.lastError

    /** The engine's own account of why the run produced nothing, or null if it has none. */
    fun failureSummary(): String? = engine?.failureSummary()

    fun status(): String {
        if (errorFlag) return "failed"
        val eng = engine
        if (eng != null) {
            return when {
                eng.runState.get() >= 4 -> "completed"
                eng.runState.get() >= 3 -> "exited-early"
                else -> "running"
            }
        }
        return if (scriptCompleted) "completed" else "running"
    }

    fun setComplete() {
        engine?.showStats(-1)
    }

    fun markScriptCompleted() {
        scriptCompleted = true
    }

    fun setRequestEngine(engine: RequestEngine) {
        running = true
        this.engine = engine
    }

    fun statusString(): String {
        if (statusOverride != null){
            return statusOverride!!
        }

        if (engine != null) {
            val engineStatus = engine!!.statusString()
            if (msg.isBlank()) return engineStatus
            val terminal = listOf(" | Completed", " | Cancelled").firstOrNull(engineStatus::endsWith)
            return if (terminal == null) {
                "$engineStatus | $msg"
            } else {
                engineStatus.removeSuffix(terminal) + " | " + msg + terminal
            }
        }

        return "Engine warming up..."
    }

    fun overrideStatus(msg: String, isError: Boolean = true) {
        statusOverride = msg
        errorFlag = isError
    }

    fun setMessage(msg: String) {
        this.msg = msg
    }

    fun abort() {
        running = false
        this.engine?.cancel()
    }
}
