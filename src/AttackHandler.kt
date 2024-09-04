package burp


class AttackHandler (){
    private var running = false
    private var engine: RequestEngine? = null
    private var statusOverride: String? = null
    var msg: String = ""
    var code: String = ""
    var baseRequest: String = ""
    var rawRequest: ByteArray = "".toByteArray()

    fun isRunning(): Boolean {
        return running
    }

    fun setComplete() {
        engine?.showStats(-1)
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
        if (statusOverride != null){
            return statusOverride!!
        }

        if (engine != null) {
            return engine!!.statusString() + " | "+msg
        }

        return "Engine warming up..."
    }

    fun overrideStatus(msg: String) {
        statusOverride = msg
    }

    fun setMessage(msg: String) {
        this.msg = msg
    }

    fun abort() {
        running = false
        this.engine?.cancel()
    }
}