package burp

import com.google.gson.Gson
import com.google.gson.JsonParser
import java.io.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class Python3Runner(
    private val script: String,
    private val baseRequest: String,
    private val rawRequest: ByteArray,
    private val endpoint: String,
    private val host: String,
    private val baseInput: String,
    private val outputHandler: OutputHandler,
    private val attackHandler: AttackHandler
) {

    @Volatile private var engine: RequestEngine? = null


    private val pendingRpcs = ConcurrentHashMap<String, CompletableFuture<Any?>>()


    private val completedRequests = ConcurrentHashMap<String, Request>()
    private val reqCounter = AtomicInteger(0)


    private val writeQueue = LinkedBlockingQueue<ByteArray>()
    private val POISON = ByteArray(0)

    private lateinit var process: Process
    private lateinit var readerThread: Thread
    private lateinit var writerThread: Thread

    private val started = AtomicBoolean(false)
    private val finished = AtomicBoolean(false)



    fun start() {
        if (!started.compareAndSet(false, true)) return

        val python3 = findPython3()
        val stubPath = extractStub()

        process = ProcessBuilder(python3, "-u", stubPath)
            .redirectError(ProcessBuilder.Redirect.INHERIT)   // CRITICAL: prevents stderr deadlock
            .start()

        readerThread = Thread(::readerLoop, "TI-py3-reader").apply { isDaemon = true; start() }
        writerThread = Thread(::writerLoop, "TI-py3-writer").apply { isDaemon = true; start() }


        send(mapOf(
            "jsonrpc" to "2.0",
            "method"  to "init",
            "params"  to mapOf(
                "script"    to (extractBaseClass() + "\n" + script),
                "req"       to baseRequest,
                "rawReq"    to java.util.Base64.getEncoder().encodeToString(rawRequest),
                "endpoint"  to endpoint,
                "host"      to host,
                "baseInput" to baseInput
            )
        ))
    }

    fun abort() {
        finished.set(true)
        engine?.cancel()
        writeQueue.offer(POISON)
        if (::process.isInitialized) process.destroyForcibly()
    }



    private fun readerLoop() {
        val din = DataInputStream(process.inputStream.buffered(65536))
        try {
            while (!finished.get()) {
                val len = din.readInt()
                if (len <= 0 || len > 16 * 1024 * 1024) {
                    // Utils.out("Python3Runner: invalid frame length $len, aborting")
                    break
                }
                val buf = ByteArray(len)
                din.readFully(buf)
                try {
                    dispatch(parseJson(String(buf, Charsets.UTF_8)))
                } catch (e: Exception) {
                    // Utils.out("Python3Runner: dispatch error: ${e.message}")
                }
            }
        } catch (_: EOFException) {

        } catch (e: Exception) {
            // if (!finished.get()) Utils.out("Python3Runner: reader error: ${e.message}")
        } finally {
            finished.set(true)
        }
    }

    private fun writerLoop() {
        val dout = DataOutputStream(process.outputStream.buffered(65536))
        try {
            while (true) {
                val frame = writeQueue.take()
                if (frame === POISON || frame.isEmpty()) break
                dout.write(frame)
                dout.flush()
            }
        } catch (_: Exception) { /* stream closed */ }
    }



    private fun dispatch(msg: Map<String, Any?>) {
        val id     = msg["id"] as? String
        val method = msg["method"] as? String


        if (id != null && msg.containsKey("result")) {
            pendingRpcs.remove(id)?.complete(msg["result"])
            return
        }

        @Suppress("UNCHECKED_CAST")
        val params = msg["params"] as? Map<String, Any?> ?: emptyMap()

        when (method) {
            "createEngine" -> {
                handleCreateEngine(params)
                if (id != null) send(mapOf("jsonrpc" to "2.0", "id" to id, "result" to "ok"))
            }
            "queue"        -> {
                handleQueue(params)
                if (id != null) send(mapOf("jsonrpc" to "2.0", "id" to id, "result" to "ok"))
            }
            "openGate"     -> {
                engine?.openGate(params["gate"] as String)
                if (id != null) send(mapOf("jsonrpc" to "2.0", "id" to id, "result" to "ok"))
            }
            "complete"     -> {
                // Python called engine.complete(timeout): just ACK immediately.
                // The watcher thread (started in handleCreateEngine) will call showStats
                // and send "done" when the engine actually finishes.
                if (id != null) send(mapOf("jsonrpc" to "2.0", "id" to id, "result" to "ok"))
            }
            "fetchBody"    -> {
                val reqId = params["reqId"] as? String ?: ""
                val body  = completedRequests[reqId]?.response
                    ?.let { java.util.Base64.getEncoder().encodeToString(it.toByteArray(Charsets.ISO_8859_1)) }
                    ?: ""
                if (id != null) send(mapOf("jsonrpc" to "2.0", "id" to id, "result" to body))
            }
            "addResult"    -> {
                val reqId = params["id"] as? String ?: ""
                completedRequests[reqId]?.let { outputHandler.add(it) }
            }
            "applySetting" -> {
                val name = params["name"] as? String ?: return
                val value = params["value"]
                engine?.internalSettings?.set(name, value ?: return)
            }
            "log"          -> Utils.out(params["msg"] as? String ?: "")
        }
    }

    private fun handleCreateEngine(params: Map<String, Any?>) {
        val ep          = params["endpoint"] as? String ?: endpoint
        val connections = (params["concurrentConnections"] as? Number)?.toInt() ?: 50
        val rpc         = (params["requestsPerConnection"] as? Number)?.toInt() ?: 100
        val retries     = (params["maxRetriesPerRequest"] as? Number)?.toInt() ?: 3
        val idle        = (params["idleTimeout"] as? Number)?.toLong() ?: 0L
        val fixCL       = params["fixContentLength"] as? Boolean ?: true
        val engineType  = (params["engine"] as? Number)?.toInt() ?: 2

        val callback: (Request, Boolean) -> Boolean = { req, interesting -> onResponse(req, interesting) }
        val eng = when (engineType) {
            1, 4 -> BurpRequestEngine(ep, connections, 2048, retries, idle, callback, null, false)
            3    -> HTTP2RequestEngine(ep, connections, 2048, rpc, retries, idle, callback, null)
            else -> ThreadedRequestEngine(
                ep, connections, 2048, 1, rpc, retries, idle,
                callback, 20, null, 8192, false
            )
        }
        engine = eng
        eng.setOutput(outputHandler)
        attackHandler.setRequestEngine(eng)
        eng.start(20)

        // Watcher: blocks until engine finishes naturally, then notifies Python
        Thread({
            eng.showStats(-1)   // -1 = wait forever until attackState >= 3
            sendDone()
            finished.set(true)
            attackHandler.setComplete()
        }, "TI-py3-watcher").apply { isDaemon = true; start() }
    }

    private fun handleQueue(params: Map<String, Any?>) {
        val eng = engine ?: run {
            // Utils.out("Python3Runner: queue called before engine created")
            return
        }
        @Suppress("UNCHECKED_CAST")
        val words = (params["words"] as? List<*>)?.map { it as? String } ?: listOf(null)
        val pauseMarkers = params["pauseMarker"]?.let { listOf(it as String) } ?: emptyList()
        eng.queue(
            template = params["template"] as? String ?: "",
            payloads = words,
            learnBoring = (params["learnBoring"] as? Number)?.toInt() ?: 0,
            gateName = params["gate"] as? String,
            label = params["label"] as? String ?: "",
            callback = null,
            pauseBefore = (params["pauseBefore"] as? Number)?.toInt() ?: 0,
            pauseTime = (params["pauseTime"] as? Number)?.toInt() ?: 0,
            pauseMarkers = pauseMarkers,
            delay = (params["delay"] as? Number)?.toLong() ?: 0L,
            endpoint = params["endpoint"] as? String
        )
    }



    fun onResponse(req: Request, interesting: Boolean): Boolean {
        val id = "r${reqCounter.incrementAndGet()}"
        completedRequests[id] = req
        val params = buildMap {
            put("id", id)
            put("status", req.getAttribute("code"))
            put("length", req.getAttribute("length"))
            put("wordcount", req.getAttribute("wordcount"))
            put("linecount", req.getAttribute("linecount"))
            put("time", req.time)
            put("label", req.label)
            put("interesting", interesting)
        }
        send(mapOf("jsonrpc" to "2.0", "method" to "handleResponse", "params" to params))
        return interesting
    }

    fun sendDone() {
        send(mapOf("jsonrpc" to "2.0", "method" to "done"))
    }



    private fun send(msg: Map<String, Any?>) {
        if (finished.get()) return
        val body  = jsonEncode(msg).toByteArray(Charsets.UTF_8)
        val frame = ByteArray(4 + body.size)
        ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN).putInt(body.size)
        body.copyInto(frame, 4)
        writeQueue.offer(frame)
    }


    private val gson = Gson()

    private fun jsonEncode(value: Any?): String = gson.toJson(value)

    @Suppress("UNCHECKED_CAST")
    private fun parseJson(text: String): Map<String, Any?> {
        return try {
            val obj = JsonParser.parseString(text.trim()).asJsonObject
            obj.entrySet().associate { (k, v) -> k to unwrapJsonElement(v) }
        } catch (_: Exception) { emptyMap() }
    }

    private fun unwrapJsonElement(el: com.google.gson.JsonElement): Any? = when {
        el.isJsonNull    -> null
        el.isJsonPrimitive -> {
            val p = el.asJsonPrimitive
            when {
                p.isBoolean -> p.asBoolean
                p.isNumber  -> p.asDouble
                else        -> p.asString
            }
        }
        el.isJsonArray  -> el.asJsonArray.map { unwrapJsonElement(it) }
        el.isJsonObject -> el.asJsonObject.entrySet().associate { (k, v) -> k to unwrapJsonElement(v) }
        else            -> null
    }



    companion object {
        fun findPython3(): String {

            val configured = Utils.callbacks?.loadExtensionSetting("python3Path")
            if (!configured.isNullOrBlank()) return configured


            val isWindows = System.getProperty("os.name", "").lowercase().contains("win")
            val candidates = if (isWindows)
                listOf("py", "python", "python3")
            else
                listOf("python3", "python")

            for (cmd in candidates) {
                try {
                    val p = ProcessBuilder(cmd, "--version")
                        .redirectErrorStream(true)
                        .start()
                    val out = p.inputStream.bufferedReader().readText()
                    if (p.waitFor() == 0 && Regex("Python 3\\.").containsMatchIn(out)) return cmd
                } catch (_: Exception) {}
            }

            throw IllegalStateException(
                "Python 3 not found. Install Python 3 or set the path in Turbo Intruder settings " +
                "(Extensions → Turbo Intruder → Python3 executable path)."
            )
        }


        fun extractStub(): String {
            val resource = Python3Runner::class.java.getResourceAsStream("/turbo_intruder.py")
                ?: throw IllegalStateException("turbo_intruder.py not found in JAR resources")
            val content = resource.readBytes()
            val hash    = content.contentHashCode().toUInt().toString(16)
            val tmpFile = File(System.getProperty("java.io.tmpdir"), "turbo_intruder_$hash.py")
            if (!tmpFile.exists()) tmpFile.writeBytes(content)
            return tmpFile.absolutePath
        }

        fun extractBaseClass(): String {
            val resource = Python3Runner::class.java.getResourceAsStream("/ScriptEnvironment.py")
                ?: return ""
            val content = resource.bufferedReader(Charsets.UTF_8).readText()
            val startMarker = "class _RequestEngineBase:"
            val endMarker = "class RequestEngine(_RequestEngineBase):"
            val startIdx = content.indexOf(startMarker)
            if (startIdx < 0) return ""
            val endIdx = content.indexOf(endMarker, startIdx)
            return if (endIdx > startIdx) content.substring(startIdx, endIdx).trimEnd()
                else ""
        }

        fun isAvailable(): Boolean = try { findPython3(); true } catch (_: Exception) { false }
    }
}


