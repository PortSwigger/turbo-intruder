package burp
import java.net.URL
import java.util.*
import kotlin.concurrent.thread
import java.awt.*
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.io.*
import javax.swing.*
import org.python.util.PythonInterpreter
import sun.tools.java.SyntaxError
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantReadWriteLock
import java.util.zip.GZIPInputStream
import netscape.javascript.JSObject.getWindow
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.util.concurrent.ConcurrentHashMap


class Scripts() {
    companion object {
        val SCRIPTENVIRONMENT = """import burp.RequestEngine, burp.Args, string, random

def randstr(length=12, allow_digits=True):
    candidates = string.ascii_lowercase
    if allow_digits:
        candidates += string.digits
    return ''.join(random.choice(candidates) for x in range(length))

class Engine:
    BURP = 1
    THREADED = 2
    ASYNC = 3
    HTTP2 = 4


class RequestEngine:

    def __init__(self, endpoint, callback=None, engine=Engine.THREADED, concurrentConnections=50, requestsPerConnection=100, pipeline=False, maxQueueSize=100, timeout=5):
        concurrentConnections = int(concurrentConnections)
        requestsPerConnection = int(requestsPerConnection)

        if not callback:
            callback = handleResponse

        if pipeline > 1:
            readFreq = int(pipeline)
        elif pipeline:
            readFreq = requestsPerConnection
        else:
            readFreq = 1

        if(engine == Engine.BURP):
            if(requestsPerConnection > 1 or pipeline):
                print('requestsPerConnection has been forced to 1 and pipelining has been disabled due to Burp engine limitations')

            self.engine = burp.BurpRequestEngine(endpoint, concurrentConnections, maxQueueSize, callback)
        elif(engine == Engine.THREADED):
            self.engine = burp.ThreadedRequestEngine(endpoint, concurrentConnections, maxQueueSize, readFreq, requestsPerConnection, callback, timeout)
        elif(engine == Engine.ASYNC):
            self.engine = burp.AsyncRequestEngine(endpoint, concurrentConnections, readFreq, requestsPerConnection, False, callback)
        elif(engine == Engine.HTTP2):
            self.engine = burp.AsyncRequestEngine(endpoint, concurrentConnections, readFreq, requestsPerConnection, True, callback)
        else:
            print('Unrecognised engine. Valid engines are Engine.BURP, Engine.THREADED, Engine.ASYNC, Engine.HTTP2')

        handler.setRequestEngine(self.engine)
        self.engine.setOutput(outputHandler)


    def queue(self, template, payload=0, learn=0):
        if payload != 0:
            self.engine.queue(template, payload, learn)
        else:
            self.engine.queue(template)

    def start(self, timeout=5):
        self.engine.start(timeout)

    def complete(self, timeout=-1):
        self.engine.showStats(timeout)
"""

        val SAMPLEBURPSCRIPT = Scripts::class.java.getResource("/examples/default.py").readText()
    }
}


class Target(val req: String, val endpoint: String, val baseInput: String)

class Wordlist(val bruteforce: Bruteforce, val observedWords: ConcurrentHashMap.KeySetView<String, Boolean>)

fun evalJython(code: String, baseRequest: String, endpoint: String, baseInput: String, outputHandler: OutputHandler, handler: AttackHandler) {
    try {
        Utilities.out("Starting attack...")
        val pyInterp = PythonInterpreter()
        pyInterp.set("target", Target(baseRequest, endpoint, baseInput))
        pyInterp.set("wordlists", Wordlist(Bruteforce(), BurpExtender.witnessedWords.savedWords))

        pyInterp.set("handler", handler)
        //pyInterp.set("helpers", BurpExtender.callbacks.helpers)
        pyInterp.set("outputHandler", outputHandler)
        pyInterp.set("table", outputHandler)
        pyInterp.exec(Scripts.SCRIPTENVIRONMENT)
        pyInterp.exec(code)
        pyInterp.exec("queueRequests(target, wordlists)")
        handler.setComplete()
    }
    catch (ex: Exception) {
        val stackTrace = StringWriter()
        ex.printStackTrace(PrintWriter(stackTrace))
        val errorContents = stackTrace.toString()
        if (errorContents.contains("Cannot queue any more items - the attack has finished")) {
            Utilities.out("Attack aborted with items waiting to be queued.")
        }
        else {
            handler.overrideStatus("Error launching attack - check extension output")
            Utilities.out("Error launching attack - bad python?")
            Utilities.out(stackTrace.toString())
        }
        handler.abort()
    }
}

class Utilities() {
    companion object {
        private val CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz" // ABCDEFGHIJKLMNOPQRSTUVWXYZ
        private val START_CHARSET = "ghijklmnopqrstuvwxyz"
        private val rnd = Random()
        var gotBurp = false
        lateinit var out: PrintWriter
        lateinit var err: PrintWriter

        fun decompress(compressed: ByteArray): String {
            try {
                val bis = ByteArrayInputStream(compressed)
                val gis = GZIPInputStream(bis)
                val br = BufferedReader(InputStreamReader(gis, "UTF-8"))
                val sb = StringBuilder()
                var line = br.readLine()
                while (line != null) {
                    sb.append(line)
                    line = br.readLine()
                }
                br.close()
                gis.close()
                bis.close()
                return sb.toString()
            }
            catch (e: IOException) {
                Utilities.out("GZIP decompression failed: "+e)
                Utilities.out("'"+String(compressed)+"'")
                return "GZIP decompression failed"
            }
        }

        fun out(text: String) {
            if (gotBurp) {
                out.println(text)
            }
            else {
                println(text)
            }
        }

        fun err(text: String) {
            if (gotBurp) {
                err.write(text)
            }
            else {
                println(text)
            }
        }

        fun randomString(len: Int): String {
            val sb = StringBuilder(len)
            sb.append(START_CHARSET.get(rnd.nextInt(START_CHARSET.length)))
            for (i in 1 until len)
                sb.append(CHARSET.get(rnd.nextInt(CHARSET.length)))
            return sb.toString()
        }

        fun setBurpPresent() {
            gotBurp = true
            out = PrintWriter(BurpExtender.callbacks.stdout, true)
            err = PrintWriter(BurpExtender.callbacks.stderr, true)
        }
    }
}

class BurpExtender(): IBurpExtender, IExtensionStateListener {

    val version = "1.0"

    override fun extensionUnloaded() {
        unloaded = true
    }

    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks
        var witnessedWords = WordRecorder()
        var unloaded = false
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?) {
        callbacks!!.registerContextMenuFactory(OfferTurboIntruder())
        callbacks.registerScannerCheck(witnessedWords)
        callbacks.registerExtensionStateListener(this)
        callbacks.setExtensionName("Turbo Intruder")
        Companion.callbacks = callbacks
        Utilities.setBurpPresent()
        Utilities.out("Loaded Turbo Intruder v${version}")
    }
}

class OfferTurboIntruder(): IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val options = ArrayList<JMenuItem>()
        if (invocation!!.selectedMessages[0] != null) {
            val probeButton = JMenuItem("Send to turbo intruder")
            probeButton.addActionListener(TurboIntruderFrame(invocation.selectedMessages[0], invocation.selectionBounds))
            options.add(probeButton)
        }
        return options
    }
}


class TurboIntruderFrame(inputRequest: IHttpRequestResponse, val selectionBounds: IntArray): ActionListener, JFrame("Turbo Intruder - " + inputRequest.httpService.host)  {
    private val req = BurpExtender.callbacks.saveBuffersToTempFiles(inputRequest)



    override fun actionPerformed(e: ActionEvent?) {
        SwingUtilities.invokeLater {
            val outerpane = JPanel(GridBagLayout())
            outerpane.layout = BorderLayout()


            val pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            pane.setDividerLocation(0.25)
            val textEditor = BurpExtender.callbacks.createTextEditor()
            val messageEditor = BurpExtender.callbacks.createMessageEditor(null, true)

            var baseInput = ""
            if(!selectionBounds.isEmpty() && selectionBounds[0] != selectionBounds[1]) {
                messageEditor.setMessage(req.request.copyOfRange(0, selectionBounds[0]) + ("%s".toByteArray()) + req.request.copyOfRange(selectionBounds[1], req.request.size), true)
                baseInput = String(req.request.copyOfRange(selectionBounds[0], selectionBounds[1]), Charsets.ISO_8859_1)
            } else {
                messageEditor.setMessage(req.request, true)
            }

            val defaultScript = BurpExtender.callbacks.loadExtensionSetting("defaultScript")
            if (defaultScript == null){
                textEditor.text = Scripts.SAMPLEBURPSCRIPT.toByteArray()
            }
            else {
                textEditor.text = defaultScript.toByteArray()
            }

            textEditor.setEditable(true)

            pane.topComponent = messageEditor.component
            pane.bottomComponent = textEditor.component

            messageEditor.component.preferredSize = Dimension(1000, 150)
            textEditor.component.preferredSize = Dimension(1000, 400)

            val button = JButton("Attack");
            var handler = AttackHandler()

            button.addActionListener {
                thread {
                    if (button.text == "Configure") {
                        handler.abort()
                        handler = AttackHandler()
                        pane.bottomComponent = textEditor.component
                        button.text = "Attack"
                    }
                    else {
                        button.text = "Configure"
                        val requestTable = RequestTable(req.httpService, handler)
                        pane.bottomComponent = requestTable
                        val script = String(textEditor.text)
                        BurpExtender.callbacks.saveExtensionSetting("defaultScript", script)
                        BurpExtender.callbacks.helpers
                        val baseRequest = BurpExtender.callbacks.helpers.bytesToString(messageEditor.message)
                        val service = req.httpService
                        val target = service.protocol + "://" + service.host + ":" + service.port
                        evalJython(script, baseRequest, target, baseInput, requestTable, handler)
                    }
                }
            }

            this.addWindowListener(object : WindowAdapter() {
                override fun windowClosing(e: WindowEvent) {
                    handler.abort()
                    e.getWindow().dispose()
                }
            })


            outerpane.add(pane, BorderLayout.CENTER)
            outerpane.add(button, BorderLayout.SOUTH)

            add(outerpane)
            pack()
            setLocationRelativeTo(getBurpFrame())
            isVisible = true
        }
    }

    fun getBurpFrame(): Frame? {
        return Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
    }
}


fun main(args : Array<String>) {


    try {
        val scriptFile = args[0]
        val code = File(scriptFile).readText()
        val req = File(args[1]).readText()
        val endpoint = args[2]
        val baseInput = args[3]
        val outputHandler = ConsolePrinter()
        val attackHandler = AttackHandler()
        Runtime.getRuntime().addShutdownHook(Thread {
            Utilities.out(attackHandler.statusString())
        })
        evalJython(code, req, endpoint, baseInput, outputHandler, attackHandler)
    }

    catch (e: FileNotFoundException) {
        Utilities.out("Couldn't find input file: "+e.message)
//        File(scriptFile).printWriter().use { out -> out.println(Scripts.SAMPLECOMMANDSCRIPT) }
//        println("Wrote example script to "+scriptFile)
    }
    catch (e: ArrayIndexOutOfBoundsException) {
        Utilities.out("Missing argument.")
        Utilities.out("Usage: java -jar turbo.jar <scriptFile> <baseRequestFile> <endpoint> <baseInput>\n" +
                "Example: java -jar turbo.jar attack.py baseReq.txt https://hackxor.net:443 foobar")
    }
}


class Args(args: Array<String>) {

    companion object {
        lateinit var args: Array<String>
    }

    init {
        Companion.args = args
    }
}
