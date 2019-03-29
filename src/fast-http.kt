package burp
import java.util.*
import kotlin.concurrent.thread
import kotlin.math.sqrt
import java.awt.*
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.io.*
import javax.swing.*
import org.python.util.PythonInterpreter
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.util.concurrent.ConcurrentHashMap


class Scripts() {
    companion object {
        val SCRIPTENVIRONMENT = """import burp.RequestEngine, burp.Args, string, random, time, math

def mean(data):
    return sum(data)/len(data)

def stddev(data):
    if len(data) == 1:
        return 0
    avg = mean(data)
    base = sum((entry-avg)**2 for entry in data)
    return math.sqrt(base/(len(data)-1))

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

    def __init__(self, endpoint, callback=None, engine=Engine.THREADED, concurrentConnections=50, requestsPerConnection=100, pipeline=False, maxQueueSize=100, timeout=5, maxRetriesPerRequest=3, readCallback=None, readSize = 1024):
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
            if(readCallback != None):
                print('Read callbacks are not supported in the Burp request engine. Try Engine.THREADED instead.')
            self.engine = burp.BurpRequestEngine(endpoint, concurrentConnections, maxQueueSize, maxRetriesPerRequest, callback, readCallback)
        elif(engine == Engine.THREADED):
            self.engine = burp.ThreadedRequestEngine(endpoint, concurrentConnections, maxQueueSize, readFreq, requestsPerConnection, maxRetriesPerRequest, callback, timeout, readCallback, readSize)
        elif(engine == Engine.ASYNC):
            self.engine = burp.AsyncRequestEngine(endpoint, concurrentConnections, readFreq, requestsPerConnection, False, callback)
        elif(engine == Engine.HTTP2):
            self.engine = burp.AsyncRequestEngine(endpoint, concurrentConnections, readFreq, requestsPerConnection, True, callback)
        else:
            print('Unrecognised engine. Valid engines are Engine.BURP, Engine.THREADED')

        handler.setRequestEngine(self.engine)
        self.engine.setOutput(outputHandler)


    def queue(self, template, payloads=None, learn=0, callback=None, gate=None):
        if payloads == None:
            payloads = []
        elif(not isinstance(payloads, list)):
            payloads = [str(payloads)]
        self.engine.queue(template, payloads, learn, callback, gate)


    def openGate(self, gate):
        self.engine.openGate(gate)


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
        Utils.out("Starting attack...")
        val pyInterp = PythonInterpreter() // todo add path to bs4
        handler.code = code
        handler.baseRequest = baseRequest
        pyInterp.set("target", Target(baseRequest, endpoint, baseInput))
        pyInterp.set("wordlists", Wordlist(Bruteforce(), Utils.witnessedWords.savedWords))
        pyInterp.set("handler", handler)
        pyInterp.set("outputHandler", outputHandler)
        pyInterp.set("table", outputHandler)
        if (Utils.gotBurp) {
            pyInterp.set("callbacks", Utils.callbacks)
            pyInterp.set("helpers", Utils.callbacks.helpers)
            pyInterp.setOut(Utils.callbacks.stdout)
            pyInterp.setErr(Utils.callbacks.stderr)
        }
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
            Utils.out("Attack aborted with items waiting to be queued.")
        }
        else {
            var message = ex.cause?.message

            if (message == null) {
                message = ex.toString()
            }
            handler.overrideStatus("Error, check extender for full details: "+message)
            Utils.out("Error launching attack - bad python?")
            Utils.out(stackTrace.toString())
        }
        handler.abort()
    }
}

class OfferTurboIntruder(): IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val options = ArrayList<JMenuItem>()
        if (invocation != null && invocation.selectedMessages[0] != null) {
            val probeButton = JMenuItem("Send to turbo intruder")
            val bounds = invocation.selectionBounds ?: IntArray(0)
            probeButton.addActionListener(TurboIntruderFrame(invocation.selectedMessages[0], bounds))
            options.add(probeButton)
        }
        return options
    }
}

class MessageController(val req: IHttpRequestResponse): IMessageEditorController {
    override fun getResponse(): ByteArray {
        return req.response ?: ByteArray(0)
    }

    override fun getRequest(): ByteArray {
        return req.request
    }

    override fun getHttpService(): IHttpService {
        return req.httpService
    }

}

class TurboIntruderFrame(inputRequest: IHttpRequestResponse, val selectionBounds: IntArray): ActionListener, JFrame("Turbo Intruder - " + inputRequest.httpService.host)  {
    private val req = Utils.callbacks.saveBuffersToTempFiles(inputRequest)



    override fun actionPerformed(e: ActionEvent?) {
        SwingUtilities.invokeLater {
            val outerpane = JPanel(GridBagLayout())
            outerpane.layout = BorderLayout()


            val pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            pane.setDividerLocation(0.25)
            val textEditor = Utils.callbacks.createTextEditor()
            val messageEditor = Utils.callbacks.createMessageEditor(MessageController(req), true)

            var baseInput = ""
            if(!selectionBounds.isEmpty() && selectionBounds[0] != selectionBounds[1]) {
                messageEditor.setMessage(req.request.copyOfRange(0, selectionBounds[0]) + ("%s".toByteArray()) + req.request.copyOfRange(selectionBounds[1], req.request.size), true)
                baseInput = String(req.request.copyOfRange(selectionBounds[0], selectionBounds[1]), Charsets.ISO_8859_1)
            } else {
                messageEditor.setMessage(req.request, true)
            }


            val defaultScript = Utils.callbacks.loadExtensionSetting("defaultScript")
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
                    if (button.text == "Halt") {
                        handler.abort()
                        button.text = "Configure"
                    }
                    else if (button.text == "Configure") {
                        handler.abort()
                        handler = AttackHandler()
                        pane.bottomComponent = textEditor.component
                        pane.setDividerLocation(0.25)
                        button.text = "Attack"
                        this.title = "Turbo Intruder - " + req.httpService.host
                    }
                    else {
                        button.text = "Halt"
                        val requestTable = RequestTable(req.httpService, handler)
                        pane.bottomComponent = requestTable
                        val script = String(textEditor.text)
                        Utils.callbacks.saveExtensionSetting("defaultScript", script)
                        Utils.callbacks.helpers
                        val baseRequest = Utils.callbacks.helpers.bytesToString(messageEditor.message)
                        val service = req.httpService
                        val target = service.protocol + "://" + service.host + ":" + service.port
                        this.title += " - running"
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
        val attackHandler = AttackHandler()
        Runtime.getRuntime().addShutdownHook(Thread {
            Utils.out(attackHandler.statusString())
        })
        Utils.out("Please note that Turbo Intruder's SSL/TLS handling may differ slightly when run outside Burp Suite.")
        val outputHandler = ConsolePrinter()
        evalJython(code, req, endpoint, baseInput, outputHandler, attackHandler)
    }

    catch (e: FileNotFoundException) {
        Utils.out("Couldn't find input file: "+e.message)
    }
    catch (e: ArrayIndexOutOfBoundsException) {
        Utils.out("Missing argument.")
        Utils.out("Usage: java -jar turbo.jar <scriptFile> <baseRequestFile> <endpoint> <baseInput>\n" +
                "Example: java -jar turbo.jar resources/examples/basic.py resources/examples/request.txt https://example.net:443 foobar")
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
