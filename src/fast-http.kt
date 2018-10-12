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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantReadWriteLock
import java.util.zip.GZIPInputStream

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

    def __init__(self, target, callback, engine=Engine.THREADED, concurrentConnections=50, requestsPerConnection=100, pipeline=False):
        concurrentConnections = int(concurrentConnections)
        requestsPerConnection = int(requestsPerConnection)

        if pipeline > 1:
            readFreq = int(pipeline)
        elif pipeline:
            readFreq = requestsPerConnection
        else:
            readFreq = 1

        if(engine == Engine.BURP):
            if(requestsPerConnection > 1 or pipeline):
                print('requestsPerConnection has been forced to 1 and pipelining has been disabled due to Burp engine limitations')

            self.engine = burp.BurpRequestEngine(target, concurrentConnections, callback)
        elif(engine == Engine.THREADED):
            self.engine = burp.ThreadedRequestEngine(target, concurrentConnections, readFreq, requestsPerConnection, callback)
        elif(engine == Engine.ASYNC):
            self.engine = burp.AsyncRequestEngine(target, concurrentConnections, readFreq, requestsPerConnection, False, callback)
        elif(engine == Engine.HTTP2):
            self.engine = burp.AsyncRequestEngine(target, concurrentConnections, readFreq, requestsPerConnection, True, callback)
        else:
            print('Unrecognised engine. Valid engines are Engine.BURP, Engine.THREADED, Engine.ASYNC, Engine.HTTP2')

        handler.setRequestEngine(self.engine)


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

        val SAMPLEBURPSCRIPT = """def queueRequests():
    engine = RequestEngine(target=target,
                           callback=handleResponse,
                           engine=Engine.BURP,  # {BURP, THREADED, ASYNC, HTTP2}
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=True
                           )

    req = helpers.bytesToString(baseRequest)

    for i in range(3):
        engine.queue(req, randstr(4+i), learn=1)
        engine.queue(req, baseInput, learn=2)
        engine.queue(req, "."+randstr(4), learn=3)

    for word in observedWords:
        engine.queue(req, word)

    for line in open('/Users/james/Dropbox/lists/discovery/PredictableRes/raft-large-words-lowercase.txt'):
        if line not in observedWords:
            engine.queue(req, line.rstrip())

    engine.start(timeout=5)
    engine.complete(timeout=60)


def handleResponse(req, interesting):
    if interesting:
        table.add(req)
"""

        val SAMPLECOMMANDSCRIPT = """
from urlparse import urlparse

def handleResponse(req, resp):
    code = resp.split(' ', 2)[1]
    if code != '404':
        print(code + ': '+req.split('\r', 1)[0])

def queueRequests():
    args = burp.Args.args

    engine = RequestEngine(target=args[2],
                           callback=handleResponse,
                           async=True,
                           concurrentConnections=args[4],
                           readFreq=args[5],
                           requestsPerConnection=args[5])

    engine.start(timeout=10)

    with open(urlfile) as file:
        for line in file:
            url = urlparse(line.rstrip())
            engine.queue('GET %s?%s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n' % (url.path, url.query, url.netloc))

    engine.complete(timeout=60)


queueRequests()
"""
    }
}

fun evalJython(code: String, baseRequest: String, target: String, baseInput: String, outputTable: RequestTable, handler: AttackHandler) {
    Utilities.out("Starting attack...")
    val pyInterp = PythonInterpreter()
    pyInterp.set("baseRequest", baseRequest) // todo avoid concurrency issues
    pyInterp.set("handler", handler)
    pyInterp.set("target", target)
    pyInterp.set("helpers", BurpExtender.callbacks.helpers)
    pyInterp.set("baseInput", baseInput)
    pyInterp.set("observedWords", BurpExtender.witnessedWords.savedWords)
    pyInterp.set("table", outputTable)
    pyInterp.exec(Scripts.SCRIPTENVIRONMENT)
    pyInterp.exec(code)
    pyInterp.exec("queueRequests()")
    Utilities.out("Attack completed")
}

fun jythonSend(scriptFile: String) {
    try {
        val pyInterp = PythonInterpreter()
        pyInterp.exec(Scripts.SCRIPTENVIRONMENT)
        pyInterp.exec(File(scriptFile).readText())
    }
    catch (e: FileNotFoundException) {
        File(scriptFile).printWriter().use { out -> out.println(Scripts.SAMPLECOMMANDSCRIPT) }
        Utilities.out("Wrote example script to "+scriptFile);
    }
}


class Utilities() {
    companion object {
        private val CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz" // ABCDEFGHIJKLMNOPQRSTUVWXYZ
        private val START_CHARSET = "ghijklmnopqrstuvwxyz"
        private val rnd = Random()
        private val out = PrintWriter(BurpExtender.callbacks.stdout, true)
        private val err = PrintWriter(BurpExtender.callbacks.stderr, true)

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
            out.println(text)
        }

        fun err(text: String) {
            err.write(text)
        }

        fun randomString(len: Int): String {
            val sb = StringBuilder(len)
            sb.append(START_CHARSET.get(rnd.nextInt(START_CHARSET.length)))
            for (i in 1 until len)
                sb.append(CHARSET.get(rnd.nextInt(CHARSET.length)))
            return sb.toString()
        }
    }
}

class BurpExtender(): IBurpExtender, IExtensionStateListener {
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
            if(!selectionBounds.isEmpty()) {
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
            val handler = AttackHandler()

            button.addActionListener {
                thread {
                    if (handler.isRunning()) {
                        handler.abort()
                        pane.bottomComponent = textEditor.component
                        button.text = "Attack"
                    }
                    else {
                        button.text = "Configure"
                        val requestTable = RequestTable(req.httpService)
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
    val scriptFile = args[0]
    Args.args = args
    jythonSend(scriptFile)
}

class Args(args: Array<String>) {

    companion object {
        lateinit var args: Array<String>
    }

    init {
        Companion.args = args
    }
}
