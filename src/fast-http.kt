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
import java.util.zip.GZIPInputStream

class Scripts() {
    companion object {
        val SCRIPTENVIRONMENT = """import burp.RequestEngine, burp.Args

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


    def queue(self, req):
        self.engine.queue(req)

    def start(self, timeout=5):
        self.engine.start(timeout)

    def complete(self, timeout=-1):
        self.engine.showStats(timeout)
"""

        val SAMPLEBURPSCRIPT = """def queueRequests():
    engine = RequestEngine(target=target,
                           callback=handleResponse,
                           engine=Engine.BURP,  # {BURP, THREADED, ASYNC, HTTP2}
                           concurrentConnections=100,
                           requestsPerConnection=100,
                           pipeline=True
                           )

    req = helpers.bytesToString(baseRequest)

    for i in range(2000):
        engine.queue(req)

    engine.start(timeout=10)
    engine.complete(timeout=10)


def handleResponse(req, resp):
    code = resp.split(' ', 2)[1]
    if code != '404':
        print(code + ': '+req.split('\r', 1)[0])


queueRequests()"""

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


class Utilities() {
    companion object {
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
                println("GZIP decompression failed")
                return "GZIP decompression failed"
            }
        }
    }
}

class BurpExtender(): IBurpExtender, IExtensionStateListener {
    override fun extensionUnloaded() {
        unloaded = true
    }

    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks
        var unloaded = false
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?) {
        callbacks!!.registerContextMenuFactory(OfferTurboIntruder())
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
            probeButton.addActionListener(TurboIntruderFrame(invocation.selectedMessages[0]))
            options.add(probeButton)
        }
        return options
    }
}


class TurboIntruderFrame(inputRequest: IHttpRequestResponse): ActionListener, JFrame("Turbo Intruder - " + inputRequest.httpService.host)  {
    private val req = BurpExtender.callbacks.saveBuffersToTempFiles(inputRequest)

    override fun actionPerformed(e: ActionEvent?) {
        SwingUtilities.invokeLater {
            val outerpane = JPanel(GridBagLayout())
            val pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            val textEditor = BurpExtender.callbacks.createTextEditor()
            val messageEditor = BurpExtender.callbacks.createMessageEditor(null, true)
            messageEditor.setMessage(req.request, true)

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

            messageEditor.component.preferredSize = Dimension(1280, 200);
            textEditor.component.preferredSize = Dimension(1280, 600);

            val button = JButton("Attack");

            button.addActionListener {
                thread {
                    val script = String(textEditor.text)
                    BurpExtender.callbacks.saveExtensionSetting("defaultScript", script)
                    BurpExtender.callbacks.helpers
                    val baseRequest = BurpExtender.callbacks.helpers.bytesToString(messageEditor.message)
                    val service = req.httpService
                    val target = service.protocol + "://" + service.host + ":" + service.port
                    evalJython(script, baseRequest, target)
                }
            }

            val c =  GridBagConstraints();
            outerpane.add(pane, c)
            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridx = 0
            c.gridy = 1
            outerpane.add(button, c)

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

    //    val url = args[0]
//    val urlfile = args[1]
//    val threads = args[2].toInt()
//    val requestsPerConnection = args[3].toInt()
//    var readFreq = requestsPerConnection
//    if (args.size > 4) {
//        readFreq = args[4].toInt();
//    }
    //javaSend(url, urlfile, threads, requestsPerConnection, readFreq)
}

fun handlecallback(req: String, resp: String): Boolean {
    val status = resp.split(" ")[1].toInt()
    if (status != 404 && status != 401) {
        println("" + status + ": " + req.split("\n")[0])
        // println(resp)
    }

    return true
}

fun javaSend(url: String, urlfile: String, threads: Int, requestsPerConnection: Int, readFreq: Int) {
    var target: URL
    val engine = ThreadedRequestEngine(url, threads, readFreq, requestsPerConnection, ::handlecallback)
    engine.start()

    val inputStream: InputStream = File(urlfile).inputStream()
    val lines = inputStream.bufferedReader().readLines()
    var requests = 0
    for(line in lines) {
        requests++
        target = URL(line);
        engine.queue("GET ${target.path}?${target.query} HTTP/1.1\r\n"
                +"Host: ${target.host}\r\n"
                +"Connection: keep-alive\r\n"
                +"\r\n")
    }

    engine.showStats()
}

fun evalJython(code: String, baseRequest: String, target: String) {
    val pyInterp = PythonInterpreter()
    pyInterp.set("baseRequest", baseRequest) // todo avoid concurrency issues
    pyInterp.set("target", target)
    pyInterp.set("helpers", BurpExtender.callbacks.helpers)
    pyInterp.exec(Scripts.SCRIPTENVIRONMENT)
    pyInterp.exec(code)
}

fun jythonSend(scriptFile: String) {
    try {
        val pyInterp = PythonInterpreter()
        pyInterp.exec(Scripts.SCRIPTENVIRONMENT)
        pyInterp.exec(File(scriptFile).readText())
    }
    catch (e: FileNotFoundException) {
        File(scriptFile).printWriter().use { out -> out.println(Scripts.SAMPLECOMMANDSCRIPT) }
        System.out.println("Wrote example script to "+scriptFile);
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


class Request(val template: String, val word: String?) {

    constructor(template: String): this(template, null)

    fun getRequest(): String {
        if (word == null) {
            return template
        }

        return template.replace("%s", word)
    }
}

abstract class RequestEngine {
    var start: Long = 0
    var successfulRequests = AtomicInteger(0)
    val attackState = AtomicInteger(0) // 0 = connecting, 1 = live, 2 = fully queued
    lateinit var completedLatch: CountDownLatch

    abstract fun start(timeout: Int = 10)
    abstract fun queue(req: String)

    open fun showStats(timeout: Int = -1) {
        attackState.set(2)
        val success = completedLatch.await(timeout.toLong(), TimeUnit.SECONDS)
        if (!success) {
            println("Aborting attack due to timeout")
            attackState.set(3)
        }
        showSummary()
    }

    fun showSummary() {
        val duration = System.nanoTime().toFloat() - start
        val requests = successfulRequests.get().toFloat()
        println("Sent " + requests.toInt() + " requests in "+duration / 1000000000 + " seconds")
        System.out.printf("RPS: %.0f\n", requests / (duration / 1000000000))
    }
}