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

class Scripts() {
    companion object {
        val SCRIPTENVIRONMENT = """import burp.RequestEngine, burp.Args
class RequestEngine:

    def __init__(self, target, callback, async=True, concurrentConnections=50, readFreq=100, requestsPerConnection=100):
        if async:
            self.engine = burp.AsyncRequestEngine(target, int(concurrentConnections), int(readFreq), int(requestsPerConnection), callback)
        else:
            self.engine = burp.ThreadedRequestEngine(target, int(concurrentConnections), int(readFreq), int(requestsPerConnection), callback)

    def queue(self, req):
        self.engine.queue(req)

    def start(self, timeout=5):
        self.engine.start(timeout)

    def complete(self, timeout=-1):
        self.engine.showStats(timeout)
"""

        val SAMPLEBURPSCRIPT = """def queueRequests():
    service = baseRequest.getHttpService()
    engine = RequestEngine(target=service.getProtocol() + "://" + service.getHost() + ":" + str(service.getPort()),
                           callback=handleResponse,
                           async=True,
                           concurrentConnections=50,
                           readFreq=100,
                           requestsPerConnection=100)

    req = helpers.bytesToString(baseRequest.getRequest())
    req = req.replace('Connection: close', 'Connection: keep-alive')
    # req = req.replace('Accept-Encoding: gzip, deflate', 'Accept-Encoding: identity') # disable compression

    for i in range(1000):
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

class BurpExtender(): IBurpExtender {
    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?) {
        callbacks!!.registerContextMenuFactory(OfferTurboIntruder())
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


class TurboIntruderFrame(val req: IHttpRequestResponse): ActionListener, JFrame("Turbo Intruder - " + req.httpService.host)  {
    init {

    }

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
                    req.request = messageEditor.message
                    evalJython(script, req)
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
    val engine = AsyncRequestEngine(url, threads, readFreq, requestsPerConnection, ::handlecallback)
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

fun evalJython(code: String, request: IHttpRequestResponse) {
    val pyInterp = PythonInterpreter()
    pyInterp.set("baseRequest", request) // todo avoid concurrency issues
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

interface RequestEngine {
    fun start(timeout: Int = 10)
    fun showStats(timeout: Int = -1)
    fun queue(req: String)
}