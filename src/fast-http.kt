package burp

import org.python.util.PythonInterpreter
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Frame
import java.awt.event.*
import java.io.*
import java.io.File
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Paths
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.swing.*
import kotlin.concurrent.thread
import org.fife.ui.rtextarea.*;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rtextarea.RTextScrollPane
import java.io.IOException
import org.fife.ui.rsyntaxtextarea.Theme
import java.io.InputStream





class Scripts() {
    companion object {
        const val SCRIPTENVIRONMENT = """import burp.RequestEngine, burp.Args, string, random, time, math

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

def queueForever(engine, req):
    # infinitely-running bruteforce (a, b ... aaa, aab etc)
    seed = 0
    while True:
        batch = []
        seed = wordlists.bruteforce.generate(seed, 5000, batch)
        for word in batch:
            engine.queue(target.req, word)

class Engine:
    BURP = 1
    THREADED = 2
    ASYNC = 3
    HTTP2 = 4


class RequestEngine:

    def __init__(self, endpoint, callback=None, engine=Engine.THREADED, concurrentConnections=50, requestsPerConnection=100, pipeline=False, maxQueueSize=100, timeout=5, maxRetriesPerRequest=3, readCallback=None, readSize=1024, resumeSSL=True, autoStart=True):
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
            self.engine = burp.ThreadedRequestEngine(endpoint, concurrentConnections, maxQueueSize, readFreq, requestsPerConnection, maxRetriesPerRequest, callback, timeout, readCallback, readSize, resumeSSL)
        elif(engine == Engine.ASYNC):
            self.engine = burp.AsyncRequestEngine(endpoint, concurrentConnections, readFreq, requestsPerConnection, False, callback)
        elif(engine == Engine.HTTP2):
            self.engine = burp.AsyncRequestEngine(endpoint, concurrentConnections, readFreq, requestsPerConnection, True, callback)
        else:
            print('Unrecognised engine. Valid engines are Engine.BURP, Engine.THREADED')

        handler.setRequestEngine(self.engine)
        self.engine.setOutput(outputHandler)
        self.userState = self.engine.userState
        self.autoStart = False
        if autoStart:
            self.autoStart = True
            self.engine.start(5)


    def queue(self, template, payloads=None, learn=0, callback=None, gate=None, label=None):
        if payloads == None:
            payloads = []
        elif(not isinstance(payloads, list)):
            payloads = [str(payloads)]
        self.engine.queue(template, payloads, learn, callback, gate, label)


    def openGate(self, gate):
        self.engine.openGate(gate)

    def start(self, timeout=5):
        if self.autoStart or self.engine.attackState.get() != 0:
            print 'The engine has already started - you no longer need to invoke engine.start() manually. If you prefer to invoke engine.start() manually, set autoStart=False in the constructor'
            return
        self.engine.start(timeout)

    def complete(self, timeout=-1):
        self.engine.showStats(timeout)


"""

        val SAMPLEBURPSCRIPT = Scripts::class.java.getResource("/examples/default.py").readText()
    }
}


class Target(val req: String, val rawreq: ByteArray, val endpoint: String, val baseInput: String)

class Wordlist(val bruteforce: Bruteforce, val observedWords: ConcurrentHashMap.KeySetView<String, Boolean>, val clipboard: ArrayList<String>)

fun evalJython(code: String, baseRequest: String, rawRequest: ByteArray, endpoint: String, baseInput: String, outputHandler: OutputHandler, handler: AttackHandler) {
    try {
        Utils.out("Starting attack...")
        val pyInterp = PythonInterpreter() // todo add path to bs4
        handler.code = code
        handler.baseRequest = baseRequest
        handler.rawRequest = rawRequest
        pyInterp.set("target", Target(baseRequest, rawRequest, endpoint, baseInput))
        pyInterp.set("wordlists", Wordlist(Bruteforce(), Utils.witnessedWords.savedWords, Utils.getClipboard()))
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
            handler.overrideStatus("User Python error, check extender for full details: $message")
            Utils.out("There was an error executing your Python script. This is probably due to a flaw in your script, rather than a bug in Turbo Intruder :)")
            Utils.out("If you think it is a Turbo Intruder issue, try out this script: https://raw.githubusercontent.com/PortSwigger/turbo-intruder/master/resources/examples/debug.py")
            Utils.out("For your convenience, here's the full stack trace:")
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
            probeButton.addActionListener(TurboIntruderFrame(invocation.selectedMessages[0], bounds, null, null))
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

class RecordResize: ComponentAdapter() {
    override fun componentResized(e: ComponentEvent?) {
        super.componentResized(e)
        Utils.setTurboSize(e?.component?.size)
    }

}

class TurboIntruderFrame(inputRequest: IHttpRequestResponse, val selectionBounds: IntArray, val fixedScript: String?, val requestOverride: ByteArray?): ActionListener, JFrame("Turbo Intruder - " + inputRequest.httpService.host)  {
    private val req = Utils.callbacks.saveBuffersToTempFiles(inputRequest)


    private fun getDefaultScript(): String {
        if (fixedScript != null) {
            return fixedScript
        }
        val defaultScript = Utils.callbacks.loadExtensionSetting("defaultScript")
        if (defaultScript == null) {
            return Scripts.SAMPLEBURPSCRIPT
        } else {
            return defaultScript
        }
    }

    override fun actionPerformed(e: ActionEvent?) {
        SwingUtilities.invokeLater {
            val pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            pane.setDividerLocation(0.25)
            pane.addComponentListener(RecordResize())

            val panel = JPanel(BorderLayout())
            val codeCombo = JComboBox<Any>()
            codeCombo.renderer = ComboBoxRenderer(10)
            codeCombo.preferredSize = Dimension(500, 30)
            val loadDirectoryButton = JButton("Choose scripts dir")
            loadDirectoryButton.addActionListener {
                val directoryChooser = JFileChooser()
                directoryChooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
                val option = directoryChooser.showOpenDialog(this)
                if (option == JFileChooser.APPROVE_OPTION) {
                    val file = directoryChooser.selectedFile
                    Utils.callbacks.saveExtensionSetting("scriptsPath", file.absolutePath)
                    readScriptDirectories(codeCombo)
                }
            }
            //val textEditor = Utils.callbacks.createTextEditor()
            //
            // https://github.com/bobbylight/RSyntaxTextArea/issues/269
            javax.swing.text.JTextComponent.removeKeymap("RTextAreaKeymap")
            javax.swing.UIManager.put("RTextAreaUI.inputMap", null)
            javax.swing.UIManager.put("RTextAreaUI.actionMap", null)
            javax.swing.UIManager.put("RSyntaxTextAreaUI.inputMap", null)
            javax.swing.UIManager.put("RSyntaxTextAreaUI.actionMap", null)
            val textEditor = RSyntaxTextArea(20, 60)


            textEditor.isEditable = true
            textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_PYTHON)
            textEditor.antiAliasingEnabled = true
            textEditor.isAutoIndentEnabled = true
            textEditor.paintTabLines = false
            textEditor.tabSize = 4
            textEditor.tabsEmulated = true

            if (UIManager.getLookAndFeel().getID().contains("Dar")) {
                val `in` = javaClass.getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/dark.xml")
                try {
                    val theme = Theme.load(`in`)
                    theme.apply(textEditor)
                } catch (ioe: IOException) {
                    Utils.out(ioe.toString())
                    ioe.printStackTrace()
                }
            }
            else {
                textEditor.highlightCurrentLine = false
            }

            val scrollableTextEditor = JScrollPane(textEditor)

            val saveButton = JButton("Save")
            saveButton.isEnabled = false
            saveButton.addActionListener {
                val comboItem = codeCombo.getSelectedItem();
                if(comboItem is DirectoryItem) {
                    try {
                        Files.write( Paths.get(comboItem.fullPath), textEditor.text.toByteArray());

                    } catch (e: IOException) {
                        System.err.println("Failed to write file:$e")
                    }
                }
            }
            val topPanel = JPanel()
            topPanel.add(codeCombo)
            topPanel.add(loadDirectoryButton)
            topPanel.add(saveButton)
            panel.add(topPanel, BorderLayout.NORTH);
            panel.add(scrollableTextEditor, BorderLayout.CENTER)
            val messageEditor = Utils.callbacks.createMessageEditor(MessageController(req), true)
            var baseInput = ""


            if (fixedScript != null) {
                messageEditor.setMessage(requestOverride?: req.request, true)
            }
            else {
                if (selectionBounds.isNotEmpty() && selectionBounds[0] != selectionBounds[1]) {
                    messageEditor.setMessage(req.request.copyOfRange(0, selectionBounds[0]) + ("%s".toByteArray()) + req.request.copyOfRange(selectionBounds[1], req.request.size), true)
                    baseInput = String(req.request.copyOfRange(selectionBounds[0], selectionBounds[1]), Charsets.ISO_8859_1)
                } else {
                    messageEditor.setMessage(req.request, true)
                }
            }
            textEditor.text = getDefaultScript()
            textEditor.setEditable(true)

            codeCombo.addActionListener {
                if(codeCombo.itemCount > 0 && !(codeCombo.getSelectedItem() is JSeparator)) {
                    if (codeCombo.selectedIndex == 0) {
                        saveButton.isEnabled = false;
                        textEditor.text = getDefaultScript()
                    } else {
                        val fileName = codeCombo.getSelectedItem().toString()
                        if (fileName.startsWith("examples/")) {
                            textEditor.text = Scripts::class.java.getResource("/" + fileName).readText()
                            saveButton.isEnabled = false;
                        } else {
                            saveButton.isEnabled = true;
                            val comboItem = codeCombo.getSelectedItem();
                            if(comboItem is DirectoryItem) {
                                textEditor.text = String(Files.readAllBytes(Paths.get(comboItem.fullPath)));
                            } else {
                                textEditor.text = String(Files.readAllBytes(Paths.get(fileName)));
                            }
                        }
                    }
                }
            }
            readScriptDirectories(codeCombo)
            pane.topComponent = messageEditor.component
            pane.bottomComponent = panel


            val button = JButton("Attack")
            panel.add(button, BorderLayout.SOUTH)

            val turboSize = Utils.getTurboSize()
            messageEditor.component.preferredSize = Dimension(turboSize.width, 200)
            panel.preferredSize = Dimension(turboSize.width, turboSize.height-200)


            var handler = AttackHandler()

            button.addActionListener {
                thread {
                    when {
                        button.text == "Halt" -> {
                            handler.abort()
                            button.text = "Configure"
                        }
                        button.text == "Configure" -> {
                            handler.abort()
                            handler = AttackHandler()
                            SwingUtilities.invokeLater {
                                panel.add(button, BorderLayout.SOUTH)
                                pane.bottomComponent = panel
                                pane.setDividerLocation(0.25)
                                button.text = "Attack"
                                button.requestFocusInWindow()
                                pane.rootPane.defaultButton = button
                                this.title = "Turbo Intruder - " + req.httpService.host
                            }
                        }
                        else -> {
                            val requestTable = RequestTable(req.httpService, handler)
                            SwingUtilities.invokeLater {
                                button.text = "Halt"
                                val requestPanel = JPanel(BorderLayout())
                                panel.remove(button)
                                requestPanel.add(requestTable, BorderLayout.CENTER)
                                requestPanel.add(button, BorderLayout.SOUTH)
                                pane.bottomComponent = requestPanel
                                button.requestFocusInWindow()
                                pane.rootPane.defaultButton = button
                            }
                            var script = textEditor.text

                            // enforce /r/n line endings
                            script = script.replace("\r\n", "\n")
                            script = script.replace("\n", "\r\n")
                            Utils.callbacks.saveExtensionSetting("defaultScript", script)
                            Utils.callbacks.helpers
                            val baseRequest = Utils.callbacks.helpers.bytesToString(messageEditor.message)
                            val service = req.httpService

                            val target: String
                            if (service.host.contains(":")) {
                                target = service.protocol + "://[" + service.host + "]:" + service.port
                            }
                            else {
                                target = service.protocol + "://" + service.host + ":" + service.port
                            }

                            this.title += " - running"
                            evalJython(script, baseRequest, messageEditor.message, target, baseInput, requestTable, handler)
                        }
                    }
                }
            }

            this.addWindowListener(object : WindowAdapter() {
                override fun windowClosing(e: WindowEvent) {
                    handler.abort()
                    e.window.dispose()
                }
            })

            SwingUtilities.invokeLater {
                add(pane)
                pane.rootPane.defaultButton = button
                pack()
                setLocationRelativeTo(getBurpFrame())
                isVisible = true
                button.requestFocus()
                button.requestFocusInWindow()
            }
        }
    }

    fun getBurpFrame(): Frame? {
        return Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
    }
    fun readScriptDirectories( codeCombo : JComboBox<Any>) {
        codeCombo.removeAllItems()
        codeCombo.addItem("Last code used")
        try {
            val scriptsPath = Utils.callbacks.loadExtensionSetting("scriptsPath")
            if (!scriptsPath.isNullOrEmpty()) {
                val folder = File(scriptsPath)
                if (folder.isDirectory) {
                    val folderList = folder.listFiles();
                    Arrays.sort(folderList);
                    for (fileEntry in folderList) {
                        if (!fileEntry.name.startsWith(".")) {
                            codeCombo.addItem(DirectoryItem(folder.absolutePath + "/" + fileEntry.name, fileEntry.name))
                        }
                    }
                }
            }
            codeCombo.addItem( JSeparator(JSeparator.HORIZONTAL))
            val readJar = ReadFromJar()
            val exampleFiles = readJar.getFiles("examples")
            exampleFiles.sort()
            for (fileName in exampleFiles) {
                if (fileName.startsWith(".") || fileName.endsWith("__init__.py")) {
                    continue
                }
                codeCombo.addItem(fileName)
            }
        } catch (e: NoSuchFileException) {
            System.err.println("Error file not found:"+e)
        } catch (e: IOException) {
            System.err.println("Error:"+e)
        }
    }
}


fun main(args : Array<String>) {


    try {
        val scriptFile = args[0]
        val code = File(scriptFile).readText()
        var req = File(args[1]).readText()
        val endpoint = args[2]
        val baseInput = args[3]
        val attackHandler = AttackHandler()
        Runtime.getRuntime().addShutdownHook(Thread {
            Utils.out(attackHandler.statusString())
        })
        Utils.out("Please note that Turbo Intruder's SSL/TLS handling may differ slightly when run outside Burp Suite.")
        if(!req.contains("\r\n")) {
            Utils.out("TURBO NOTICE: The input request appears to be using \\n instead of \\r\\n as a line-ending. Consider changing your text-editor settings. Normalising...")
            req = req.replace("\n", "\r\n")
        }
        val outputHandler = ConsolePrinter()
        evalJython(code, req, File(args[1]).readBytes(), endpoint, baseInput, outputHandler, attackHandler)
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
