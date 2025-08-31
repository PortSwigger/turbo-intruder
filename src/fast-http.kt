package burp

import burp.api.montoya.http.message.HttpRequestResponse
import org.fife.ui.rsyntaxtextarea.*
import org.fife.ui.rtextarea.*
import org.python.util.PythonInterpreter
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Frame
import java.awt.GridBagLayout
import java.awt.GridBagConstraints
import java.awt.Insets
import java.awt.FlowLayout
import java.awt.event.*
import java.io.*
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Paths
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.swing.*
import kotlin.concurrent.thread


class Scripts() {
    companion object {
        val SCRIPTENVIRONMENT = Scripts::class.java.getResource("/ScriptEnvironment.py").readText()
        val DEFAULT_RAW_REQUEST: String = listOf(
            "GET / HTTP/1.1",
            "Host: example.com",
            "Cache-Control: max-age=0",
            "Sec-Ch-Ua: \"Google Chrome\";v=\"139\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"139\"",
            "Sec-Ch-Ua-Mobile: ?0",
            "Sec-Ch-Ua-Platform: \"macOS\"",
            "Accept-Language: en-US;q=0.9,en;q=0.8",
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site: none",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-User: ?1",
            "Sec-Fetch-Dest: document",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: close",
            "",
            ""
        ).joinToString("\r\n")

        val SAMPLEBURPSCRIPT: String = """
            def queueRequests(target, wordlists):
                engine = RequestEngine(endpoint=target.endpoint,
                                       concurrentConnections=10,
                                       requestsPerConnection=1,
                                       pipeline=False
                                       )

                # engine.engine.applySetting('ignoreLength', True)

                # send 100 requests
                for word in range(0, 100):
                    engine.queue(target.req)


            def handleResponse(req, interesting):
                # currently available attributes are req.status, req.wordcount, req.length and req.response
                if req.status != 99999:
                    table.add(req)
        """.trimIndent()
    }
}


class Target(val req: String, val rawreq: ByteArray, val endpoint: String, val baseInput: String)

class Wordlist(val bruteforce: Bruteforce, val observedWords: ConcurrentHashMap.KeySetView<String, Boolean>, val clipboard: ArrayList<String>)

fun evalJython(code: String, baseRequest: String, rawRequest: ByteArray, endpoint: String, host: String, baseInput: String, outputHandler: OutputHandler, handler: AttackHandler, reqs: MutableList<HttpRequestResponse>?) {
    val pyInterp = PythonInterpreter() // todo add path to bs4
    try {
        Utils.out("Starting attack...")
        handler.code = code
        handler.baseRequest = baseRequest
        handler.rawRequest = rawRequest
        pyInterp.set("target", Target(baseRequest, rawRequest, endpoint, baseInput))
        val savedWords = Utils.witnessedWords.savedWords
        if (savedWords.isEmpty()) {
            savedWords.add("To use this wordlist, enable 'learn observed words'")
        }
        pyInterp.set("wordlists", Wordlist(Bruteforce(), Utils.witnessedWords.savedWords, Utils.getClipboard()))
        pyInterp.set("handler", handler)
        pyInterp.set("outputHandler", outputHandler)
        pyInterp.set("table", outputHandler)
        pyInterp.set("requests", reqs)
        pyInterp.set("host", host)
        if (Utils.gotBurp) {
            pyInterp.set("callbacks", Utils.callbacks)
            pyInterp.set("helpers", Utils.callbacks.helpers)
            pyInterp.set("utilities", Utils.utilities)
            pyInterp.set("api", Utils.montoyaApi)
            pyInterp.setOut(Utils.callbacks.stdout)
            pyInterp.setErr(Utils.callbacks.stderr)
        }
        pyInterp.exec(Scripts.SCRIPTENVIRONMENT)
        pyInterp.exec(code)
        pyInterp.exec("queueRequests(target, wordlists)")
        handler.setComplete()
        pyInterp.exec("completed(outputHandler.getAllRquests())".trimMargin())
    }
    catch (ex: Exception) {
        var error = ex
        var stackTrace = errorToStacktrace(error)
        if (stackTrace.contains("Cannot queue any more items - the attack has finished")) {
            Utils.out("Attack aborted with items waiting to be queued.")
            try {
                pyInterp.exec("completed(outputHandler.getAllRquests())".trimMargin())
                handler.abort()
                return
            } catch (ex2: Exception) {
                error = ex2
                stackTrace = errorToStacktrace(ex2)
            }
        }

        var message = error.cause?.message
        if (message == null) {
            message = error.toString()
        }
        handler.overrideStatus("User Python error, check extender for full details: $message")
        Utils.out("There was an error executing your Python script. This is probably due to a flaw in your script, rather than a bug in Turbo Intruder :)")
        Utils.out("If you think it is a Turbo Intruder issue, try out this script: https://raw.githubusercontent.com/PortSwigger/turbo-intruder/master/resources/examples/debug.py")
        Utils.out("For your convenience, here's the full stack trace:")
        Utils.out(stackTrace)

        handler.abort()
    }
}


fun errorToStacktrace(ex: Exception): String {
    val stackTrace = StringWriter()
    ex.printStackTrace(PrintWriter(stackTrace))
    return stackTrace.toString()
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

class TurboIntruderFrame(inputReq: IHttpRequestResponse, val selectionBounds: IntArray, val fixedScript: String?, val requestOverride: ByteArray?, val reqs: MutableList<HttpRequestResponse>?): ActionListener, JFrame("Turbo Intruder - " + inputReq.httpService.host)  {
    val req = Utils.callbacks.saveBuffersToTempFiles(inputReq) // warning: currently changes HTTP/2 to HTTP/1.1 and breaks the offsets

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
            Utilities.globalSettings.registerSetting("font-size", 14);
            Utilities.globalSettings.registerSetting("line-numbers", true);
            Utilities.globalSettings.registerSetting("show-eol", false);
            Utilities.globalSettings.registerSetting("visible-whitespace", false);

            val pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            pane.setDividerLocation(0.25)
            pane.addComponentListener(RecordResize())

            val panel = JPanel(BorderLayout())
            val codeCombo = JComboBox<Any>()
            codeCombo.renderer = ComboBoxRenderer(10)
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
            textEditor.eolMarkersVisible = Utilities.globalSettings.getBoolean("show-eol")
            textEditor.isWhitespaceVisible = Utilities.globalSettings.getBoolean("visible-whitespace")

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

            textEditor.font = textEditor.font.deriveFont(Utilities.globalSettings.getInt("font-size").toFloat())

            //val scrollableTextEditor = JScrollPane(textEditor)
            val scrollableTextEditor = RTextScrollPane(textEditor)
            scrollableTextEditor.lineNumbersEnabled = Utilities.globalSettings.getBoolean("line-numbers")

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
            val topPanel = JPanel(BorderLayout())

            // Host/Port/Protocol controls
            val initialService = req.httpService
            val hostField = JTextField(initialService.host, 16)
            val portField = JTextField(initialService.port.toString(), 5)
            val protocolCombo = JComboBox(arrayOf("http", "https"))
            protocolCombo.selectedItem = initialService.protocol

            val leftPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            leftPanel.add(JLabel("Host:"))
            leftPanel.add(hostField)
            leftPanel.add(JLabel("Port:"))
            leftPanel.add(portField)
            leftPanel.add(JLabel("Protocol:"))
            leftPanel.add(protocolCombo)

            val rightPanel = JPanel(GridBagLayout())
            val gbc = GridBagConstraints()
            gbc.insets = Insets(0, 4, 0, 0)
            gbc.gridy = 0
            gbc.gridx = 0
            gbc.weightx = 1.0
            gbc.fill = GridBagConstraints.HORIZONTAL
            rightPanel.add(codeCombo, gbc)

            gbc.gridx = 1
            gbc.weightx = 0.0
            gbc.fill = GridBagConstraints.NONE
            rightPanel.add(loadDirectoryButton, gbc)

            gbc.gridx = 2
            rightPanel.add(saveButton, gbc)

            topPanel.add(leftPanel, BorderLayout.WEST)
            topPanel.add(rightPanel, BorderLayout.CENTER)
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

            class ToggleAttack(): ActionListener {
                override fun actionPerformed(e: ActionEvent?) {
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
                                    title = "Turbo Intruder - " + req.httpService.host
                                }
                            }
                            else -> {
                                // Build service/target from UI inputs
                                val inputHost = hostField.text.trim().ifEmpty { initialService.host }
                                val inputPort = try { portField.text.trim().toInt() } catch (ex: Exception) { initialService.port }
                                val inputProtocol = (protocolCombo.selectedItem?.toString() ?: initialService.protocol).lowercase()
                                val newService = Utils.callbacks.helpers.buildHttpService(inputHost, inputPort, inputProtocol)

                                val requestTable = RequestTable(newService, handler)
                                SwingUtilities.invokeLater {
                                    button.text = "Halt"
                                    val requestPanel = JPanel(BorderLayout())
                                    panel.remove(button)
                                    requestPanel.add(requestTable, BorderLayout.CENTER)
                                    requestPanel.add(button, BorderLayout.SOUTH)
                                    pane.bottomComponent = requestPanel
                                    button.requestFocusInWindow()
                                    pane.rootPane.defaultButton = button
                                    title = "Turbo Intruder - " + inputHost
                                }
                                var script = textEditor.text

                                Utils.callbacks.saveExtensionSetting("defaultScript", script)
                                Utils.callbacks.helpers

                                val baseRequest = Utils.callbacks.helpers.bytesToString(messageEditor.message)

                                val target: String
                                if (inputHost.contains(":")) {
                                    target = inputProtocol + "://[" + inputHost + "]:" + inputPort
                                }
                                else {
                                    target = inputProtocol + "://" + inputHost + ":" + inputPort
                                }

                                // enforce /r/n line endings
                                script = script.replace("\r\n", "\n")
                                script = script.replace("\n", "\r\n")
                                title += " - running"
                                evalJython(script, baseRequest, messageEditor.message, target, inputHost, baseInput, requestTable, handler, reqs)
                            }
                        }
                    }
                }
            }
            button.addActionListener(ToggleAttack())

            button.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke(
                    "control ENTER"
                ), "toggleAttack"
            )

            button.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke(
                    "control SPACE"
                ), "toggleAttack"
            )

            button.getActionMap().put("toggleAttack", object : AbstractAction() {
                override fun actionPerformed(e: ActionEvent) {
                    ToggleAttack().actionPerformed(e)
                }
            })


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
        var req = ""
        var endpoint = ""
        var baseInput = ""
        var rawReq = "".toByteArray()
        if (args.size > 1) {
            req = File(args[1]).readText()
            rawReq = File(args[1]).readBytes()
            endpoint = args[2]
            baseInput = args[3]
        }
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
        evalJython(code, req, rawReq, endpoint, "", baseInput, outputHandler, attackHandler, mutableListOf())
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
