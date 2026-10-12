package burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext
import burp.api.montoya.ui.hotkey.HotKey
import burp.api.montoya.ui.hotkey.HotKeyContext
import burp.api.montoya.ui.hotkey.HotKeyEvent
import burp.api.montoya.ui.hotkey.HotKeyHandler
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.util.function.Consumer
import java.util.stream.Collectors
import javax.swing.JFrame
import javax.swing.JMenuItem
import javax.swing.SwingUtilities
import kotlin.jvm.optionals.getOrNull


class BurpExtender() : IBurpExtender, IExtensionStateListener, BurpExtension {

    companion object {
        const val version = "2.0.1"
    }

    private var mcpServer: mcp.TurboMcpServer? = null
    private var mcpServerGate: McpServerGate? = null
    // Lives for the whole extension so the control panel keeps receiving entries across restarts.
    private val mcpActivityLog = mcp.McpActivityLog()
    private var mcpControlPanel: mcp.ui.McpControlPanel? = null

    override fun extensionUnloaded() {
        Utils.unloaded = true
        mcpServerGate?.shutdown()
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        callbacks!!.registerContextMenuFactory(OfferTurboIntruder())
        Utils.setBurpPresent(callbacks)
        callbacks.registerScannerCheck(Utils.witnessedWords)
        callbacks.registerExtensionStateListener(this)
        callbacks.setExtensionName("Turbo Intruder")
        Utils.out("Loaded Turbo Intruder v$version")

        Utils.utilities = Utilities(callbacks, HashMap(), "Turbo Intruder")
        Utilities.globalSettings.registerSetting("learn observed words", false);
        Utilities.globalSettings.registerSetting("desync-agent-mode", false);
        Utilities.globalSettings.registerSetting(
            McpServerGate.SETTING,
            false,
            McpServerGate.DESCRIPTION,
        )

        SwingUtilities.invokeLater(ConfigMenu())
        SwingUtilities.invokeLater { addRunScriptToExistingMenu() }

        val gate = McpServerGate(
            enabled = { Utilities.globalSettings?.getBoolean(McpServerGate.SETTING) == true },
            start = ::startMcpServer,
            stop = ::stopMcpServer,
            reportFailure = { message, error ->
                Utils.err("$message:\n${error.stackTraceToString()}")
            },
            onStateChange = { running ->
                mcpActivityLog.record(
                    if (running) "MCP server started on http://localhost:31337" else "MCP server stopped"
                )
                SwingUtilities.invokeLater { mcpControlPanel?.refresh() }
            },
        )
        mcpServerGate = gate
        Utilities.globalSettings.registerListener(McpServerGate.SETTING) { value ->
            gate.settingChanged(value)
        }
        gate.applyInitialState()
    }

    private fun startMcpServer() {
        if (mcpServer != null) {
            return
        }
        val server = mcp.TurboMcpServer(
            port = 31337,
            collaboratorProvider = mcp.BurpCollaboratorProvider(),
            desyncMode = { Utilities.globalSettings?.getBoolean("desync-agent-mode") == true },
            activityLog = mcpActivityLog
        )
        try {
            server.start()
        } catch (e: Exception) {
            try {
                server.stop()
            } catch (cleanupFailure: Exception) {
                e.addSuppressed(cleanupFailure)
            }
            throw e
        }
        mcpServer = server
        Utils.out("MCP server listening on http://localhost:31337")
    }

    private fun stopMcpServer() {
        val server = mcpServer ?: return
        server.stop()
        mcpServer = null
        Utils.out("MCP server stopped")
    }

    override fun initialize(montoyaApi: MontoyaApi) {
        Utils.montoyaApi = montoyaApi
        Utilities.montoyaApi = montoyaApi
        montoyaApi.userInterface().registerContextMenuItemsProvider(BulkMenu())
        montoyaApi.userInterface().registerContextMenuItemsProvider(OfferTurboIntruderWithScript())
        registerHotkey(montoyaApi)
        registerMcpTab(montoyaApi)
    }

    /**
     * Registers the "Turbo MCP" suite tab: a live view of the MCP server with start/stop controls
     * and an activity log. The buttons drive the gate (runtime start/stop); the persisted
     * auto-start setting still lives in the Turbo Intruder settings menu.
     *
     * Burp does not guarantee whether the Montoya initialize() callback runs before or after the
     * legacy registerExtenderCallbacks() where the gate is created, so the panel dereferences
     * mcpServerGate at call time (not at registration) and the tab is registered regardless. The
     * gate is created synchronously during load, so it is always present before the UI is usable.
     */
    private fun registerMcpTab(montoyaApi: MontoyaApi) {
        SwingUtilities.invokeLater {
            val panel = mcp.ui.McpControlPanel(
                isRunning = { mcpServerGate?.isRunning() ?: false },
                onStart = { mcpServerGate?.settingChanged("true") },
                onStop = { mcpServerGate?.settingChanged("false") },
                address = { "http://localhost:31337" },
                activityLog = mcpActivityLog,
                securityNotice = McpServerGate.DESCRIPTION
            )
            mcpControlPanel = panel
            try {
                montoyaApi.userInterface().registerSuiteTab("Turbo MCP", panel)
            } catch (e: Exception) {
                Utils.err("Failed to register Turbo MCP tab: ${e.message}")
            }
        }
    }

    fun registerHotkey(montoyaApi: MontoyaApi) {
        try {
            val hotKey: HotKey? = HotKey.hotKey("Send to Turbo Intruder", "Ctrl+Alt-T");
            val handler = HotKeyHandler { event: HotKeyEvent? ->
                event!!.messageEditorRequestResponse().ifPresent(Consumer { editor: MessageEditorHttpRequestResponse? ->
                    val requestResponse = editor!!.requestResponse()
                    val inputReq = Resp(requestResponse)
                    val selectionOffsets = editor.selectionOffsets().getOrNull()
                    var bounds = intArrayOf()
                    if (selectionOffsets != null) {
                        bounds =
                            intArrayOf(selectionOffsets.startIndexInclusive(), selectionOffsets.endIndexExclusive())
                    }
                    TurboIntruderFrame(inputReq, bounds, null, null, null).actionPerformed(null)
                })
            }

            montoyaApi.userInterface().registerHotKeyHandler(
                HotKeyContext.HTTP_MESSAGE_EDITOR,
                hotKey,
                handler
            );
        } catch (e: NoSuchMethodError) {
            // Utils.out("Please update Burp Suite to the latest available version")
        }

        // Keep Montoya registrations minimal to avoid duplicating the existing top-level menu
    }

    // ConfigurableSettings.java in albinowaxUtils inits a default Settings menu, let's find it and add more items to it
    private fun addRunScriptToExistingMenu() {
        val burpFrame = java.awt.Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
        if (burpFrame is JFrame) {
            val menuBar = burpFrame.jMenuBar ?: return
            for (i in 0 until menuBar.menuCount) {
                val menu = menuBar.getMenu(i) ?: continue
                if (menu.text == "Turbo Intruder") {
                    val runItem = JMenuItem("Run script")
                    runItem.addActionListener {
                        try {
                            val helpers = Utils.callbacks.helpers
                            val host = "example.com"
                            val port = 443
                            val protocol = "https"
                            val service = helpers.buildHttpService(host, port, protocol)
                            val raw = Scripts.DEFAULT_RAW_REQUEST.toByteArray(Charsets.ISO_8859_1)
                            val stub = StubRequest(raw, service)
                            TurboIntruderFrame(stub, IntArray(0), Scripts.SAMPLEBURPSCRIPT, raw, null).actionPerformed(null)
                        } catch (e: Exception) {
                            Utils.out("Failed to open Turbo Intruder: " + (e.message ?: e.toString()))
                        }
                    }
                    menu.add(runItem)
                    menu.revalidate()
                    menu.repaint()
                    break
                }
            }
        }
    }
}
