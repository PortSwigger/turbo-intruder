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
        const val version = "1.61"
    }

    override fun extensionUnloaded() {
        Utils.unloaded = true
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

        SwingUtilities.invokeLater(ConfigMenu())
        SwingUtilities.invokeLater { addRunScriptToExistingMenu() }
    }

    override fun initialize(montoyaApi: MontoyaApi) {
        Utils.montoyaApi = montoyaApi
        Utilities.montoyaApi = montoyaApi
        montoyaApi.userInterface().registerContextMenuItemsProvider(BulkMenu())
        registerHotkey(montoyaApi)
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