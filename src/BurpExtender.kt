package burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import javax.swing.JMenuItem
import javax.swing.SwingUtilities

class BurpExtender() : IBurpExtender, IExtensionStateListener, BurpExtension {

    companion object {
        const val version = "1.5"
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
    }

    override fun initialize(montoyaApi: MontoyaApi) {
        Utils.montoyaApi = montoyaApi
        montoyaApi.userInterface().registerContextMenuItemsProvider(BulkMenu())
    }
}