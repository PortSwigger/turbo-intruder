package burp

import java.util.*
import javax.swing.SwingUtilities

class BurpExtender(): IBurpExtender, IExtensionStateListener {

    companion object {
        const val version = "1.23"
    }

    override fun extensionUnloaded() {
        Utils.unloaded = true
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?) {
        callbacks!!.registerContextMenuFactory(OfferTurboIntruder())
        Utils.setBurpPresent(callbacks)
        callbacks.registerScannerCheck(Utils.witnessedWords)
        callbacks.registerExtensionStateListener(this)
        callbacks.setExtensionName("Turbo Intruder")
        Utils.out("Loaded Turbo Intruder v$version")

        Utilities(callbacks, HashMap(), "Turbo Intruder")
        Utilities.globalSettings.registerSetting("font-size", 16);
        SwingUtilities.invokeLater(ConfigMenu())
    }
}
