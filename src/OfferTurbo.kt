package burp

import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import java.util.ArrayList
import javax.swing.JMenuItem

class OfferTurboIntruder(): IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val options = ArrayList<JMenuItem>()
        if (invocation != null && invocation.selectedMessages != null && invocation.selectedMessages[0] != null && invocation.selectedMessages[0].httpService != null) {
            val probeButton = JMenuItem("Send to turbo intruder")
            val bounds = invocation.selectionBounds ?: IntArray(0)
            probeButton.addActionListener(TurboIntruderFrame(invocation.selectedMessages[0], bounds, null, null, null))
            options.add(probeButton)
        }
        return options
    }
}

class BulkMenu(): ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        if (event == null || event!!.selectedRequestResponses() === null || event!!.selectedRequestResponses().isEmpty()) {
            return mutableListOf();
        }
        val item = JMenuItem("Bulk Turbo")
        val resp = Resp(event.selectedRequestResponses()[0])
        item.addActionListener(TurboIntruderFrame(resp, IntArray(0), null, null, event.selectedRequestResponses()))
        return mutableListOf(item)
    }
}