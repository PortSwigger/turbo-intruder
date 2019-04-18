package burp

import java.util.ArrayList
import javax.swing.JMenuItem

class OfferSuggestedAttacks(): IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val options = ArrayList<JMenuItem>()
        if (invocation != null && invocation.selectedMessages[0] != null) {
            val probeButton = JMenuItem("Try suggested attack")
            val bounds = invocation.selectionBounds ?: IntArray(0)
            probeButton.addActionListener(TurboIntruderFrame(invocation.selectedMessages[0], bounds, "script goes here!"))
            options.add(probeButton)
        }
        return options
    }
}