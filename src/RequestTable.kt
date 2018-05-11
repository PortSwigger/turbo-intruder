package burp

import javax.swing.JPanel
import javax.swing.event.ListSelectionEvent
import javax.swing.event.ListSelectionListener
import com.sun.java.accessibility.util.SwingEventMonitor.addListSelectionListener
import javax.swing.JTable
import java.awt.BorderLayout
import javax.swing.JSplitPane
import javax.swing.text.StyleConstants.getComponent
import javax.swing.JScrollPane
import com.sun.corba.se.spi.presentation.rmi.StubAdapter.request
import java.awt.Dimension


class RequestTable(val service: IHttpService): JPanel() {
    val model = RequestTableModel()
    val issueTable = JTable(model)
    val requestEditor: IMessageEditor
    val responseEditor: IMessageEditor
    val bottomSplit: JSplitPane
    val requestListView: JScrollPane
    private val controller = MessageEditorController()
    private var currentRequest: Request? = null

    fun setCurrentRequest(req: Request?) {
        println("Setting current request to "+req!!.word)
        currentRequest = req
        requestEditor.setMessage(req.getRawRequest(), true)
        responseEditor.setMessage(req.getRawResponse(), false)
    }

    init {

        issueTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        //issueTable.getColumnModel().getColumn(0).setPreferredWidth(500)

        issueTable.getSelectionModel().addListSelectionListener({
            val req = model.getRequest(issueTable.getSelectedRow())
            setCurrentRequest(req)
        })

        requestListView = JScrollPane(issueTable)

        requestEditor = BurpExtender.callbacks.createMessageEditor(controller, false)
        responseEditor = BurpExtender.callbacks.createMessageEditor(controller, false)
        bottomSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.getComponent(), responseEditor.getComponent())
        bottomSplit.setResizeWeight(0.5)


        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, requestListView, bottomSplit)

        requestListView.preferredSize = Dimension(1280, 400)
        splitPane.setDividerLocation(0.2)
        splitPane.resizeWeight = 0.2
        splitPane.preferredSize = Dimension(1280, 880)

        this.layout = BorderLayout()
        this.add(splitPane, BorderLayout.CENTER)


        BurpExtender.callbacks.customizeUiComponent(this)
    }


    fun add(req: Request) {
        model.addRequest(req)
    }

    inner class MessageEditorController : IMessageEditorController {
        override fun getHttpService(): IHttpService? {
            return service //currentRequest.getHttpService()
        }

        override fun getRequest(): ByteArray? {
            return currentRequest?.getRawRequest()
        }

        override fun getResponse(): ByteArray? {
            return currentRequest?.getRawResponse()
        }
    }

}


