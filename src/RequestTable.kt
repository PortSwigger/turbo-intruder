package burp

import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger
import javax.swing.*
import javax.swing.border.BevelBorder
import javax.swing.table.TableRowSorter


class UpdateStatusbar(val message: JLabel, val handler: AttackHandler): ActionListener {
    lateinit var timer: Timer

    override fun actionPerformed(e: ActionEvent?) {
        if (handler.hasFinished() || SwingUtilities.getWindowAncestor(message) == null){
            timer.stop()
            val parent = (SwingUtilities.getWindowAncestor(message) as JFrame?)
            parent?.title = parent?.title?.replace(" - running", " - done")
        }

        message.text = handler.statusString()
    }

}

interface OutputHandler {
    var requests: MutableList<Request>

    abstract fun add(req: Request)
    fun save(req: Request) {
        try {
            requests.add(req)
        } catch (e: Exception) {
            Utils.err("Error saving request: "+e.message)
            e.printStackTrace()
        }
    }
}

class ConsolePrinter() : OutputHandler {
    private val requestID = AtomicInteger(0)
    override var requests: MutableList<Request> = java.util.ArrayList()

    init {
        Utils.out("ID | Word | Status | Wordcount | Length | Time")
    }

    override fun add(req: Request) {
        save(req)
        Utils.out(String.format("%s | %s | %s | %s | %s | %s", requestID.incrementAndGet(), req.words.joinToString(separator="/"), req.code, req.wordcount, req.length, req.time))
    }
}


class RequestTable(val service: IHttpService, val handler: AttackHandler): JPanel(), OutputHandler {
    override var requests: MutableList<Request> = java.util.ArrayList()
    val model = RequestTableModel(this)
    val issueTable = JTable(model)
    val requestEditor: IMessageEditor
    val responseEditor: IMessageEditor
    val bottomSplit: JSplitPane
    val requestListView: JScrollPane
    private val controller = MessageEditorController()
    private var currentRequest: Request? = null
    private var firstEntry = true
    private val lock = Object()
    private var descending = true

    fun clear() {
        SwingUtilities.invokeLater({
            requests.clear()
            model.fireTableDataChanged()
        })
    }

    fun setCurrentRequest(req: Request?) {
        //println("Setting current request to "+req!!.word)
        synchronized(lock) {
            currentRequest = req!!
            requestEditor.setMessage(req.getRequestAsBytes(), true)
            responseEditor.setMessage(
                Utilities.replaceFirst(
                    req.getResponseAsBytes(),
                    "Content-Encoding: gzip",
                    "X-Content-Encoding: gz"
                ), false
            )
        }
    }

    fun setSortOrder(column: Int, descending: Boolean) {
        this.descending = descending
        val order = if (descending) SortOrder.DESCENDING else SortOrder.ASCENDING
        issueTable.rowSorter.sortKeys = listOf(RowSorter.SortKey(column, order))
    }

    init {

        issueTable.rowSorter = TableRowSorter(model)
        setSortOrder(0, true)

        issueTable.autoResizeMode = JTable.AUTO_RESIZE_OFF
        //issueTable.getColumnModel().getColumn(0).setPreferredWidth(500)

        issueTable.selectionModel.addListSelectionListener {
            val req = model.getRequest(issueTable.convertRowIndexToModel(issueTable.selectedRow))
            setCurrentRequest(req!!)
        }

        requestListView = JScrollPane(issueTable)

        val turboSize = Utils.getTurboSize()
        requestEditor = Utils.callbacks.createMessageEditor(controller, false)
        responseEditor = Utils.callbacks.createMessageEditor(controller, false)
        bottomSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.getComponent(), responseEditor.getComponent())
        bottomSplit.resizeWeight = 0.5
        bottomSplit.preferredSize = Dimension(turboSize.width, turboSize.height/2)


        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, requestListView, bottomSplit)

        requestListView.preferredSize = Dimension(turboSize.width, turboSize.height/2)
        splitPane.setDividerLocation(0.2)
        splitPane.preferredSize = Dimension(turboSize.width, turboSize.height)

        this.layout = BorderLayout()
        this.add(splitPane, BorderLayout.CENTER)


        splitPane.resizeWeight = 0.5


        val statusPanel = JPanel()
        statusPanel.border = BevelBorder(BevelBorder.LOWERED)
        this.add(statusPanel, BorderLayout.SOUTH) //
        statusPanel.preferredSize = Dimension(this.getWidth(), 30)
        statusPanel.layout = BoxLayout(statusPanel, BoxLayout.X_AXIS)
        val statusLabel = JLabel("")
        statusLabel.horizontalAlignment = SwingConstants.LEFT
        statusPanel.add(statusLabel)

        val updateStatusbar = UpdateStatusbar(statusLabel, handler)
        val panelUpdater = Timer(1000, updateStatusbar)
        updateStatusbar.timer = panelUpdater
        panelUpdater.start()

        val menu = JPopupMenu()

        val reportToOrganizerButton = JMenuItem("Save to Organizer")
        reportToOrganizerButton.addActionListener {
            val comment = JOptionPane.showInputDialog(menu, "Comment", "",  JOptionPane.PLAIN_MESSAGE) as String
            val reqs = getSelectedRequests().map(Request::getMontoyaRequest)
            val notes = comment + "\n" + handler.statusString() + "\n\n" + handler.code
            for (req in reqs) {
                req!!.annotations().setNotes(notes)
                Utils.montoyaApi.organizer().sendToOrganizer(req)
            }
        }
        menu.add(reportToOrganizerButton)

//        val addToSitemap = JMenuItem("Add to sitemap")
//        addToSitemap.addActionListener {
//            for (req in getSelectedRequests()) {
//                Utils.callbacks.addToSiteMap(req.getBurpRequest())
//            }
//        }
//        menu.add(addToSitemap)

        val createIssueButton = JMenuItem("Report as issue")
        createIssueButton.addActionListener {
            val reqs = getSelectedRequests().map(Request::getBurpRequest)


            val comment = JOptionPane.showInputDialog(menu, "Comment", "", JOptionPane.PLAIN_MESSAGE) as String

            val htmlTable = StringBuilder()
            htmlTable.append("<table>")
            htmlTable.append("<tr><td>Payload</td><td>Status</td><td>Time</td><td>Arrival</td><td>Label</td><td>Queue ID</td><td>Connection ID</td></tr>")

            for (req in getSelectedRequests()) {
                htmlTable.append("<tr><td>")
                if (req.words.isNotEmpty()) {
                    htmlTable.append(req.words[0])
                }
                htmlTable.append("</td><td>")
                htmlTable.append(req.status)
                htmlTable.append("</td><td>")
                htmlTable.append(req.time)
                htmlTable.append("</td><td>")
                htmlTable.append(req.arrival)
                htmlTable.append("</td><td>")
                htmlTable.append(req.label)
                htmlTable.append("</td><td>")
                htmlTable.append(req.order)
                htmlTable.append("</td><td>")
                htmlTable.append(req.connectionID)
                htmlTable.append("</td></tr>")
            }
            htmlTable.append("</table>")
            val service = reqs[0].httpService
            val baseReq = StubRequest(Utils.stringToBytes(handler.baseRequest), service)
            val url = URL(service.protocol + "://" + service.host + ":" +service.port)
            val detail = "<b>Comment: "+comment+"</b><br/><br/><b>Status:</b> "+statusLabel.text + "<br/><br/>\n<pre>"+ handler.code.replace("<", "&lt;")+"</pre>\n"+htmlTable
            val issue = TurboScanIssue(service, url, arrayOf<IHttpRequestResponse>(baseReq) + reqs.toTypedArray(), "Turbo Intruder Attack", detail, "Information", "Certain", "")
            Utils.callbacks.addScanIssue(issue)
        }
        menu.add(createIssueButton)


        issueTable.componentPopupMenu = menu
        Utils.callbacks.customizeUiComponent(this)
        Utils.callbacks.customizeUiComponent(issueTable)
    }

    private fun getSelectedRequests(): ArrayList<Request> {
        synchronized(lock) {
            val requests = ArrayList<Request>()
            val table = issueTable.model as RequestTableModel
            for (index in issueTable.selectedRows) {
                val req = table.getRequest(issueTable.convertRowIndexToModel(index))
                if (req != null) {
                    requests.add(req)
                }
            }
            return requests
        }
    }


    override fun add(req: Request) {
        synchronized(lock) {
            try {
                save(req)
                if (descending) {
                    model.fireTableRowsInserted(0, 0)
                } else {
                    model.fireTableRowsInserted(requests.lastIndex, requests.lastIndex)
                }
                if (firstEntry && issueTable.rowCount > 0) {
                    issueTable.changeSelection(0, 0, false, false) // this is nuking the first row
                    issueTable.requestFocusInWindow()
                    firstEntry = false
                }
            } catch (e: Exception) {
                Utils.err("Error adding request to table: "+e.message)
                Utilities.showError(e)
                e.printStackTrace()
            }
        }

    }

    inner class MessageEditorController : IMessageEditorController {
        override fun getHttpService(): IHttpService? {
            if (currentRequest?.montoyaReq != null) {
                val montoyaService = currentRequest!!.montoyaReq!!.httpService()
                return Utils.callbacks.helpers.buildHttpService(montoyaService.host(), montoyaService.port(), montoyaService.secure())
            }
            return service
        }

        override fun getRequest(): ByteArray? {
            return currentRequest?.getRequestAsBytes()
        }

        override fun getResponse(): ByteArray? {
            return currentRequest?.getResponseAsBytes()
        }
    }

}


