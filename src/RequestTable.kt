package burp

import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.net.URL
import java.text.NumberFormat
import javax.swing.*
import javax.swing.border.BevelBorder
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableRowSorter


class UpdateStatusbar(val message: JLabel, val handler: RunHandler): ActionListener {
    lateinit var timer: Timer

    override fun actionPerformed(e: ActionEvent?) {
        if (handler.status() != "running" || SwingUtilities.getWindowAncestor(message) == null){
            timer.stop()
            val parent = (SwingUtilities.getWindowAncestor(message) as JFrame?)
            parent?.title = parent?.title?.replace(" - running", " - done")
        }

        message.text = handler.statusString()
        // The label clips at the width of the window rather than wrapping. A run that has
        // a reason to report leads with it so the start of it survives, and the tooltip is
        // where the rest of the line, underlying error included, can still be read.
        message.toolTipText = if (handler.failureSummary() != null) message.text else null
    }

}

interface OutputHandler {
    abstract fun add(req: Request)
    abstract fun getAllRquests(): List<Request>
}

class RequestTable(val store: ResultStore, val service: IHttpService, val handler: RunHandler): JPanel() {
    val model = RequestTableModel()
    val issueTable = JTable(model)
    val requestEditor: IMessageEditor
    val responseEditor: IMessageEditor
    val bottomSplit: JSplitPane
    val requestListView: JScrollPane
    private val controller = MessageEditorController()
    private var currentRequest: Request? = null
    private val lock = Object()
    private var descending = true
    private var initialized = false
    private var sortModifiedAfterInit = false

    fun clear() {
        model.clear()
    }

    fun hasSortBeenModified(): Boolean = sortModifiedAfterInit

    fun setCurrentRequest(req: Request?) {
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
        if (initialized) {
            sortModifiedAfterInit = true
        }
        this.descending = descending
        val order = if (descending) SortOrder.DESCENDING else SortOrder.ASCENDING
        issueTable.rowSorter.sortKeys = listOf(RowSorter.SortKey(column, order))
    }

    internal fun autoSortByAnomalyRank() {
        descending = true
        val order = SortOrder.DESCENDING
        issueTable.rowSorter.sortKeys = listOf(RowSorter.SortKey(3, order))
    }

    init {

        val sorter = object : TableRowSorter<RequestTableModel>(model) {
            override fun toggleSortOrder(column: Int) {
                sortModifiedAfterInit = true
                val sortKeys = this.sortKeys
                if (sortKeys.isEmpty() || sortKeys[0].column != column) {
                    // First click: descending
                    this.sortKeys = listOf(RowSorter.SortKey(column, SortOrder.DESCENDING))
                } else if (sortKeys[0].sortOrder == SortOrder.DESCENDING) {
                    // Second click: ascending
                    this.sortKeys = listOf(RowSorter.SortKey(column, SortOrder.ASCENDING))
                } else {
                    // Third click: unsorted
                    this.sortKeys = emptyList()
                }
            }
        }
        issueTable.rowSorter = sorter
        setSortOrder(0, true)

        // Add custom renderer for anomaly rank column to format with commas
        val anomalyRankRenderer = object : DefaultTableCellRenderer() {
            private val numberFormat = NumberFormat.getNumberInstance()

            override fun getTableCellRendererComponent(
                table: JTable?,
                value: Any?,
                isSelected: Boolean,
                hasFocus: Boolean,
                row: Int,
                column: Int
            ): Component {
                val formattedValue = if (value is Number) {
                    numberFormat.format(value)
                } else {
                    value
                }
                return super.getTableCellRendererComponent(table, formattedValue, isSelected, hasFocus, row, column)
            }
        }
        issueTable.columnModel.getColumn(3).cellRenderer = anomalyRankRenderer

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

        // Poll ResultStore for new results
        var lastKnownSize = 0
        var finishedAt: Long? = null
        val storePoller = javax.swing.Timer(100) {
            // Stop polling 10 seconds after run completes
            if (handler.status() != "running") {
                if (finishedAt == null) {
                    finishedAt = System.currentTimeMillis()
                } else if (System.currentTimeMillis() - finishedAt!! > 10000) {
                    (it.source as javax.swing.Timer).stop()
                    return@Timer
                }
            }
            val currentSize = store.count()
            if (currentSize > lastKnownSize) {
                for (i in lastKnownSize until currentSize) {
                    val req = store.getRequestByIndex(i)
                    if (req != null) {
                        model.addRow(req)
                        if (lastKnownSize == 0) {
                            setCurrentRequest(req)
                        }
                    }
                }
                lastKnownSize = currentSize
            }
        }
        storePoller.start()

        val menu = JPopupMenu()

        val reportToOrganizerButton = JMenuItem("Save to Organizer")
        reportToOrganizerButton.addActionListener {
            val comment = JOptionPane.showInputDialog(menu, "Comment", "",  JOptionPane.PLAIN_MESSAGE) as String
            val reqs = getSelectedRequests().map(Request::getMontoyaRequest)
            val notes = comment + "\n" + handler.statusString() + "\n\n" + SCRIPT_MARKER + "\n" + handler.code
            for (req in reqs) {
                req!!.annotations().setNotes(notes)
                Utils.montoyaApi.organizer().sendToOrganizer(req)
            }
        }
        menu.add(reportToOrganizerButton)

        // warning, this doesn't reliably save entries with duplicate URLs
        val addToSitemap = JMenuItem("Add to sitemap")
        addToSitemap.addActionListener {
            for (req in getSelectedRequests()) {
                Utils.callbacks.addToSiteMap(req.getBurpRequest())
            }
        }
        menu.add(addToSitemap)

        val createIssueButton = JMenuItem("Report as issue")
        createIssueButton.addActionListener {
            val reqs = getSelectedRequests().map(Request::getBurpRequest)


            val comment = JOptionPane.showInputDialog(menu, "Comment", "", JOptionPane.PLAIN_MESSAGE) as String

            val htmlTable = StringBuilder()
            htmlTable.append("<table>")
            htmlTable.append("<tr><td>Payload</td><td>Status</td><td>TTFB</td><td>TTLB</td><td>Arrival</td><td>Label</td><td>Queue ID</td><td>Connection ID</td></tr>")

            for (req in getSelectedRequests()) {
                htmlTable.append("<tr><td>")
                if (req.words.isNotEmpty()) {
                    htmlTable.append(req.words[0])
                }
                htmlTable.append("</td><td>")
                htmlTable.append(req.status)
                htmlTable.append("</td><td>")
                htmlTable.append(req.ttfb)
                htmlTable.append("</td><td>")
                htmlTable.append(req.ttlb)
                htmlTable.append("</td><td>")
                htmlTable.append(req.arrival)
                htmlTable.append("</td><td>")
                htmlTable.append(req.label)
                htmlTable.append("</td><td>")
                htmlTable.append(req.order)
                htmlTable.append("</td><td>")
                htmlTable.append(req.connectionId)
                htmlTable.append("</td></tr>")
            }
            htmlTable.append("</table>")
            val service = reqs[0].httpService
            val baseReq = StubRequest(Utils.stringToBytes(handler.baseRequest), service)
            val url = URL(service.protocol + "://" + service.host + ":" +service.port)
            val detail = "<b>Comment: "+comment+"</b><br/><br/><b>Status:</b> "+statusLabel.text + "<br/><br/>\n<pre>"+ handler.code.replace("<", "&lt;")+"</pre>\n"+htmlTable
            val issue = TurboScanIssue(service, url, arrayOf<IHttpRequestResponse>(baseReq) + reqs.toTypedArray(), "Turbo Intruder Finding", detail, "Information", "Certain", "")
            Utils.callbacks.addScanIssue(issue)
        }
        menu.add(createIssueButton)


        issueTable.componentPopupMenu = menu
        Utils.callbacks.customizeUiComponent(this)
        Utils.callbacks.customizeUiComponent(issueTable)

        initialized = true
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


