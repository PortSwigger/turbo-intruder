package burp

import javax.*
import javax.swing.*
import javax.swing.event.TableModelListener
import javax.swing.table.AbstractTableModel
import java.*
import java.util.*


class TableRequest(val req: Request) {
    val code = BurpExtender.callbacks.helpers.analyzeResponse(req.getRawResponse()).statusCode
    val wordcount =  BurpExtender.callbacks.helpers.analyzeResponseVariations(req.getRawResponse()).getAttributeValue("word_count", 0)
}

class RequestTableModel : AbstractTableModel() {
    internal var requests: MutableList<TableRequest> = ArrayList<TableRequest>()
    internal var editable: Boolean = false

    override fun getRowCount(): Int {
        return requests.size
    }

    override fun getColumnCount(): Int {
        return columns.size
    }

    override fun getColumnName(column: Int): String {
        return columns[column]
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
        val request = requests[rowIndex]

        return when (columnIndex) {
            0 -> request.req.word
            1 ->  request.code
            2 -> request.wordcount
            else -> null
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean {
        return editable && columnIndex != 4
    }

    fun addRequest(req: Request) {

        requests.add(TableRequest(req))
        fireTableRowsInserted(requests.size, requests.size)
    }


    fun getRequest(index: Int): TableRequest? {
        try {
            return requests[index]
        } catch (ex: ArrayIndexOutOfBoundsException) {
            return null
        }

    }

    companion object {
        internal var columns = Arrays.asList("Payload", "Status", "Words")
    }
}