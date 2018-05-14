package burp

import javax.*
import javax.swing.*
import javax.swing.event.TableModelListener
import javax.swing.table.AbstractTableModel
import java.*
import java.util.*



class RequestTableModel : AbstractTableModel() {
    internal var requests: MutableList<Request> = ArrayList<Request>()
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
        when (columnIndex) {
            0 -> return request.word
            else -> return null
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean {
        return editable && columnIndex != 4
    }

    fun addRequest(req: Request) {
        requests.add(req)
        fireTableRowsInserted(requests.size, requests.size)
    }


    fun getRequest(index: Int): Request? {
        try {
            return requests[index]
        } catch (ex: ArrayIndexOutOfBoundsException) {
            return null
        }

    }

    companion object {
        internal var columns = Arrays.asList("Payload")
    }
}