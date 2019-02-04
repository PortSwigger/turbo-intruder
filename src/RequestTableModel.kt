package burp

import javax.swing.table.AbstractTableModel
import java.util.*

class RequestTableModel : AbstractTableModel() {
    internal var requests: MutableList<Request> = ArrayList()
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
            0 -> rowIndex
            1 -> request.word
            2 ->  request.code
            3 -> request.wordcount
            4 -> request.length
            else -> null
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean {
        return editable && columnIndex != 4
    }

    fun addRequest(req: Request) {
        requests.add(req)
        fireTableRowsInserted(requests.lastIndex, requests.lastIndex)
    }


    fun getRequest(index: Int): Request? {
        try {
            return requests[index]
        } catch (ex: ArrayIndexOutOfBoundsException) {
            return null
        }

    }

    companion object {
        internal var columns = Arrays.asList("Row", "Payload", "Status", "Words", "Length")
    }
}