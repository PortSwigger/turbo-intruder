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

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return when (columnIndex) {
            0 -> java.lang.Integer::class.java
            1 -> String::class.java
            2 -> java.lang.Integer::class.java
            3 -> java.lang.Integer::class.java
            4 -> java.lang.Integer::class.java
            5 -> java.lang.Long::class.java
            else -> throw RuntimeException()
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
        val request = requests[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> request.words.joinToString(separator="/")
            2 ->  request.code
            3 -> request.wordcount
            4 -> request.length
            5 -> request.time
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
        internal var columns = Arrays.asList("Row", "Payload", "Status", "Words", "Length", "Time")
    }
}