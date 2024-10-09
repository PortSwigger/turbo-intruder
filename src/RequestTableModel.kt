package burp

import javax.swing.table.AbstractTableModel
import java.util.*
import javax.swing.table.DefaultTableModel

class RequestTableModel(val handler: OutputHandler): AbstractTableModel() {

    internal var editable: Boolean = false

    override fun getRowCount(): Int {
        return handler.requests.size
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
            6 -> java.lang.Long::class.java
            7 -> String::class.java
            8 -> java.lang.Integer::class.java
            9 -> java.lang.Integer::class.java

            else -> throw RuntimeException()
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
        val request = handler.requests[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> request.words.joinToString(separator="/")
            2 ->  request.code
            3 -> request.wordcount
            4 -> request.length
            5 -> request.time
            6 -> request.arrival
            7 -> request.label
            8 -> request.id
            9 -> request.connectionID
            else -> null
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean {
        return editable && columnIndex != 4
    }


    fun getRequest(index: Int): Request? {
        return try {
            handler.requests[index]
        } catch (ex: ArrayIndexOutOfBoundsException) {
            null
        }

    }

    companion object {
        internal val columns = listOf("Row", "Payload", "Status", "Words", "Length", "Time", "Arrival", "Label", "Queue ID", "Connection ID")
    }
}