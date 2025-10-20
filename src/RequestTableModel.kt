package burp

import javax.swing.table.AbstractTableModel
import java.util.*
import javax.swing.SwingUtilities

class RequestTableModel: AbstractTableModel() {

    private val requests: MutableList<Request> = ArrayList()

    override fun getRowCount(): Int {
        return requests.size
    }

    override fun getColumnCount(): Int {
        return columns.size
    }

    override fun getColumnName(column: Int): String {
        try {
            return columns[column]
        } catch (e: Exception) {
            Utils.err("Error getting column name: "+e.message)
            e.printStackTrace()
            throw e
        }
    }

    override fun getColumnClass(columnIndex: Int): Class<*> {
        try {
            return when (columnIndex) {
                0 -> java.lang.Integer::class.java
                1 -> String::class.java
                2 -> java.lang.Integer::class.java
                3 -> java.lang.Integer::class.java
                4 -> java.lang.Integer::class.java
                5 -> java.lang.Integer::class.java
                6 -> java.lang.Long::class.java
                7 -> java.lang.Long::class.java
                8 -> String::class.java
                9 -> java.lang.Integer::class.java
                10 -> java.lang.Integer::class.java

                else -> throw RuntimeException("Invalid column requested")
            }
        } catch (e: Exception) {
            Utils.err("Error getting column class: "+e.message)
            e.printStackTrace()
            throw e
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        try {
            val request = requests[rowIndex]

            return when (columnIndex) {
                0 -> rowIndex
                1 -> request.words.joinToString(separator = "/")
                2 -> request.code
                3 -> request.anomalyRank ?: 0
                4 -> request.wordcount
                5 -> request.length
                6 -> request.time
                7 -> request.arrival
                8 -> request.label
                9 -> request.id
                10 -> request.connectionID
                else -> throw RuntimeException("Invalid column requested")
            }
        } catch (e: Exception) {
            Utils.err("Error getting value at row $rowIndex, column $columnIndex: "+e.message)
            e.printStackTrace()
            throw e
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean {
        return false
    }

    fun getRequest(index: Int): Request? {
        return try {
            requests[index]
        } catch (ex: ArrayIndexOutOfBoundsException) {
            Utils.out("Couldn't get request at index $index")
            throw ex
        }

    }

    companion object {
        internal val columns = listOf("Row", "Payload", "Status", "Anomaly rank", "Words", "Length", "Time", "Arrival", "Label", "Queue ID", "Connection ID")
    }

    fun getAllRequests(): List<Request> {
        return requests
    }

    fun addRow(req: Request) {
        requests.add(req)
        try {
            fireTableRowsInserted(requests.lastIndex, requests.lastIndex)
        } catch (e: Exception) {
//            Utils.err("Error firing table rows inserted: "+e.message)
//            Utilities.showError(e)
//            e.printStackTrace()
        }
    }

    fun clear() {
        SwingUtilities.invokeLater({
            requests.clear()
            fireTableDataChanged()
        })
    }

    fun updateRankings() {
        SwingUtilities.invokeLater({
            fireTableDataChanged()
        })
    }
}