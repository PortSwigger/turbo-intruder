package burp

import javax.swing.table.AbstractTableModel
import java.util.*

class TableRequest(val req: Request) {
    var code: Short = 0
    var length: Int = 0
    var wordcount: Int = 0


    init {
        val resp = req.getResponseAsBytes() ?: "".toByteArray()
        code = Utils.callbacks.helpers.analyzeResponse(resp).statusCode

        length = req.response?.length ?: 0

        wordcount = (req.response ?: "").split(Regex("[^a-zA-Z0-9]")).size


        // wordcount =  Utils.callbacks.helpers.analyzeResponseVariations(resp).getAttributeValue("word_count", 0)

//        if (resp != null) {
//            val code = BurpExtender.callbacks.helpers.analyzeResponse(resp).statusCode
//            val wordcount =  BurpExtender.callbacks.helpers.analyzeResponseVariations(resp).getAttributeValue("word_count", 0)
//        } else {
//            val code = "null"
//            val wordcount = "0"
//        }
    }
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
            0 -> rowIndex
            1 -> request.req.word
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
        internal var columns = Arrays.asList("Row", "Payload", "Status", "Words", "Length")
    }
}