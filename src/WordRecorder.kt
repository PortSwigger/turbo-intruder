package burp

import java.util.*
import java.util.concurrent.ConcurrentHashMap

class WordRecorder: IScannerCheck {

    val savedWords = ConcurrentHashMap.newKeySet<String>()
    val wordRegex = "[^a-zA-Z]".toRegex()

    override fun doActiveScan(p0: IHttpRequestResponse?, p1: IScannerInsertionPoint?): MutableList<IScanIssue> {
        return ArrayList()
    }

    override fun consolidateDuplicateIssues(p0: IScanIssue?, p1: IScanIssue?): Int {
        return 0
    }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse?): MutableList<IScanIssue> {
        savedWords.addAll(Utils.callbacks.helpers.bytesToString(baseRequestResponse?.request).split(wordRegex))
        savedWords.addAll(Utils.callbacks.helpers.bytesToString(baseRequestResponse?.response).split(wordRegex))
        return ArrayList()
    }
}