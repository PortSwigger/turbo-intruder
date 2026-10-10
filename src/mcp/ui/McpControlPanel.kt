package mcp.ui

import mcp.ActivityEntry
import mcp.McpActivityLog
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import kotlin.concurrent.thread

/**
 * Burp suite-tab panel for controlling and observing the MCP server. It is a thin view over
 * injected callbacks: it never starts or stops the server itself, it asks the gate (via [onStart]
 * / [onStop]) and then refreshes. Server start/stop does socket I/O, so it runs off the Event
 * Dispatch Thread; every Swing mutation is marshalled back onto the EDT.
 *
 * This Swing class is not unit-tested (no Burp runtime headless); its collaborators — the gate
 * (isRunning / state changes) and [McpActivityLog] — are.
 */
class McpControlPanel(
    private val isRunning: () -> Boolean,
    private val onStart: () -> Unit,
    private val onStop: () -> Unit,
    private val address: () -> String,
    private val activityLog: McpActivityLog,
    private val securityNotice: String
) : JPanel(BorderLayout(8, 8)) {

    private val statusLabel = JLabel()
    private val startButton = JButton("Start")
    private val stopButton = JButton("Stop")
    private val logArea = JTextArea(16, 80).apply {
        isEditable = false
        lineWrap = false
    }
    private val timeFormat = SimpleDateFormat("HH:mm:ss")

    init {
        border = BorderFactory.createEmptyBorder(12, 12, 12, 12)

        val top = JPanel(BorderLayout(8, 4))
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            add(statusLabel)
            add(startButton)
            add(stopButton)
        }
        val notice = JLabel("<html><i>$securityNotice</i></html>")
        top.add(controls, BorderLayout.NORTH)
        top.add(notice, BorderLayout.SOUTH)

        add(top, BorderLayout.NORTH)
        add(JScrollPane(logArea).apply {
            border = BorderFactory.createTitledBorder("Activity")
        }, BorderLayout.CENTER)

        startButton.addActionListener { toggle(start = true) }
        stopButton.addActionListener { toggle(start = false) }

        // Seed existing history, then append live.
        activityLog.snapshot().forEach { appendLine(it) }
        activityLog.addListener { entry -> SwingUtilities.invokeLater { appendLine(entry) } }

        refresh()
    }

    /** Refresh status label and button enablement from the current server state. Call on the EDT. */
    fun refresh() {
        val running = runCatching { isRunning() }.getOrDefault(false)
        statusLabel.text = if (running) "● Running  —  ${address()}" else "○ Stopped"
        startButton.isEnabled = !running
        stopButton.isEnabled = running
    }

    private fun toggle(start: Boolean) {
        startButton.isEnabled = false
        stopButton.isEnabled = false
        thread(name = "mcp-ui-${if (start) "start" else "stop"}", isDaemon = true) {
            runCatching { if (start) onStart() else onStop() }
            SwingUtilities.invokeLater { refresh() }
        }
    }

    private fun appendLine(entry: ActivityEntry) {
        logArea.append("${timeFormat.format(Date(entry.timestamp))}  ${entry.message}\n")
        logArea.caretPosition = logArea.document.length
    }
}
