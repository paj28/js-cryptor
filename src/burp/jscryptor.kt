package burp

import java.awt.BorderLayout
import java.awt.Component
import java.awt.Frame
import java.lang.Integer.min
import java.net.URL
import javax.script.Invocable
import javax.script.ScriptEngine
import javax.script.ScriptEngineManager
import javax.swing.JButton
import javax.swing.JMenuItem
import javax.swing.JOptionPane.*
import javax.swing.JPanel
import javax.swing.SwingUtilities


class BurpExtender: IBurpExtender {
    companion object {
        const val name = "JS Cryptor"
        const val header = "X-JSCryptor: decrypted\r\n"
        val headerByteArray = header.toByteArray(Charsets.ISO_8859_1)
        const val dummyUrl = "http://burp/jscryptor"
        lateinit var callbacks: IBurpExtenderCallbacks
        var scriptRunner: ScriptRunner? = null

        fun savePanelData(panelData: PanelData) {
            val scriptEngineRunner = ScriptRunner(panelData.encryptFunction, panelData.decryptFunction)
            try {
                scriptEngineRunner.test()
                scriptRunner = scriptEngineRunner
                panelData.save()
                showMessageDialog(getBurpFrame(), "Functions saved", BurpExtender.name, INFORMATION_MESSAGE);
            } catch (ex: Exception) {
                scriptRunner = null
                showMessageDialog(getBurpFrame(), ex.message, BurpExtender.name, ERROR_MESSAGE);
            }
        }
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        Companion.callbacks = callbacks
        callbacks.setExtensionName(BurpExtender.name)

        val panelData = loadPanelData()
        val scriptRunner = ScriptRunner(panelData.encryptFunction, panelData.decryptFunction)
        try {
            scriptRunner.test()
            Companion.scriptRunner = scriptRunner
        }
        catch (ex: java.lang.Exception) {
            // do nothing
        }

        callbacks.addSuiteTab(JsCryptorTab(panelData))
        callbacks.registerMessageEditorTabFactory(MessageEditorTabFactory())
        callbacks.registerHttpListener(HttpListener())
    }
}


class JsCryptorTab(private val panelData: PanelData): ITab {
    override val tabCaption = BurpExtender.name
    override val uiComponent: Component
            get() {
                val jsCryptorPanel = JsCryptorPanel()
                jsCryptorPanel.setData(panelData)
                return jsCryptorPanel
            }
}


class PanelData {
    var encryptFunction= ""
    var decryptFunction = ""

    fun save() {
        val serializedConfig = listOf(encryptFunction, decryptFunction).joinToString("\u0000")
        BurpExtender.callbacks.addToSiteMap(DummyHttpRequestResponse(serializedConfig))
    }
}


fun loadPanelData(): PanelData {
    val panelData = PanelData()
    try {
        val siteMap = BurpExtender.callbacks.getSiteMap(BurpExtender.dummyUrl)
        if (siteMap.isNotEmpty()) {
            val configList = String(siteMap[0].response, Charsets.ISO_8859_1).split("\u0000")
            panelData.encryptFunction = configList[0]
            panelData.decryptFunction = configList[1]
        }
    }
    catch (ex: java.lang.Exception) {
        // do nothing
    }
    return panelData
}


class DummyHttpRequestResponse(private val config: String): IHttpRequestResponse {
    override var comment = "JS Cryptor configuration"
    override var highlight = "" // TODO: null
    override var httpService = BurpExtender.callbacks.helpers.buildHttpService("burp", 80, false)
    override var request = BurpExtender.callbacks.helpers.buildHttpRequest(URL(BurpExtender.dummyUrl))
    override var response = config.toByteArray(Charsets.ISO_8859_1)
}


class MessageEditorTabFactory: IMessageEditorTabFactory {
    override fun createNewInstance(controller: IMessageEditorController?, editable: Boolean): IMessageEditorTab {
        return MessageEditorTab(controller, editable)
    }
}


class MessageEditorTab(controller: IMessageEditorController?, editable: Boolean): IMessageEditorTab {

    var messageIsRequest: Boolean = false

    override val uiComponent = MessageEditorPanel(controller, editable)
    override val tabCaption = BurpExtender.name
    override fun isEnabled(content: ByteArray, isRequest: Boolean) = BurpExtender.scriptRunner != null
    override val isModified
            get() = uiComponent.textEditor.isTextModified
    override val selectedData
            get() = uiComponent.textEditor.selectedText

    override val message: ByteArray
        get() {
            try {
                val scriptRunner = BurpExtender.scriptRunner ?: return uiComponent.textEditor.text
                return scriptRunner.encryptOrDecrypt("encrypt", uiComponent.textEditor.text, messageIsRequest)
            }
            catch(ex: Exception) {
                SwingUtilities.invokeLater {
                    showMessageDialog(getBurpFrame(), ex.message, BurpExtender.name, ERROR_MESSAGE);
                }
                return uiComponent.textEditor.text
            }
        }

    override fun setMessage(content: ByteArray, isRequest: Boolean) {
        try {
            messageIsRequest = isRequest
            uiComponent.textEditor.text = BurpExtender.scriptRunner?.encryptOrDecrypt("decrypt", content, isRequest) ?: byteArrayOf()
        }
        catch(ex: Exception) {
            uiComponent.textEditor.text = byteArrayOf()
            SwingUtilities.invokeLater {
                showMessageDialog(getBurpFrame(), ex.message, BurpExtender.name, ERROR_MESSAGE);
            }
        }
    }
}


class MessageEditorPanel(private val controller: IMessageEditorController?, editable: Boolean): JPanel() {
    val textEditor = BurpExtender.callbacks.createTextEditor()

    init {
        textEditor.setEditable(editable)
        layout = BorderLayout()
        add(textEditor.component, BorderLayout.CENTER)

        if (controller != null) {
            val bottomPanel = JPanel()
            val sendToScanner = JButton("Send to Scanner")
            sendToScanner.addActionListener {
                BurpExtender.callbacks.doActiveScan(
                        controller.httpService.host,
                        controller.httpService.port,
                        controller.httpService.protocol == "https",
                        addHeaderToRequest(textEditor.text).toByteArray(Charsets.ISO_8859_1))
            }
            bottomPanel.add(sendToScanner)

            val sendToIntruder = JButton("Send to Intruder")
            sendToIntruder.addActionListener {
                BurpExtender.callbacks.sendToIntruder(
                        controller.httpService.host,
                        controller.httpService.port,
                        controller.httpService.protocol == "https",
                        addHeaderToRequest(textEditor.text).toByteArray(Charsets.ISO_8859_1))
            }
            bottomPanel.add(sendToIntruder)

            val sendToComparer = JButton("Send to Comparer")
            sendToComparer.addActionListener {
                BurpExtender.callbacks.sendToComparer(textEditor.text)
            }
            bottomPanel.add(sendToComparer)
            add(bottomPanel, BorderLayout.SOUTH)
        }
    }
}


fun addHeaderToRequest(request: ByteArray): String {
    val requestInfo = BurpExtender.callbacks.helpers.analyzeRequest(request)
    val requestString = String(request, Charsets.ISO_8859_1)
    return (requestString.substring(0, requestInfo.bodyOffset - 2)
            + BurpExtender.header + "\r\n"
            + requestString.substring(requestInfo.bodyOffset))
}


class ScriptRunner(
    private val encryptFunction: String,
    private val decryptFunction: String
) {
    private val scriptEngineManager = ScriptEngineManager()
    private val scriptEngine: ScriptEngine = scriptEngineManager.getEngineByName("nashorn")
    private val invocable = scriptEngine as Invocable

    fun test() {
        scriptEngine.eval(encryptFunction)
        val result = invocable.invokeFunction("encrypt", "test")
        if (result !is String) {
            throw Exception("Encrypt function must return a string")
        }

        scriptEngine.eval(decryptFunction)
        val result2 = invocable.invokeFunction("decrypt", "test")
        if (result2 !is String) {
            throw Exception("Decrypt function must return a string")
        }
    }

    private fun getBodyOffset(content: ByteArray, isRequest: Boolean): Int {
        if (isRequest) {
            return BurpExtender.callbacks.helpers.analyzeRequest(content).bodyOffset
        } else {
            return BurpExtender.callbacks.helpers.analyzeResponse(content).bodyOffset
        }
    }

    fun encryptOrDecrypt(operation: String, content: ByteArray, isRequest: Boolean): ByteArray {
        val bodyOffset = getBodyOffset(content, isRequest)
        val body = content.copyOfRange(bodyOffset, content.size)
        val convertedBody = invocable.invokeFunction(operation, String(body, Charsets.ISO_8859_1))
        var headersString = String(content.copyOfRange(0, bodyOffset), Charsets.ISO_8859_1)
        // TODO: fixup Content-Length
        return (headersString + convertedBody).toByteArray(Charsets.ISO_8859_1)
    }
}


class HttpListener: IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        val scriptRunner = BurpExtender.scriptRunner ?: return

        if (!findArrayInArray(BurpExtender.headerByteArray, messageInfo.request)) {
            return
        }

        try {
            if (messageIsRequest) {
                messageInfo.request = scriptRunner.encryptOrDecrypt("encrypt", messageInfo.request, true)
            } else {
                messageInfo.response = scriptRunner.encryptOrDecrypt("decrypt", messageInfo.response, false)
            }
        }
        catch (ex: Exception) {
            BurpExtender.callbacks.issueAlert(ex.message ?: "Unknown error")
        }
    }
}


fun getBurpFrame(): Frame? {
    return Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
}


fun findArrayInArray(needle: ByteArray, haystack: ByteArray): Boolean {
    val end = min(1024, haystack.size) - needle.size;
    val firstByte = needle[0]
    outer@ for (i in 0 .. end) {
        if (haystack[i] == firstByte) {
            for (j in 1 .. needle.lastIndex) {
                if (haystack[i + j] != needle[j]) {
                    break@outer
                }
            }
            return true
        }
    }
    return false
}
