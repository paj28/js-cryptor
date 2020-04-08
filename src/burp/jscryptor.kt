package burp

import java.awt.BorderLayout
import java.awt.Component
import java.awt.Font
import java.awt.Frame
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.net.URL
import javax.script.Invocable
import javax.script.ScriptEngine
import javax.script.ScriptEngineManager
import javax.swing.*
import javax.swing.JOptionPane.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener


class BurpExtender: IBurpExtender {
    companion object {
        const val name = "JS Cryptor"
        const val header = "X-JSCryptor: decrypted\r\n"
        const val dummyUrl = "http://burp/jscryptor"
        lateinit var callbacks: IBurpExtenderCallbacks
        var scriptRunner: ScriptRunner? = null
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
                return jsCryptorPanel.panel
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
    // TODO: controller could be null
    override fun createNewInstance(controller: IMessageEditorController, editable: Boolean): IMessageEditorTab {
        return MessageEditorTab(controller, editable)
    }
}


class MessageEditorTab(controller: IMessageEditorController, editable: Boolean): IMessageEditorTab {
    private val messageEditorPanel = MessageEditorPanel(controller, editable)

    override val tabCaption = BurpExtender.name

    override val uiComponent: Component
        get() = messageEditorPanel

    override val message: ByteArray
        get() = messageEditorPanel.text.toByteArray(Charsets.UTF_8)

    override val selectedData: ByteArray
        get() = messageEditorPanel.selectedText?.toByteArray(Charsets.UTF_8) ?: byteArrayOf()

    override fun isEnabled(content: ByteArray, isRequest: Boolean) = BurpExtender.scriptRunner != null

    override fun setMessage(content: ByteArray, isRequest: Boolean) {
        try {
            messageEditorPanel.text = BurpExtender.scriptRunner?.encryptOrDecrypt("decrypt", content, isRequest) ?: ""
        }
        catch(ex: Exception) {
            messageEditorPanel.text = ""
            showMessageDialog(getBurpFrame(), ex.message, BurpExtender.name, ERROR_MESSAGE);
        }
    }

    override val isModified
        get() = messageEditorPanel.modified
}


class MessageEditorPanel(private val controller: IMessageEditorController?, editable: Boolean): JPanel(), DocumentListener {
    var modified = false
    private var currentText: String? = null

    private val textArea = JTextArea()
    init {
        textArea.font = Font("Courier New", Font.PLAIN, 13)
        textArea.isEditable = editable
        textArea.document.addDocumentListener(this)
        layout = BorderLayout()
        add(JScrollPane(textArea), BorderLayout.CENTER)
        buildPopupMenu()
    }

    private fun buildPopupMenu() {
        if (controller == null) {
            return
        }
        val popupMenu = JPopupMenu()

        val sendToScanner = JMenuItem("Send to Scanner")
        sendToScanner.addActionListener {
            BurpExtender.callbacks.doActiveScan(
                controller.httpService.host,
                controller.httpService.port,
                controller.httpService.protocol == "https",
                text.toByteArray(Charsets.ISO_8859_1))
        }
        popupMenu.add(sendToScanner)

        val sendToIntruder = JMenuItem("Send to Intruder")
        sendToIntruder.addActionListener {
            BurpExtender.callbacks.sendToIntruder(
                controller.httpService.host,
                controller.httpService.port,
                controller.httpService.protocol == "https",
                text.toByteArray(Charsets.ISO_8859_1))
        }
        popupMenu.add(sendToIntruder)

        val sendToComparer = JMenuItem("Send to Comparer")
        sendToComparer.addActionListener {
            BurpExtender.callbacks.sendToComparer(text.toByteArray(Charsets.ISO_8859_1))
        }
        popupMenu.add(sendToComparer)

        textArea.componentPopupMenu = popupMenu
    }

    var text: String
        get() = textArea.text
        set(text) {
            if(currentText == text) {
                return
            }
            currentText = text
            textArea.text = text
            modified = false
        }

    val selectedText: String?
        get() = textArea.selectedText

    override fun changedUpdate(e: DocumentEvent?) {
        modified = true
    }

    override fun insertUpdate(e: DocumentEvent?) {
        modified = true
    }

    override fun removeUpdate(e: DocumentEvent?) {
        modified = true
    }
}


class SaveActionListener(val jsCryptorPanel: JsCryptorPanel): ActionListener {
    override fun actionPerformed(event: ActionEvent) {
        val panelData = PanelData()
        jsCryptorPanel.getData(panelData)
        val scriptEngineRunner = ScriptRunner(panelData.encryptFunction, panelData.decryptFunction)
        try {
            scriptEngineRunner.test()
            BurpExtender.scriptRunner = scriptEngineRunner
            panelData.save()
            showMessageDialog(getBurpFrame(), "Functions saved", BurpExtender.name, INFORMATION_MESSAGE);
        }
        catch(ex: Exception) {
            BurpExtender.scriptRunner = null
            showMessageDialog(getBurpFrame(), ex.message, BurpExtender.name, ERROR_MESSAGE);
        }
    }
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

    fun encryptOrDecrypt(operation: String, content: ByteArray, isRequest: Boolean): String {
        val bodyOffset = getBodyOffset(content, isRequest)
        val body = content.copyOfRange(bodyOffset, content.size)
        val decryptedBody = invocable.invokeFunction(operation, String(body, Charsets.ISO_8859_1))
        var headersString = String(content.copyOfRange(0, bodyOffset), Charsets.ISO_8859_1)
        if (operation == "decrypt") {
            headersString = (headersString.substring(0, headersString.length - 2)
                           + BurpExtender.header
                           + headersString.substring(headersString.length - 2))
        }
        // TODO: fixup Content-Length
        return headersString + decryptedBody
    }
}


class HttpListener: IHttpListener {
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        val scriptRunner = BurpExtender.scriptRunner ?: return

        // TODO: make this more efficient
        if (BurpExtender.header !in String(messageInfo.request, Charsets.ISO_8859_1)) {
            return
        }

        try {
            if (messageIsRequest) {
                val encryptedRequest = scriptRunner.encryptOrDecrypt("encrypt", messageInfo.request, true)
                messageInfo.request = encryptedRequest.toByteArray(Charsets.ISO_8859_1)
            } else {
                val decryptedResponse = scriptRunner.encryptOrDecrypt("decrypt", messageInfo.response, false)
                messageInfo.response = decryptedResponse.toByteArray(Charsets.ISO_8859_1)
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