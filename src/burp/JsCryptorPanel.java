package burp;

import javax.swing.*;

public class JsCryptorPanel {
    private JTextArea encryptFunction;
    private JTextArea decryptFunction;
    public JPanel panel;
    private JButton saveButton;

    public JsCryptorPanel() {
        saveButton.addActionListener(new SaveActionListener(this));
    }

    public void setData(PanelData data) {
        encryptFunction.setText(data.getEncryptFunction());
        decryptFunction.setText(data.getDecryptFunction());
    }

    public void getData(PanelData data) {
        data.setEncryptFunction(encryptFunction.getText());
        data.setDecryptFunction(decryptFunction.getText());
    }

    public boolean isModified(PanelData data) {
        if (encryptFunction.getText() != null ? !encryptFunction.getText().equals(data.getEncryptFunction()) : data.getEncryptFunction() != null)
            return true;
        if (decryptFunction.getText() != null ? !decryptFunction.getText().equals(data.getDecryptFunction()) : data.getDecryptFunction() != null)
            return true;
        return false;
    }
}
