package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.CustomScanJSONData;

import javax.swing.*;
import java.awt.*;

public class RequestCountVerifier extends NumberTextVerifier {
    private CustomScanMainPanel customScanMainPanel;

    RequestCountVerifier(CustomScanMainPanel customScanMainPanel) {
        super(5, false, false);
        this.customScanMainPanel = customScanMainPanel;
    }

    /**
     * Approve focus moving to other target component
     * @param input
     * @return if input value is valid(verify function returns true) then return true.
     */
    @Deprecated(since = "9")
    @Override
    public boolean shouldYieldFocus(JComponent input) {
        boolean parentResult = super.shouldYieldFocus(input);
        shouldYieldFocusInternal(parentResult, input);
        return parentResult;
    }

    /**
     * Approve focus moving to other target component
     * @param input
     * @param target
     * @return if input value is valid(verify function returns true) then return true.
     * @since 9
     */
    @Override
    public boolean shouldYieldFocus(JComponent input, JComponent target) {
        boolean parentResult = super.shouldYieldFocus(input, target);
        shouldYieldFocusInternal(parentResult, input);
        return parentResult;
    }

    private void shouldYieldFocusInternal(boolean parentResult, JComponent input) {
        if (parentResult) {
            JTextField jTextField = (JTextField) input;
            String inputString = jTextField.getText();
            CustomScanJSONData.ScanRule selectedScanRule = customScanMainPanel.getSelectedScanRule();
            int requestCountValue = 0;
            try {
                requestCountValue = Integer.parseInt(inputString);
            } catch (NumberFormatException ex) {
                requestCountValue = 0;
            }
            selectedScanRule.setRequestCount(requestCountValue);// set input to selected ScanRule
            customScanMainPanel.fileSaveAction();// save to file
        } else {
            Toolkit.getDefaultToolkit().beep();// beep to signal input error
            CustomScanJSONData.ScanRule selectedScanRule = customScanMainPanel.getSelectedScanRule();
            JTextField jTextField = (JTextField) input;
            int currentValue = selectedScanRule.getRequestCount();
            jTextField.setText(Integer.toString(currentValue));// restore input to current value
        }
    }
}
