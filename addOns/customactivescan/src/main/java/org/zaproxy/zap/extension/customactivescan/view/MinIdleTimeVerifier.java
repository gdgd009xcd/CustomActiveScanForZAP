package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.CustomScanJSONData;

import javax.swing.*;
import java.awt.*;

public class MinIdleTimeVerifier extends NumberTextVerifier {
    private CustomScanMainPanel customScanMainPanel;

    MinIdleTimeVerifier(CustomScanMainPanel customScanMainPanel) {
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
        if(isVerifyCalled()) {
            if (parentResult) {
                JTextField jTextField = (JTextField) input;
                String inputString = jTextField.getText();
                CustomScanJSONData.ScanRule selectedScanRule = customScanMainPanel.getSelectedScanRule();
                int minIdleTimeValue = 0;
                try {
                    minIdleTimeValue = Integer.parseInt(inputString);
                } catch (NumberFormatException ex) {
                    minIdleTimeValue = 0;
                }
                selectedScanRule.setMinIdleTime(minIdleTimeValue);// set input to selected ScanRule
                customScanMainPanel.fileSaveAction();// save to file
            } else {
                Toolkit.getDefaultToolkit().beep();// beep to signal input error
                CustomScanJSONData.ScanRule selectedScanRule = customScanMainPanel.getSelectedScanRule();
                JTextField jTextField = (JTextField) input;
                int currentValue = selectedScanRule.getMinIdleTime();
                jTextField.setText(Integer.toString(currentValue));// restore input to current value
            }
        }
        ClearIsVerifyCalled();
    }
}
