package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.CustomScanJSONData;

import javax.swing.*;
import java.awt.*;

public class MaxIdleTimeVerifier extends NumberTextVerifier {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private CustomScanMainPanel customScanMainPanel;

    MaxIdleTimeVerifier(CustomScanMainPanel customScanMainPanel) {
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
            int maxIdleTimeValue = 0;
            try {
                maxIdleTimeValue = Integer.parseInt(inputString);
            } catch (NumberFormatException ex) {
                maxIdleTimeValue = 0;
            }
            LOGGER4J.debug("MaxIdleTime value:" + maxIdleTimeValue + " before fileSaveAction");
            selectedScanRule.setMaxIdleTime(maxIdleTimeValue);// set input to selected ScanRule
            customScanMainPanel.fileSaveAction();// save to file.
        } else {
            Toolkit.getDefaultToolkit().beep();// beep to signal input error
            CustomScanJSONData.ScanRule selectedScanRule = customScanMainPanel.getSelectedScanRule();
            JTextField jTextField = (JTextField) input;
            int currentValue = selectedScanRule.getMaxIdleTime();
            jTextField.setText(Integer.toString(currentValue));// restore input to current value
            LOGGER4J.debug("MaxIdleTime parentResult false");
        }
    }
}
