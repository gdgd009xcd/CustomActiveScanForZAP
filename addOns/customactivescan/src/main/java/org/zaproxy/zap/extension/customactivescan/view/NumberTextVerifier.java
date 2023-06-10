package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NumberTextVerifier extends InputVerifier {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private int len;
    private boolean isPlusNumber;
    private boolean isPrefixFilledWithZero;

    NumberTextVerifier(int len, boolean isPlusNumber, boolean isPrefixFilledWithZero){
        this.len = len;
        this.isPlusNumber = isPlusNumber;
        this.isPrefixFilledWithZero = isPrefixFilledWithZero;
    }

    @Override
    public boolean verify(JComponent jComponent) {
        JTextField jTextField = (JTextField) jComponent;
        String inputString = jTextField.getText();
        LOGGER4J.debug("verify [" + inputString + "]");
        return isValidNumeric(inputString);
    }



    private boolean isValidNumeric(String inputString) {
        boolean inputIsNumeric = false;
        try {
            int number = Integer.parseInt(inputString);
            if (!this.isPrefixFilledWithZero) {
                Pattern compiledRegex = Pattern.compile("^0+\\d+", Pattern.MULTILINE);
                Matcher m = compiledRegex.matcher(inputString);
                if (m.find()) {
                    return false;
                }
            }
            if (this.isPlusNumber) {
                if (number < 0) {
                    return false;
                }
            }
            inputIsNumeric = true;
        } catch (NumberFormatException ex) {
            if (inputString == null || inputString.isEmpty()) {
                return true;
            }
        }
        return inputIsNumeric;
    }
}
