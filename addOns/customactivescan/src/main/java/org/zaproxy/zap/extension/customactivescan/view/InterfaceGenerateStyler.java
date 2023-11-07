package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.text.StyledDocument;
import javax.swing.text.Style;

public interface InterfaceGenerateStyler {
    public Style getStyle(StyledDocument doc, String text);
}
