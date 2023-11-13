package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules;
import org.zaproxy.zap.extension.tab.Tab;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import java.awt.*;

@SuppressWarnings("serial")
public class MainWorkPanelTab extends AbstractPanel {
    public MainWorkPanelTab(ExtensionHook exhook, ExtensionAscanRules extensionAscan) {
        setLayout(new CardLayout());
        this.setName("CustomActiveScan");
        this.setIcon(ExtensionAscanRules.cIcon);
        CustomScanMainPanel mainPanel = new CustomScanMainPanel();
        extensionAscan.setCustomScanMainPanel(mainPanel);
        Border mainBorder = new LineBorder(Color.RED, 1);
        mainPanel.setBorder(mainBorder);
        // set scrolledwindow. if you do not specify scrolledwindow, then mainPanel window size is shrinked(packed) with WorkPanelSize.
        JScrollPane scroller = new JScrollPane();
        scroller.setViewportView(mainPanel);
        scroller.setAutoscrolls(true);
        this.add(scroller);
    }
}
