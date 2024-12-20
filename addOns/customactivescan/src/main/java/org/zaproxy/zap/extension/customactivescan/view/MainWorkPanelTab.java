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
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private ExtensionHook extensionHook;
    private ExtensionAscanRules extensionAscan;
    private boolean isBuildCalled = false;

    protected MainWorkPanelTab(ExtensionHook extensionHook, ExtensionAscanRules extensionAscan) {
        super();
        this.extensionHook = extensionHook;
        this.extensionAscan = extensionAscan;
    }

    /**
     * new instance method<br>
     * you must define this in your extended classes for instantiation
     *
     * @param extensionHook
     * @param extensionAscan
     * @return
     */
    public static final MainWorkPanelTab newInstance(ExtensionHook extensionHook, ExtensionAscanRules extensionAscan) {
        MainWorkPanelTab mainWorkPanelTab = new MainWorkPanelTab(extensionHook, extensionAscan);
        return mainWorkPanelTab.buildMainWorkPanelTab();
    }

    /**
     * build this GUI.<br>
     * you must call this method after creating this object.
     *
     * @return this object
     */
    protected final MainWorkPanelTab buildMainWorkPanelTab() {
        setLayout(new CardLayout());
        this.setName("CustomActiveScan");
        this.setIcon(ExtensionAscanRules.cIcon);
        CustomScanMainPanel mainPanel = new CustomScanMainPanel(this).build();
        extensionAscan.setCustomScanMainPanel(mainPanel);
        Border mainBorder = new LineBorder(Color.RED, 1);
        mainPanel.setBorder(mainBorder);
        // set scrolledwindow. if you do not specify scrolledwindow, then mainPanel window size is shrinked(packed) with WorkPanelSize.
        JScrollPane scroller = new JScrollPane();
        scroller.setViewportView(mainPanel);
        scroller.setAutoscrolls(true);
        this.add(scroller);
        this.isBuildCalled = true;
        return this;
    }

    public void setVisible(boolean isVisible) {
        if (this.isBuildCalled) {
            super.setVisible(isVisible);
        } else {
            LOGGER4J.error("You must call build() method before calling setVisible()");
            throw new IllegalStateException("You must call build() method before calling setVisible()");
        }
    }
}
