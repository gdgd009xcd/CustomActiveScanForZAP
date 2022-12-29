package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;

import static org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules.ZAP_ICONS;

@SuppressWarnings("serial")
public class ScanLogPanel extends JPanel {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public ScanLogPanel(String[] flagColumns) {
        super();
        setLayout(new BorderLayout());

        // pause button
        JPanel horizontalPane = new JPanel(new FlowLayout(FlowLayout.LEFT));

        ImageIcon pauseIcon = MyFontUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/pause.png")));
        ImageIcon runIcon = MyFontUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/run.png")));
        JCheckBox pauseCheckBox = new JCheckBox("Running", pauseIcon);
        pauseCheckBox.setSelected(false);
        pauseCheckBox.setSelectedIcon(runIcon);
        pauseCheckBox.addItemListener(e -> {
            boolean isSelected = e.getStateChange() == ItemEvent.SELECTED ? true : false;
            if (isSelected) {
                pauseCheckBox.setText("Paused");
            } else {
                pauseCheckBox.setText("Running");
            }
            LOGGER4J.debug(isSelected?"Pause":"Run");
        });

        horizontalPane.add(pauseCheckBox);

        add(horizontalPane, BorderLayout.PAGE_START);

        // ScanLog area
        JScrollPane scanLogScroller = new JScrollPane();
        scanLogScroller.setPreferredSize(new Dimension(400,400));
        scanLogScroller.setAutoscrolls(true);

        String[] baseColumnNames = {"Time", "Method", "URL", "Code", "Reason", "Length"};
        String[] totalColumnNames = baseColumnNames;
        if (flagColumns != null && flagColumns.length > 0) {
            totalColumnNames = new String[baseColumnNames.length + flagColumns.length];
            System.arraycopy(baseColumnNames, 0, totalColumnNames, 0, baseColumnNames.length);
            System.arraycopy(flagColumns, 0, totalColumnNames, baseColumnNames.length, flagColumns.length);
        }
        JTable scanLogTable = new JTable(new String[0][0], totalColumnNames);
        scanLogScroller.setViewportView(scanLogTable);
        add(scanLogScroller, BorderLayout.CENTER);
    }
}
