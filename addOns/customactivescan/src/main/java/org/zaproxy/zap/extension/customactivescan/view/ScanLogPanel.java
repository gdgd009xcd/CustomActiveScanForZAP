package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules;
import org.zaproxy.zap.extension.customactivescan.model.PauseActionObject;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ItemEvent;

import static org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules.ZAP_ICONS;

@SuppressWarnings("serial")
public class ScanLogPanel extends JPanel {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private JCheckBox pauseCheckBox;
    JTextField requestCountTextField;
    JTable scanLogTable;
    DefaultTableModel scanLogTableModel;
    private PauseActionObject pauseActionObject;
    private Thread pauseActionThread;
    private boolean pauseCheckBoxActionMask;
    private String[] totalColumnNames;

    public ScanLogPanel(String[] flagColumns, int scannerId, boolean isPaused) {
        super();
        setLayout(new BorderLayout());

        pauseCheckBoxActionMask = false;

        // pause button
        JPanel horizontalPane = new JPanel(new FlowLayout(FlowLayout.LEFT));

        ImageIcon pauseIcon = MyFontUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/pause.png")));
        ImageIcon runIcon = MyFontUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/run.png")));
        pauseCheckBox = new JCheckBox("Running", pauseIcon);

        pauseActionObject = new PauseActionObject();

        ExtensionAscanRules.scannerIdPauseActionMap.put(scannerId, pauseActionObject);

        pauseActionThread = null;
        pauseCheckBox.setSelectedIcon(runIcon);
        pauseCheckBox.addItemListener(e -> {
            boolean isSelected = e.getStateChange() == ItemEvent.SELECTED ? true : false;
            if (!pauseCheckBoxActionMask) {
                setSelectedPauseAction(scannerId, isSelected);
            } else {
                pauseCheckBoxActionMask = false;
            }
            LOGGER4J.debug(isSelected ? "Pause" : "Run");

        });
        pauseCheckBox.setSelected(isPaused);

        horizontalPane.add(pauseCheckBox);
        JLabel requestCountLabel = new JLabel("| Req.Cnt");
        requestCountTextField = new JTextField(5);
        requestCountTextField.setText("3");
        requestCountTextField.setToolTipText("Sending Request count until next pausing");
        horizontalPane.add(requestCountLabel);
        horizontalPane.add(requestCountTextField);

        add(horizontalPane, BorderLayout.PAGE_START);

        // ScanLog area
        JScrollPane scanLogScroller = new JScrollPane();
        scanLogScroller.setPreferredSize(new Dimension(400,400));
        scanLogScroller.setAutoscrolls(true);

        String[] baseColumnNames = {"Time", "Method", "URL", "Code", "Reason", "Length"};
        totalColumnNames = baseColumnNames;
        if (flagColumns != null && flagColumns.length > 0) {
            totalColumnNames = new String[baseColumnNames.length + flagColumns.length];
            System.arraycopy(baseColumnNames, 0, totalColumnNames, 0, baseColumnNames.length);
            System.arraycopy(flagColumns, 0, totalColumnNames, baseColumnNames.length, flagColumns.length);
        }
        scanLogTableModel = new DefaultTableModel(new String[0][0], totalColumnNames);
        scanLogTable = new JTable(scanLogTableModel);

        scanLogScroller.setViewportView(scanLogTable);
        add(scanLogScroller, BorderLayout.CENTER);
    }

    public void disablePauseCheckBox() {
        this.pauseCheckBox.setText("Completed.");
        this.pauseCheckBox.setEnabled(false);
    }

    public boolean setSelectedPauseAction(int scannerId, boolean isPaused) {
        if (isPaused) {
            if (pauseActionObject.createNewThread(scannerId)) {
                pauseCheckBox.setText("Paused");
                return true;
            } else {
                return false;
            }
        } else {
            pauseActionObject.terminateWaitingThread();
            pauseCheckBox.setText("Running");
        }
        return true;
    }

    public void setSelectedPauseCheckBox(boolean isPaused, boolean actionMasked) {
        pauseCheckBoxActionMask = actionMasked;
        pauseCheckBox.setSelected(isPaused);
    }

    public int getRequestCount() {
        String stringValue = this.requestCountTextField.getText();
        try {
            int count = Integer.parseInt(stringValue);
            return count > 0 ? count : -1;
        } catch(NumberFormatException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        return -1;
    }

    public PauseActionObject getPauseActionObject() {
        return this.pauseActionObject;
    }

    protected void updateRequestCounter(int offset) {
        int count = getRequestCount();
        if (this.pauseActionObject != null) {
            this.pauseActionObject.setCounter(count + offset);
        }
    }

    public int totalColumnCount() {
        return totalColumnNames.length;
    }

    public void addRowToScanLogTableModel(String[] rowData) {
        scanLogTableModel.addRow(rowData);
    }
}
