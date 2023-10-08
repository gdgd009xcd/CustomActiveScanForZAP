package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules;
import org.zaproxy.zap.extension.customactivescan.Utilities;
import org.zaproxy.zap.extension.customactivescan.model.PauseActionObject;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.List;

import static org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules.MESSAGE_PREFIX;
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
    private CustomScanMainPanel customScanMainPanel;
    private List<HttpMessage> resultMessageList;
    private String flagColumnRegexString;

    public ScanLogPanel(CustomScanMainPanel customScanMainPanel, String[] flagColumns, int scannerId, boolean isPaused) {
        super();
        setLayout(new BorderLayout());

        this.resultMessageList = new ArrayList<>();
        this.customScanMainPanel = customScanMainPanel;
        pauseCheckBoxActionMask = false;

        JPanel horizontalPane = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        horizontalPane.setLayout(gridBagLayout);

        // Grid 0,0 : pause checkbox
        ImageIcon pauseIcon = MyFontUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/pause.png")));
        ImageIcon runIcon = MyFontUtils.getScaledIcon(new ImageIcon(ScanLogPanel.class.getResource(ZAP_ICONS + "/run.png")));
        pauseCheckBox = new JCheckBox(Constant.messages.getString(MESSAGE_PREFIX + "text.running.pausecheckbox"), pauseIcon);
        pauseCheckBox.setToolTipText(Constant.messages.getString(MESSAGE_PREFIX + "tooltip.pausecheckbox"));

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
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        //gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.1d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,1,1,1);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gridBagLayout.setConstraints(pauseCheckBox, gbc);
        horizontalPane.add(pauseCheckBox);



        // Grid 1,0: randomize checkbox
        JCheckBox randomizeIdleTimeCheckBox = new JCheckBox(Constant.messages.getString(MESSAGE_PREFIX + "title.randomidletime"));
        randomizeIdleTimeCheckBox.setSelected(this.customScanMainPanel.isRandomizeIdleTime());
        randomizeIdleTimeCheckBox.setToolTipText(Constant.messages.getString(MESSAGE_PREFIX + "tooltip.randomidletime"));
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.1d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,1,1,1);
        //gbc.anchor = GridBagConstraints.NORTHEAST;
        gridBagLayout.setConstraints(randomizeIdleTimeCheckBox, gbc);
        horizontalPane.add(randomizeIdleTimeCheckBox);


        // Grid 0,1: request count text field
        LineBorder requestCountLineBorder = new LineBorder(Color.BLUE, 1, true);
        String requestCountTitleString = Constant.messages.getString(MESSAGE_PREFIX + "title.sendingrequestcount");
        int requestCountColumnSize = requestCountTitleString.length() + 2;
        TitledBorder requestCountTitledBorder = new TitledBorder(requestCountLineBorder,
                requestCountTitleString,
                TitledBorder.LEFT,
                TitledBorder.TOP);
        requestCountTextField = new JTextField(this.customScanMainPanel.getRequestCountValue(), requestCountColumnSize);
        requestCountTextField.setToolTipText(Constant.messages.getString(MESSAGE_PREFIX + "tooltip.sendingrequestcount"));
        requestCountTextField.setInputVerifier(new RequestCountVerifier(this.customScanMainPanel));
        requestCountTextField.setBorder(requestCountTitledBorder);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        //gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.1d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,1,1,1);
        //gbc.anchor = GridBagConstraints.NORTHEAST;
        gridBagLayout.setConstraints(requestCountTextField, gbc);
        horizontalPane.add(requestCountTextField);

        // Grid 1,1: minium idle time textfield
        LineBorder minIdleTimeLineBorder = new LineBorder(Color.BLUE, 1, true);
        String minIdleTimeTitleString = Constant.messages.getString(MESSAGE_PREFIX + "title.minidletime");
        int minIdleTimeColumnSize = minIdleTimeTitleString.length() + 2;
        TitledBorder minIdleTimeTitledBorder = new TitledBorder(minIdleTimeLineBorder,
                minIdleTimeTitleString,
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JTextField minIdleTimeTextField = new JTextField(this.customScanMainPanel.getMinimumIdleTimeTextFieldValue(), minIdleTimeColumnSize);
        minIdleTimeTextField.setToolTipText(Constant.messages.getString(MESSAGE_PREFIX + "tooltip.minidletime"));
        minIdleTimeTextField.setInputVerifier(new MinIdleTimeVerifier(this.customScanMainPanel));
        minIdleTimeTextField.setBorder(minIdleTimeTitledBorder);
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        // gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.1d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,1,1,1);
        //gbc.anchor = GridBagConstraints.NORTHEAST;
        gridBagLayout.setConstraints(minIdleTimeTextField, gbc);
        horizontalPane.add(minIdleTimeTextField);

        // Grid 2,1: maximum idle time textfield
        LineBorder maxIdleTimeLineBorder = new LineBorder(Color.BLUE, 1, true);
        String maxIdleTimeTitleString = Constant.messages.getString(MESSAGE_PREFIX + "title.maxidletime");
        int maxIdleTimeColumnSize = maxIdleTimeTitleString.length() + 2;
        TitledBorder maxIdleTimeTitledBorder = new TitledBorder(maxIdleTimeLineBorder,
                maxIdleTimeTitleString,
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JTextField maxIdleTimeTextField = new JTextField(this.customScanMainPanel.getMaximumIdleTimeTextFieldValue(), maxIdleTimeColumnSize);
        maxIdleTimeTextField.setInputVerifier(new MaxIdleTimeVerifier(this.customScanMainPanel));
        maxIdleTimeTextField.setToolTipText(Constant.messages.getString(MESSAGE_PREFIX + "tooltip.maxidletime"));
        maxIdleTimeTextField.setBorder(maxIdleTimeTitledBorder);
        gbc.gridx = 2;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        // gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.1d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,1,1,1);
        //gbc.anchor = GridBagConstraints.NORTHEAST;
        gridBagLayout.setConstraints(maxIdleTimeTextField, gbc);
        horizontalPane.add(maxIdleTimeTextField);

        add(horizontalPane, BorderLayout.PAGE_START);

        // ScanLog area
        JScrollPane scanLogScroller = new JScrollPane();
        scanLogScroller.setPreferredSize(new Dimension(400,400));
        scanLogScroller.setAutoscrolls(true);

        String[] baseColumnNames = {"Time", "Method", "URL", "Code", "Reason", "Length"};
        totalColumnNames = baseColumnNames;
        flagColumnRegexString = "";
        if (flagColumns != null && flagColumns.length > 0) {
            totalColumnNames = new String[baseColumnNames.length + flagColumns.length];
            System.arraycopy(baseColumnNames, 0, totalColumnNames, 0, baseColumnNames.length);
            System.arraycopy(flagColumns, 0, totalColumnNames, baseColumnNames.length, flagColumns.length);
            for(String flag: flagColumns) {
                if (!flagColumnRegexString.isEmpty()) {
                    flagColumnRegexString += "|";
                }
                flagColumnRegexString += flag;
            }
        }
        scanLogTableModel = new DefaultTableModel(new String[0][0], totalColumnNames);
        scanLogTable = new JTable(scanLogTableModel);


        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem menuShowSelectedMessage = new JMenuItem("show");
        menuShowSelectedMessage.addActionListener(l ->{
            int selectedRowIndex = scanLogTable.getSelectedRow();
            if (selectedRowIndex != -1) {
                showSelectedMessage(selectedRowIndex);
            }
        });
        popupMenu.add(menuShowSelectedMessage);
        scanLogTable.setComponentPopupMenu(popupMenu);
        scanLogTable.addMouseListener(new JTableRowSelector(scanLogTable));
        scanLogScroller.setViewportView(scanLogTable);
        add(scanLogScroller, BorderLayout.CENTER);
    }

    public void disablePauseCheckBox() {
        this.pauseCheckBox.setText(Constant.messages.getString(MESSAGE_PREFIX + "text.completed.pausecheckbox"));
        this.pauseCheckBox.setEnabled(false);
    }

    public boolean setSelectedPauseAction(int scannerId, boolean isPaused) {
        if (isPaused) {
            if (pauseActionObject.createNewThread(scannerId)) {
                pauseCheckBox.setText(Constant.messages.getString(MESSAGE_PREFIX + "text.pause.pausecheckbox"));
                return true;
            } else {
                return false;
            }
        } else {
            pauseActionObject.terminateWaitingThread();
            pauseCheckBox.setText(Constant.messages.getString(MESSAGE_PREFIX + "text.running.pausecheckbox"));
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

    public void addRowToScanLogTableModel(String[] rowData, HttpMessage resultMessage) {
        scanLogTableModel.addRow(rowData);
        resultMessageList.add(resultMessage);
    }

    private void showSelectedMessage(int selectedTableRowIndex) {
        LOGGER4J.debug("selected row:" + selectedTableRowIndex);
        HttpMessage selectedMessage = resultMessageList.get(selectedTableRowIndex);
        if (selectedMessage != null) {
            String requestString = selectedMessage.getRequestHeader().toString() + selectedMessage.getRequestBody().toString();
            String responseString = selectedMessage.getResponseHeader().toString() + selectedMessage.getResponseBody().toString();
            RegexTestDialog.PaneContents paneContents = new RegexTestDialog.PaneContents(this.flagColumnRegexString);
            paneContents.addTitleAndContent("Request", requestString);
            paneContents.addTitleAndContent("Response", responseString);
            RegexTestDialog regexTestDialog = new RegexTestDialog(SwingUtilities.windowForComponent(this),"Result", Dialog.ModalityType.MODELESS, paneContents);
            regexTestDialog.selectTabbedPane(1);
            regexTestDialog.setVisible(true);
            regexTestDialog.resetScrollBarToLeftTop();
            regexTestDialog.regexSearchActionPerformed(null);
        }
    }
}
