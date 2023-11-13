package org.zaproxy.zap.extension.customactivescan.view;

import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.customactivescan.*;
import org.zaproxy.zap.extension.customactivescan.model.AttackTitleType;
import org.zaproxy.zap.extension.customactivescan.model.CustomScanJSONData;
import org.zaproxy.zap.extension.customactivescan.model.PauseActionObject;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules.ZAP_ICONS;

@SuppressWarnings("serial")
public class ScanLogPanel extends JPanel implements DisposeChildInterface, InterfaceRenderCondition, InterfacePopUpAction {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private final String[] baseColumnNames = {
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col0.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col1.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col2.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col3.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col4.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col5.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col6.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col7.text"),
    };
    private final String[] baseColumnToolTips = {
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col0.tooltip.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col1.tooltip.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col2.tooltip.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col3.tooltip.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col4.tooltip.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col5.tooltip.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col6.tooltip.text"),
            Constant.messages.getString("customactivescan.ScanLogPanel.baseColumnNames.col7.tooltip.text"),
    };

    private final int scanLogScrollerWidth = 800;
    private final int[] basesColumnPreferredSizes = {
            10,
            10,
            10,
            7,
            10,
            10,
            38,
            5,
    };

    private final Color WHITE_GRRENTEA_COLOR =  new Color(217,247,165);
    JFrame jFrame = null;
    private JCheckBox pauseCheckBox;
    JTextField requestCountTextField;
    JTable scanLogTable;
    DefaultTableModel scanLogTableModel;
    private PauseActionObject pauseActionObject;
    private boolean pauseCheckBoxActionMask;
    private String[] totalColumnNames;
    private CustomScanMainPanel customScanMainPanel;
    private List<HttpMessageWithLCSResponse> resultMessageList;
    private String flagColumnRegexString;
    RegexTestDialog regexTestDialog;
    int currentSelectedTableRowIndex = -1;
    int firstTargetRowIndex = -1;
    HttpMessage selectedMessage = null;
    private int scannerId;

    private ParmGenMacroTraceParams pmtParams = null;

    public ScanLogPanel(JFrame jFrame, CustomScanMainPanel customScanMainPanel, String[] flagColumns, int scannerId, boolean isPaused) {
        super();
        this.scannerId = scannerId;
        this.jFrame = jFrame;
        this.currentSelectedTableRowIndex = -1;
        setLayout(new BorderLayout());

        this.regexTestDialog = null;
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
        pauseCheckBox = new JCheckBox(Constant.messages.getString("customactivescan.testsqlinjection.text.running.pausecheckbox"), pauseIcon);
        pauseCheckBox.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.pausecheckbox"));

        pauseActionObject = new PauseActionObject();

        ExtensionAscanRules.scannerIdPauseActionMap.put(scannerId, pauseActionObject);

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
        JCheckBox randomizeIdleTimeCheckBox = new JCheckBox(Constant.messages.getString("customactivescan.testsqlinjection.title.randomidletime"));
        randomizeIdleTimeCheckBox.setSelected(this.customScanMainPanel.isRandomizeIdleTime());
        randomizeIdleTimeCheckBox.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.randomidletime"));
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
        String requestCountTitleString = Constant.messages.getString("customactivescan.testsqlinjection.title.sendingrequestcount");
        int requestCountColumnSize = requestCountTitleString.length() + 2;
        TitledBorder requestCountTitledBorder = new TitledBorder(requestCountLineBorder,
                requestCountTitleString,
                TitledBorder.LEFT,
                TitledBorder.TOP);
        requestCountTextField = new JTextField(this.customScanMainPanel.getRequestCountValue(), requestCountColumnSize);
        requestCountTextField.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.sendingrequestcount"));
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
        String minIdleTimeTitleString = Constant.messages.getString("customactivescan.testsqlinjection.title.minidletime");
        int minIdleTimeColumnSize = minIdleTimeTitleString.length() + 2;
        TitledBorder minIdleTimeTitledBorder = new TitledBorder(minIdleTimeLineBorder,
                minIdleTimeTitleString,
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JTextField minIdleTimeTextField = new JTextField(this.customScanMainPanel.getMinimumIdleTimeTextFieldValue(), minIdleTimeColumnSize);
        minIdleTimeTextField.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.minidletime"));
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
        String maxIdleTimeTitleString = Constant.messages.getString("customactivescan.testsqlinjection.title.maxidletime");
        int maxIdleTimeColumnSize = maxIdleTimeTitleString.length() + 2;
        TitledBorder maxIdleTimeTitledBorder = new TitledBorder(maxIdleTimeLineBorder,
                maxIdleTimeTitleString,
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JTextField maxIdleTimeTextField = new JTextField(this.customScanMainPanel.getMaximumIdleTimeTextFieldValue(), maxIdleTimeColumnSize);
        maxIdleTimeTextField.setInputVerifier(new MaxIdleTimeVerifier(this.customScanMainPanel));
        maxIdleTimeTextField.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.maxidletime"));
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
        scanLogScroller.setPreferredSize(new Dimension(scanLogScrollerWidth,400));
        scanLogScroller.setAutoscrolls(true);

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
        scanLogTable = new JTable(scanLogTableModel){

            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                final InterfaceRenderCondition condition = ScanLogPanel.this;
                Component compo = super.prepareRenderer(renderer, row, column);
                if (isRowSelected(row)) {
                    //compo.setForeground(getSelectionForeground());
                    //compo.setBackground(getSelectionBackground());
                } else {
                    //compo.setForeground(getForeground());
                    if (condition.isTarget(row, column)) {
                        compo.setBackground(Color.RED);
                    } else {
                        if (row % 2 == 0) {
                            compo.setBackground(getBackground());
                        } else {
                            compo.setBackground(WHITE_GRRENTEA_COLOR);
                        }
                    }
                }
                return compo;
            }
        };

        TableHeaderToolTips tableHeaderToolTips = new TableHeaderToolTips(scanLogTable.getColumnModel(), baseColumnToolTips);
        scanLogTable.setTableHeader(tableHeaderToolTips);

        int colIndex = 0;
        for(Integer widthPercent: basesColumnPreferredSizes) {
            int preferredWidth =(int)Math.round((double) widthPercent / 100 * scanLogScrollerWidth);
            scanLogTable.getColumnModel().getColumn(colIndex++).setPreferredWidth(preferredWidth);
        }

        ScanLogPanelPopUp popupMenu = new ScanLogPanelPopUp(this);
        /***
        JMenuItem menuShowSelectedMessage = new JMenuItem("showMessage");
        menuShowSelectedMessage.addActionListener(l ->{
            int selectedRowIndex = scanLogTable.getSelectedRow();
            if (selectedRowIndex != -1) {
                LOGGER4J.debug("menu show executed:" + selectedRowIndex);
                showSelectedMessage(selectedRowIndex);
            }
        });
        popupMenu.add(menuShowSelectedMessage);
         *****/
        scanLogTable.setComponentPopupMenu(popupMenu);
        scanLogTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scanLogTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent listSelectionEvent) {
                if (listSelectionEvent.getValueIsAdjusting()) {// Without this code, valueChanged method will be called twice
                    // (valueChanged will be called on every mousePress/mouseRelease)
                    return;
                }
                int selectedRow = scanLogTable.getSelectedRow();
                HttpMessageWithLCSResponse selectedMessageWithLCSResponse = resultMessageList.get(selectedRow);
                selectedMessageWithLCSResponse.setPopUpInvokerComponent(ScanLogPanel.this);
                selectedMessageWithLCSResponse.setPmtParams(ScanLogPanel.this.pmtParams);
                ScanLogPanel.this.selectedMessage = selectedMessageWithLCSResponse;
                if( ScanLogPanel.this.regexTestDialog != null) {// call showSelectedMessage when  already existed regexTestDialog.
                    LOGGER4J.debug("valueChanged excecuted:" + selectedRow);
                    ScanLogPanel.this.showSelectedMessage(selectedRow);
                }
            }
        });
        scanLogScroller.setViewportView(scanLogTable);
        add(scanLogScroller, BorderLayout.CENTER);
    }

    public void disablePauseCheckBox() {
        this.pauseCheckBox.setText(Constant.messages.getString("customactivescan.testsqlinjection.text.completed.pausecheckbox"));
        this.pauseCheckBox.setEnabled(false);
    }

    public boolean setSelectedPauseAction(int scannerId, boolean isPaused) {
        if (isPaused) {
            if (pauseActionObject.createNewThread(scannerId)) {
                pauseCheckBox.setText(Constant.messages.getString("customactivescan.testsqlinjection.text.pause.pausecheckbox"));
                return true;
            } else {
                return false;
            }
        } else {
            pauseActionObject.terminateWaitingThread();
            pauseCheckBox.setText(Constant.messages.getString("customactivescan.testsqlinjection.text.running.pausecheckbox"));
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

    /**
     * add message to ScanLogPanel's messageList and tableModel
     * @param rowData
     * @param resultMessage
     * @return messageList size
     */
    private int addRowToScanLogTableModel(String[] rowData, HttpMessageWithLCSResponse resultMessage) {
        scanLogTableModel.addRow(rowData);
        resultMessage.setMessageIndexInScanLogPanel(resultMessageList.size());
        resultMessageList.add(resultMessage);
        return resultMessageList.size();
    }

    private String[] generateRecordArrayFromMessage(HttpMessageWithLCSResponse resultMessage, CustomScanJSONData.ScanRule selectedScanRule) {
        // get baseColumn data : "Time", "Method", "URL", "Code", "Reason", "Length"
        // extract "Time" String from response header
        String timeString = "";
        HttpResponseHeader httpResponseHeader = resultMessage.getResponseHeader();
        String dateString = httpResponseHeader.getHeader("Date");
        if (dateString != null && !dateString.isEmpty()) {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
            try {
                Date responseDate = simpleDateFormat.parse(dateString);
                SimpleDateFormat defaultDateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
                timeString = defaultDateFormat.format(responseDate);
            } catch (ParseException ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
        // extract "Method" String from request header
        HttpRequestHeader httpRequestHeader = resultMessage.getRequestHeader();
        String methodString = httpRequestHeader.getMethod();

        // extract URL string from request header
        org.apache.commons.httpclient.URI uri = httpRequestHeader.getURI();
        String urlString = "";
        try {
            urlString = uri.getURI();
        } catch (URIException e) {
            LOGGER4J.error(e.getMessage(), e);
        }

        // get Status 3 digit code
        int statusCode = resultMessage.getWorstResponseStatus();
        String statusCodeString = Integer.toString(statusCode);

        // get Reason code
        String reasonCodeString = httpResponseHeader.getReasonPhrase();

        // get length
        int contentLength = resultMessage.getOriginalAverageResponseSize();
        String contentLengthString = Integer.toString(contentLength);

        //String entireResponseString = resultMessage.getResponseHeader().toString() + resultMessage.getResponseBody().toString();
        String entireResponseString = resultMessage.getLCSResponse();
        List<String> resultRecord = new ArrayList<>();
        resultRecord.add(timeString);
        resultRecord.add(methodString);
        resultRecord.add(urlString);
        resultRecord.add(statusCodeString);
        resultRecord.add(reasonCodeString);
        resultRecord.add(contentLengthString);
        resultRecord.add(resultMessage.getAttackTitleString());
        resultRecord.add(resultMessage.getPercentString());

        for (String flagItem : selectedScanRule.flagResultItems) {
            Pattern compiledRegex = Pattern.compile(flagItem);
            Matcher m = compiledRegex.matcher(entireResponseString);
            int foundCount = 0;
            while (m.find()) {
                foundCount++;
            }
            resultRecord.add(Integer.toString(foundCount));
        }

        String[] resultRecordArray = resultRecord.toArray(new String[0]);

        return resultRecordArray;
    }

    public int addMessageToScanLogTableModel(HttpMessageWithLCSResponse resultMessage, CustomScanJSONData.ScanRule selectedScanRule){
        int sizeOfMessageList = 0; //  size of ScanLogPanel.resultMessageList
        // search regex pattern in response result message
        if (resultMessage != null) {
            String[] resultRecordArray = generateRecordArrayFromMessage(resultMessage, selectedScanRule);
            sizeOfMessageList = addRowToScanLogTableModel(resultRecordArray, resultMessage);

        }
        return sizeOfMessageList;
    }

    public int updateScanLogTableModelWithResultMessage(HttpMessageWithLCSResponse resultMessage, CustomScanJSONData.ScanRule selectedScanRule) {
        // int rowIndex = resultMessageList.indexOf(resultMessage); this return sucks..
        int rowIndex = resultMessage.getMessageIndexInScanLogPanel();
        if (rowIndex > -1) {
            String[] resultRecordArray = generateRecordArrayFromMessage(resultMessage, selectedScanRule);
            int colIndex = 0;
            for(String columnValue: resultRecordArray){
                this.scanLogTableModel.setValueAt(columnValue,rowIndex, colIndex++);
            }
        }
        return rowIndex;
    }

    private void showSelectedMessage(int selectedTableRowIndex) {
        LOGGER4J.debug("selected row:" + selectedTableRowIndex);
        HttpMessageWithLCSResponse selectedMessage = resultMessageList.get(selectedTableRowIndex);
        if (selectedMessage != null && this.currentSelectedTableRowIndex != selectedTableRowIndex) {
            String requestString = selectedMessage.getRequestHeader().toString() + selectedMessage.getRequestBody().toString();
            String responseString = selectedMessage.getResponseHeader().toString() + selectedMessage.getResponseBody().toString();
            String LcsResponseString = selectedMessage.getLCSResponse();
            RegexTestDialog.PaneContents paneContents = new RegexTestDialog.PaneContents(this.flagColumnRegexString);
            paneContents.addTitleAndContent("Request", requestString, selectedMessage.getLcsCharacterIndexOfLcsRequest());
            //paneContents.addTitleAndContent("Response", responseString, null);
            paneContents.addTitleAndContent("Response(LCS)", LcsResponseString, selectedMessage.getLcsCharacterIndexOfLcsResponse());
            Alert alert = selectedMessage.getAlert();
            if (alert != null) {
                addAlertToTitleAndContent(paneContents, alert);
            }
            if (this.regexTestDialog == null) {
                regexTestDialog = new RegexTestDialog(
                        this.jFrame,
                        this,
                        "Result",
                        Dialog.ModalityType.MODELESS,
                        paneContents);
                regexTestDialog.selectTabbedPane(1);
                regexTestDialog.setVisible(true);
                regexTestDialog.resetScrollBarToLeftTop();
                regexTestDialog.regexSearchActionPerformed(null);
            } else {
                regexTestDialog.updateContentsWithPaneContents(paneContents);
                regexTestDialog.resetScrollBarToLeftTop();
                regexTestDialog.clearAllSearchedInfo();// this method must call
            }
            regexTestDialog.setImplicitStylesOnSelectedPane(true);
            this.currentSelectedTableRowIndex = selectedTableRowIndex;
        }
    }

    private void addAlertToTitleAndContent(RegexTestDialog.PaneContents paneContents, Alert alert){
        List<StartEndPosition> startEndList = new ArrayList<>();
        InterfaceOptionStaticStyler optionStyler =  new InterfaceOptionStaticStyler() {
            final Icon icon =  alert.getIcon();
            @Override
            public String getStyleName() {
                return "#ALERTFLAGICON#";
            }

            @Override
            public void setStyleAttributes(Style style) {
                StyleConstants.setIcon(style, icon);
            }
        };
        List<InterfaceOptionStaticStyler> optionStylerList = new ArrayList<>();
        optionStylerList.add(optionStyler);
        StringBuffer alertContentString = new StringBuffer();
        alertContentString.append(alert.getName() +"\n\n");// no style default Bold.

        StartEndPosition position = addTextWithFIXED(alertContentString, AlertTitleType.RISK.getTitleName(), startEndList);

        position = addTextWithStyles(alertContentString, optionStyler.getStyleName(), startEndList, optionStyler.getStyleName());
        position = addTextWithNullStyle(alertContentString, Alert.MSG_RISK[alert.getRisk()] + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.CONFIDENCE.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, Alert.MSG_CONFIDENCE[alert.getConfidence()] + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.PARAMETER.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, alert.getParam() + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.ATTACK.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, alert.getAttack() + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.EVIDENCE.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, alert.getEvidence()  + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.INPUTVECTOR.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, Utilities.getInputVectorName(alert) + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.CWE.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, Utilities.normlizedId(alert.getCweId()) + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.WASC.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, Utilities.normlizedId(alert.getWascId()) + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.SOURCE.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, Utilities.getSourceData(alert) + "\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.REFERENCE.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, alert.getAlertRef() + "\n\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.DESCRIPTION.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, "\n" + alert.getDescription() + "\n\n", startEndList);

        position = addTextWithFIXED(alertContentString, AlertTitleType.OTHERINFO.getTitleName(), startEndList);
        position = addTextWithNullStyle(alertContentString, "\n" + alert.getOtherInfo() + "\n\n", startEndList);

        paneContents.addTitleAndContent("Alert", alertContentString.toString(), startEndList, optionStylerList);
    }

    private StartEndPosition addTextWithFIXED(StringBuffer alertContentString, String addString, List<StartEndPosition> startEndList) {
        return addTextWithStyles(alertContentString, addString, startEndList, RegexTestDialog.FIXED_LABEL_STYLENAME);
    }

    private StartEndPosition addTextWithNullStyle(StringBuffer alertContentString, String addString, List<StartEndPosition> startEndList){
        return addTextWithStyles(alertContentString, addString, startEndList, SwingStyle.STYLE_NAME);
    }
    private StartEndPosition addTextWithStyles(StringBuffer alertContentString, String addString, List<StartEndPosition> startEndList, String styleName) {
        int startPos = alertContentString.length();
        alertContentString.append(addString);
        int endPos = alertContentString.length();
        StartEndPosition position = new StartEndPosition(startPos, endPos);
        position.styleName = styleName;
        startEndList.add(position);
        return position;
    }
    @Override
    public void disposeChild() {
        if (this.regexTestDialog != null) {
            this.regexTestDialog.dispose();
            this.regexTestDialog = null;
        }
        this.currentSelectedTableRowIndex = -1;
    }

    @Override
    public boolean isTarget(int row, int col) {
        try {
            if (resultMessageList.size() > row) {
                HttpMessageWithLCSResponse message = resultMessageList.get(row);
                if (message != null) {
                    return message.hasResponseLCS() && message.getAttackTitleType() != AttackTitleType.Original;
                }
            }
        } catch (Exception ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        return false;
    }

    private int getFirstTargetRowIndex() {
        int index = 0;
        for(HttpMessageWithLCSResponse message: resultMessageList) {
            if (message.hasResponseLCS()) return index;
            index++;
        }
        return -1;
    }

    private void scrollScanLogTableToSpecifiedCellIndex(int rowIndex, int colIndex) {
        if (!(scanLogTable.getParent() instanceof JViewport)) {
            return;
        }
        JViewport parentViewPort = (JViewport)scanLogTable.getParent();

        // the Rectangle of the specified cell index.
        // x,y position is relative from Table leftTop corner.
        Rectangle rectangleOfSpecifiedTableCell = scanLogTable.getCellRect(rowIndex, colIndex, true);

        // the table position in ViewPort. This is relative position from lefttop corner of table.
        // if table size < viewport size then position is zero.
        // if table size > viewport size and scrolled something,
        // the positon has value of the lefttop corner of the [visible table area in viewport]
        // so the position of value is always between zero and table size;
        Point tableVisibleLeftTopPointInViewPort = parentViewPort.getViewPosition();

        LOGGER4J.debug("point x=" + tableVisibleLeftTopPointInViewPort.x + " y=" + tableVisibleLeftTopPointInViewPort.y);
        rectangleOfSpecifiedTableCell.setLocation(
                rectangleOfSpecifiedTableCell.x-tableVisibleLeftTopPointInViewPort.x,
                rectangleOfSpecifiedTableCell.y-tableVisibleLeftTopPointInViewPort.y);

        scanLogTable.scrollRectToVisible(rectangleOfSpecifiedTableCell);
    }

    public void scrollScanLogTableToFirstTargetRow() {
        int rowIndex = getFirstTargetRowIndex();
        scrollScanLogTableToSpecifiedCellIndex(rowIndex, 0);
    }

    public void repaintScanLogTable() {
        this.scanLogTable.repaint();
    }

    public HttpMessage getSelectedMessage() {
        return this.selectedMessage;
    }

    @Override
    public void popUpActionPerformed(HttpMessage message) {
        int selectedRowIndex = scanLogTable.getSelectedRow();
        if (selectedRowIndex != -1) {
            LOGGER4J.debug("menu show executed:" + selectedRowIndex);
            showSelectedMessage(selectedRowIndex);
        }
    }

    protected void postPmtParamsToScanLogPanel(int selectedRequestNo, int lastRequestNo, int tabIndex) {
        LOGGER4J.info("ScanLogPanel postPmtParamsToScanLogPanel selectedRequestNo="
                + selectedRequestNo + " lastRequestNo=" + lastRequestNo + " tabIndex=" + tabIndex);

        this.pmtParams = new ParmGenMacroTraceParams(this.scannerId, selectedRequestNo, lastRequestNo, tabIndex);
    }

    public Integer getScannerId() {
        return this.scannerId;
    }




}
