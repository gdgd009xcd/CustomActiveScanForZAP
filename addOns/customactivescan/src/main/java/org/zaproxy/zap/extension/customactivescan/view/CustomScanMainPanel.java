package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules;
import org.zaproxy.zap.extension.customactivescan.model.CustomScanDataModel;
import org.zaproxy.zap.extension.customactivescan.model.CustomScanJSONData;
import org.zaproxy.zap.extension.customactivescan.model.InjectionPatterns;
import org.zaproxy.zap.extension.customactivescan.model.ModifyType;
import org.zaproxy.zap.extension.help.ExtensionHelp;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("serial")
public class CustomScanMainPanel extends JPanel {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private JLabel ruleTypeLabel = null;
    private JCheckBox convertURLencodedToRawValueChexkBox;
    private JScrollPane rulePatternScroller = null;
    private int selectedScanRuleIndex = -1;
    private CustomScanDataModel scanDataModel;
    private boolean showFileDialog = false;
    private JCheckBox scanLogCheckBox = null;
    private boolean ruleComboBoxActionIsNoNeedSave;
    JPopupMenu flagPatternPopupMenu = null;
    JMenuItem flagPatternMod;
    JList<String> flagPatternList;
    DefaultListModel<String> flagPatternListModel;
    JComboBox<String> ruleComboBox;
    JCheckBox randomizeIdleTimeCheckBox;
    JTextField minimumIdleTimeTextField;
    JTextField maximumIdleTimeTextField;
    JTextField requestCountTextField;
    private boolean isBuildCalled = false;

    private MainWorkPanelTab mainWorkPanelTab = null;

    private GridBagLayout getGridBagLayout() {
        return (GridBagLayout) getLayout();
    }

    public CustomScanMainPanel(MainWorkPanelTab mainWorkPanelTab) {
        super(new GridBagLayout());
    }

    /**
     * build panel contents.<br>
     * you must call this method after creating this object.
     */
    public final CustomScanMainPanel build() {

        GridBagLayout gridBagLayout = getGridBagLayout();

        this.mainWorkPanelTab = mainWorkPanelTab;

        this.showFileDialog = false;
        this.ruleComboBoxActionIsNoNeedSave = false;

        // load scan configration data.
        scanDataModel = new CustomScanDataModel();

        int ruleCount = scanDataModel.getScanRuleCount();
        if (ruleCount > 0) {
            selectedScanRuleIndex = 0;
        }
        CustomScanJSONData.ScanRule selectedScanRule = getSelectedScanRule();

        // create GUI

        GridBagConstraints gbc = new GridBagConstraints();
        // menu for configuring rule
        JPanel scanRuleMenuBarPanel = new JPanel();
        BorderLayout borderLayout = new BorderLayout();
        scanRuleMenuBarPanel.setLayout(borderLayout);
        JMenuBar scanRuleMenuBar = new JMenuBar();
        //scanRuleMenuBar.setPreferredSize(new Dimension(50, 27));
        JMenu scanRuleMenuTitle = new JMenu(Constant.messages.getString("customactivescan.customscanmainpanel.rule.text"));
        scanRuleMenuBar.add(scanRuleMenuTitle);
        JMenuItem addRuleMenuItem = new JMenuItem(Constant.messages.getString("customactivescan.customscanmainpanel.rule.add.text"));
        scanRuleMenuTitle.add(addRuleMenuItem);
        addRuleMenuItem.addActionListener(e ->{
            addRuleActionPerformed(e);
        });
        JMenuItem addRuleCopyFromMenuItem = new JMenuItem(Constant.messages.getString("customactivescan.customscanmainpanel.rule.copy.text"));
        scanRuleMenuTitle.add(addRuleCopyFromMenuItem);
        addRuleCopyFromMenuItem.addActionListener(e -> {
            copyRuleActionPerformed(e);
        });
        JMenuItem delRuleMenuItem = new JMenuItem(Constant.messages.getString("customactivescan.customscanmainpanel.rule.del.text"));
        scanRuleMenuTitle.add(delRuleMenuItem);
        delRuleMenuItem.addActionListener(e ->{
            delRuleActionPerformed(e);
        });
        JMenuItem loadFileMenuItem = new JMenuItem(Constant.messages.getString("customactivescan.customscanmainpanel.rule.load.text"));
        scanRuleMenuTitle.add(loadFileMenuItem);
        loadFileMenuItem.addActionListener(e ->{
            loadFileActionPerformed(e);
        });
        JMenuItem saveFileMenuItem = new JMenuItem(Constant.messages.getString("customactivescan.customscanmainpanel.rule.saveas.text"));
        scanRuleMenuTitle.add(saveFileMenuItem);
        saveFileMenuItem.addActionListener(e ->{
            saveFileActionPerformed(e);
        });

        if (selectedScanRule != null) {
            ruleTypeLabel = new JLabel(selectedScanRule.getRuleTypeName());
        } else {
            ruleTypeLabel = new JLabel("");
        }
        LineBorder ruleTypeLabelBorderLine = new LineBorder(Color.BLACK, 1, true);
        ruleTypeLabel.setBorder(ruleTypeLabelBorderLine);
        JLabel spaceLabel = new JLabel(" ");
        scanRuleMenuBar.add(ruleTypeLabel);
        scanRuleMenuBar.add(spaceLabel);

        //help menu
        JButton scanRuleHelpBtn = new JButton(ExtensionAscanRules.qIcon);
        scanRuleHelpBtn.setToolTipText(Constant.messages.getString("customactivescan.customscanmainpanel.helpBtnTooltip.text"));
        scanRuleHelpBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ExtensionHelp.showHelp("addon.customactivescan");
            }
        });
        scanRuleMenuBar.add(scanRuleHelpBtn);
        scanRuleMenuBar.add(new JSeparator(SwingConstants.VERTICAL));

        // Gridbaglayout cannot handle JMenuBar properly, so we use Borderlayout for JMenuBar
        scanRuleMenuBarPanel.add(scanRuleMenuBar, BorderLayout.LINE_START);

        // scanRule Combobox
        ruleComboBox = new JComboBox<>();
        for(CustomScanJSONData.ScanRule rule: scanDataModel.getScanRuleList()) {
            ruleComboBox.addItem(rule.patterns.name);
        }

        //ruleComboBox.setPreferredSize(new Dimension(70, 27));
        ruleComboBox.addActionListener(e -> {
            ruleComboBoxActionPerformed(e);
        });
        scanRuleMenuBarPanel.add(ruleComboBox, BorderLayout.CENTER);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.1d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,1,1,1);
        //gbc.anchor = GridBagConstraints.NORTHEAST;
        gridBagLayout.setConstraints(scanRuleMenuBarPanel, gbc);
        add(scanRuleMenuBarPanel);

        // create borderlayout for adding option input components in the future
        //  |-------------border layout PAGE_START--------------------|
        //  | |---------Box layout BoxLayout.Y_AXIS-----------------| |
        //  | | checkBox1 ------------------|                       | |
        //  | | checkBox2 ------------------|                       | |
        //  | |-----------------------------------------------------| |
        //  |-------------border layout PAGE_CENTER-------------------|
        //  | |---------------- JScrollPane ------------------------| |
        //  | |                                                     | |
        //  | |-----------------------------------------------------| |
        //  |---------------------------------------------------------|
        //
        // ｃreate BorderLayout JPanel
        JPanel rulePatternBorderPanel = new JPanel();
        BorderLayout rulePatternBorderLayout = new BorderLayout();
        rulePatternBorderLayout.setVgap(10);
        rulePatternBorderPanel.setLayout(rulePatternBorderLayout);
        // set border to this BorderLayout JPanel
        LineBorder rulePatternBorderLine = new LineBorder(Color.BLACK, 2, true);
        TitledBorder rulePatternTitledBorder = new TitledBorder(rulePatternBorderLine,
                Constant.messages.getString("customactivescan.customscanmainpanel.rulePatternTitledBorder.text"),
                TitledBorder.LEFT,
                TitledBorder.TOP);
        rulePatternBorderPanel.setBorder(rulePatternTitledBorder);

        // create BoxLayout.Y=AXIS
        JPanel rulePatternOptionsBoxPanel = new JPanel();
        rulePatternOptionsBoxPanel.setLayout(new BoxLayout(rulePatternOptionsBoxPanel, BoxLayout.Y_AXIS));
        // create checkBox
        convertURLencodedToRawValueChexkBox = new JCheckBox(Constant.messages.getString("customactivescan.customscanmainpanel.convertURLencodedToRawValueChexkBox.text"));
        convertURLencodedToRawValueChexkBox.setToolTipText(Constant.messages.getString("customactivescan.customscanmainpanel.convertURLencodedToRawValueChexkBox.toolTip.text"));
        if (selectedScanRule != null) {
            convertURLencodedToRawValueChexkBox.setSelected(selectedScanRule.isConvertURLdecodedValue());
        } else {
            convertURLencodedToRawValueChexkBox.setSelected(false);
        }
        convertURLencodedToRawValueChexkBox.addActionListener(e -> {
                CustomScanJSONData.ScanRule currentScanRule = getSelectedScanRule();
                if (currentScanRule != null && !this.ruleComboBoxActionIsNoNeedSave) {
                    LOGGER4J.debug("START convertURLencodedToRawValueChexkBox addActionListener called.");
                    currentScanRule.setConvertURLdecodedValue(this.convertURLencodedToRawValueChexkBox.isSelected());
                    fileSaveAction();// The convertURL CheckBox is focusout when the save dialog appears
                    LOGGER4J.debug("END convertURLencodedToRawValueChexkBox addActionListener called.");
                }
            }
        );

        rulePatternOptionsBoxPanel.add(convertURLencodedToRawValueChexkBox);//add checkBox to BoxLayout JPanel
        // add BoxLayout JPanel to PAGE_START area of BorderLayout JPanel
        rulePatternBorderPanel.add(rulePatternOptionsBoxPanel, BorderLayout.PAGE_START);

        // custom scan pattern list
        rulePatternScroller = new JScrollPane();
        createRuleTable(selectedScanRule);
        rulePatternScroller.setPreferredSize(new Dimension(400,400));
        rulePatternScroller.setAutoscrolls(true);


        // add JScrolledPane to CENTER area of BorderLayout JPanel
        rulePatternBorderPanel.add(rulePatternScroller, BorderLayout.CENTER);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 0d;
        gbc.weighty = 0.5d;
        gbc.insets = new Insets(1,1,1,1);
        //gbc.anchor = GridBagConstraints.FIRST_LINE_START;
        gridBagLayout.setConstraints(rulePatternBorderPanel, gbc);
        // add BorderLayout in this Panel.
        add(rulePatternBorderPanel);

        // separator
        JSeparator separator1 = new JSeparator();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,0,1,0);
        gridBagLayout.setConstraints(separator1, gbc);
        add(separator1);

        // config "ScanLog" shows response results
        JPanel scanLogPanel = new JPanel();

        borderLayout = new BorderLayout();
        borderLayout.setVgap(10);
        scanLogPanel.setLayout(borderLayout);
        LineBorder scanLogPanelBorderLine = new LineBorder(Color.BLACK, 2, true);
        TitledBorder scanLogPanelTitledBorder = new TitledBorder(scanLogPanelBorderLine,
                Constant.messages.getString("customactivescan.customscanmainpanel.scanLogPanelTitledBorder.text"),
                TitledBorder.LEFT,
                TitledBorder.TOP);
        scanLogPanel.setBorder(scanLogPanelTitledBorder);

        scanLogCheckBox = new JCheckBox(Constant.messages.getString("customactivescan.customscanmainpanel.scanLogCheckBox.text"));
        if (selectedScanRule != null) {
            scanLogCheckBox.setSelected(selectedScanRule.getDoScanLogOutput());
        } else {
            scanLogCheckBox.setSelected(false);
        }

        // you should use addActionListner method if you want to popup dialog in listener method.
        // DO NOT USE addItemListener. it will occur complicated problem with using dialog.
        scanLogCheckBox.addActionListener(e -> {
            CustomScanJSONData.ScanRule currentScanRule = getSelectedScanRule();
            if (currentScanRule != null && !this.ruleComboBoxActionIsNoNeedSave) {
                LOGGER4J.debug("START scanLogCheckBox addActionListener called.");
                currentScanRule.setDoScanLogOutput(this.scanLogCheckBox.isSelected());
                fileSaveAction();// The scanLog CheckBox is focusout when the save dialog appears
                LOGGER4J.debug("END scanLogCheckBox addActionListener called.");
            }
        });
        scanLogPanel.add(scanLogCheckBox, BorderLayout.PAGE_START);

        // Regexes for detecting keyword in Http response.
        this.flagPatternListModel = new DefaultListModel<>();
        if (selectedScanRule != null) {
            for (String data : selectedScanRule.flagResultItems) {
                this.flagPatternListModel.addElement(data);
            }
        }
        this.flagPatternList = new JList<>(this.flagPatternListModel);
        this.flagPatternPopupMenu = new JPopupMenu();
        JMenuItem flagPatternAdd = new JMenuItem(Constant.messages.getString("customactivescan.customscanmainpanel.flagPatternAdd.text"));
        flagPatternAdd.addActionListener(l ->{
            addFlagPatternActionPerformed(l, true);
        });
        this.flagPatternPopupMenu.add(flagPatternAdd);
        this.flagPatternMod = new JMenuItem(Constant.messages.getString("customactivescan.customscanmainpanel.flagPatternMod.text"));
        this.flagPatternMod.addActionListener(l ->{
            addFlagPatternActionPerformed(l, false);
        });
        this.flagPatternPopupMenu.add(flagPatternMod);
        JMenuItem flagPatternDel = new JMenuItem(Constant.messages.getString("customactivescan.customscanmainpanel.flagPatternDel.text"));
        flagPatternDel.addActionListener(l -> {
            int selectedIndex = this.flagPatternList.getSelectedIndex();
            if (selectedIndex != -1) {
                this.flagPatternListModel.remove(selectedIndex);
                this.updateFlagResultItemsWithFlagPatternListModel();
            }
        });
        this.flagPatternPopupMenu.add(flagPatternDel);
        flagPatternList.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {

            }

            @Override
            public void mousePressed(MouseEvent mouseEvent) {
                flagPatternPopupMenuPerformed(mouseEvent);
            }

            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                flagPatternPopupMenuPerformed(mouseEvent);
            }

            @Override
            public void mouseEntered(MouseEvent mouseEvent) {

            }

            @Override
            public void mouseExited(MouseEvent mouseEvent) {

            }
        });
        JScrollPane flagPatternScroller = new JScrollPane(flagPatternList);
        flagPatternScroller.setPreferredSize(new Dimension(700,400));
        flagPatternScroller.setAutoscrolls(true);
        LineBorder flagPatternBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder flagPatternTitledBorder = new TitledBorder(flagPatternBorderLine,
                Constant.messages.getString("customactivescan.customscanmainpanel.flagPatternTitledBorder.text"),
                TitledBorder.LEFT,
                TitledBorder.TOP);
        flagPatternScroller.setBorder(flagPatternTitledBorder);

        scanLogPanel.add(flagPatternScroller, BorderLayout.CENTER);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 0d;
        gbc.weighty = 0.5d;
        gbc.insets = new Insets(1,1,1,1);
        gridBagLayout.setConstraints(scanLogPanel, gbc);
        add(scanLogPanel);

        // separator
        JSeparator separator2 = new JSeparator();
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,0,1,0);
        gridBagLayout.setConstraints(separator2, gbc);
        add(separator2);

        // Idle time config panel
        JPanel idleTimePanel = new JPanel();
        GridLayout idleTimeLayout = new GridLayout(3,3);
        idleTimePanel.setLayout(idleTimeLayout);
        LineBorder idleTimePanelBorderLine = new LineBorder(Color.BLACK, 1, true);
        TitledBorder idleTimePanelTitledBorder = new TitledBorder(idleTimePanelBorderLine,
                Constant.messages.getString("customactivescan.customscanmainpanel.idleTimePanelTitledBorder.text"),
                TitledBorder.LEFT,
                TitledBorder.TOP);
        idleTimePanel.setBorder(idleTimePanelTitledBorder);

        // randomize idle time or not
        randomizeIdleTimeCheckBox = new JCheckBox(Constant.messages.getString("customactivescan.testsqlinjection.title.randomidletime"));
        randomizeIdleTimeCheckBox.setSelected(selectedScanRule.isRandomIdleTime());
        randomizeIdleTimeCheckBox.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.randomidletime"));
        randomizeIdleTimeCheckBox.addActionListener(actionEvent->{
            CustomScanJSONData.ScanRule currentScanRule = getSelectedScanRule();
            if (currentScanRule.isRandomIdleTime() != randomizeIdleTimeCheckBox.isSelected()) {
                currentScanRule.setRandomIdleTime(randomizeIdleTimeCheckBox.isSelected());
                fileSaveAction();
            }
        });
        idleTimePanel.add(randomizeIdleTimeCheckBox);

        // dummy label
        JLabel dummyLabel = new JLabel();
        idleTimePanel.add(dummyLabel);

        // Minimum idle time between  sending requests
        LineBorder minimumIdleTimeBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder minimumIdleTimeTitledBorder = new TitledBorder(minimumIdleTimeBorderLine,
                Constant.messages.getString("customactivescan.testsqlinjection.title.minidletime"),
                TitledBorder.LEFT,
                TitledBorder.TOP);
        minimumIdleTimeTextField = new JTextField(Integer.toString(selectedScanRule.getMinIdleTime()));
        minimumIdleTimeTextField.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.minidletime"));
        minimumIdleTimeTextField.setBorder(minimumIdleTimeTitledBorder);
        minimumIdleTimeTextField.setInputVerifier(new MinIdleTimeVerifier(this));
        idleTimePanel.add(minimumIdleTimeTextField);

        // Maximum idle time between  sending requests
        LineBorder maximumIdleTimeBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder maximumIdleTimeTitledBorder = new TitledBorder(maximumIdleTimeBorderLine,
                Constant.messages.getString("customactivescan.testsqlinjection.title.maxidletime"),
                TitledBorder.LEFT,
                TitledBorder.TOP);
        maximumIdleTimeTextField = new JTextField(Integer.toString(selectedScanRule.getMaxIdleTime()));
        maximumIdleTimeTextField.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.maxidletime"));
        maximumIdleTimeTextField.setBorder(maximumIdleTimeTitledBorder);
        maximumIdleTimeTextField.setInputVerifier(new MaxIdleTimeVerifier(this));

        idleTimePanel.add(maximumIdleTimeTextField);

        LineBorder requestCountBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder requestCountTitledBorder = new TitledBorder(requestCountBorderLine,
                Constant.messages.getString("customactivescan.testsqlinjection.title.sendingrequestcount"),
                TitledBorder.LEFT,
                TitledBorder.TOP);
        requestCountTextField = new JTextField(5);
        requestCountTextField.setBorder(requestCountTitledBorder);
        requestCountTextField.setToolTipText(Constant.messages.getString("customactivescan.testsqlinjection.tooltip.sendingrequestcount"));
        requestCountTextField.setText(Integer.toString(selectedScanRule.getRequestCount()));
        requestCountTextField.setInputVerifier(new RequestCountVerifier(this));
        idleTimePanel.add(requestCountTextField);

        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1,0,1,0);
        gridBagLayout.setConstraints(idleTimePanel, gbc);
        add(idleTimePanel);

        this.isBuildCalled = true;
        return this;
    }

    private void createRuleTable(CustomScanJSONData.ScanRule selectedScanRule) {
        if (this.rulePatternScroller != null) {
            DefaultTableModel defaultTableModel = new DefaultTableModel();
            if (selectedScanRule != null) {
                ruleTypeLabel.setText(selectedScanRule.getRuleTypeName());
                List<Object[]> tableDataList = new ArrayList<>();

                if (scanLogCheckBox != null) {
                    LOGGER4J.debug("scanLogCheckBox setSelected in createRuleTable");
                    scanLogCheckBox.setSelected(selectedScanRule.getDoScanLogOutput());
                }
                if (convertURLencodedToRawValueChexkBox != null) {
                    convertURLencodedToRawValueChexkBox.setSelected(selectedScanRule.isConvertURLdecodedValue());
                }

                if (selectedScanRule.ruleType == CustomScanJSONData.RuleType.SQL) {

                    String[] columnNames = {"Modify", "TrueValue", "FalseValue", "ErrorValue", "TrueName", "FalseName", "ErrorName"};
                    for (InjectionPatterns.TrueFalsePattern patternRow : selectedScanRule.patterns.patterns) {
                        Object[] rowData = {
                                patternRow.modifyType,
                                patternRow.trueValuePattern,
                                patternRow.falseValuePattern,
                                patternRow.errorValuePattern,
                                patternRow.trueNamePattern,
                                patternRow.falseNamePattern,
                                patternRow.errorNamePattern
                        };
                        tableDataList.add(rowData);
                    }
                    Object[][] tableDataArray = tableDataList.toArray(new Object[0][0]);// specified zero size array means that  new array will be allocated
                    defaultTableModel.setDataVector(tableDataArray, columnNames);
                } else { // RuleType.PenTest
                    String[] columnNames = {"Modify", "TrueValue"};
                    for (InjectionPatterns.TrueFalsePattern patternRow : selectedScanRule.patterns.patterns) {
                        Object[] rowData = {
                                patternRow.modifyType,
                                patternRow.trueValuePattern
                        };
                        tableDataList.add(rowData);
                    }
                    Object[][] tableDataArray = tableDataList.toArray(new Object[0][0]);// specified zero size array means that  new array will be allocated
                    defaultTableModel.setDataVector(tableDataArray, columnNames);
                }
            } else {
                ruleTypeLabel.setText("");
            }
            JTable rulePatternTable = CustomJTable.newInstance(this, this.rulePatternScroller, defaultTableModel);
            // disable column move(reordering)
            JTableHeader jtableHeader = rulePatternTable.getTableHeader();
            jtableHeader.setReorderingAllowed(false);

            // tracking table focus
            rulePatternTable.addFocusListener(new FocusListener() {
                public void focusGained(FocusEvent e) {
                    LOGGER4J.debug("JTable focusGained :" + (rulePatternTable.isEditing() ? "EDITING": "NONE"));
                }
                public void focusLost(FocusEvent e) {
                    LOGGER4J.debug("JTable focusLost :" + (rulePatternTable.isEditing() ? "EDITING": "NONE"));
                }
            });
            // tracking table cell editor focus
            DefaultCellEditor dce = (DefaultCellEditor)  rulePatternTable.getDefaultEditor(Object.class);
            dce.getComponent().addFocusListener(new FocusListener() {
                public void focusLost(FocusEvent e) {
                    LOGGER4J.debug("CellEditor focusLost");
                    tableCellEditorFocusLost(dce);
                }
                public void focusGained(FocusEvent e) {
                    LOGGER4J.debug("CellEditor focusGained");
                }
            });

            defaultTableModel.addTableModelListener(e ->{
                rulePatternTableChanged(e);
            });
        }
    }

    public void addRuleActionPerformed(ActionEvent e) {
        LOGGER4J.debug("addRuleActionPerformed");
        new AddRuleDialog(this, Constant.messages.getString("customactivescan.customscanmainpanel.AddRuleDialogTitle.text"), Dialog.ModalityType.DOCUMENT_MODAL).setVisible(true);
    }

    public void copyRuleActionPerformed(ActionEvent e) {
        LOGGER4J.debug("copyRuleActionPerformed");
        new AddRuleDialogByCopy(this, Constant.messages.getString("customactivescan.customscanmainpanel.AddRuleDialogByCopyTitle.text"), Dialog.ModalityType.DOCUMENT_MODAL).setVisible(true);
    }

    public void delRuleActionPerformed(ActionEvent e) {
        String selectedItem = (String)this.ruleComboBox.getSelectedItem();
        int optionNo = JOptionPane.showConfirmDialog(this, Constant.messages.getString("customactivescan.customscanmainpanel.delRuleConfirmDialogMessage.arg0.text", selectedItem), Constant.messages.getString("customactivescan.customscanmainpanel.delRuleConfirmDialogTitle.text"), JOptionPane.YES_NO_OPTION);
        switch(optionNo) {
            case JOptionPane.YES_OPTION:
                int selectedRuleIndex = this.ruleComboBox.getSelectedIndex();
                int itemCount = this.ruleComboBox.getItemCount();
                LOGGER4J.debug("itemCount:" + itemCount + " delIndex:" + selectedRuleIndex);
                this.ruleComboBox.removeItemAt(selectedRuleIndex);// must be used method removeItemAt but not remove.
                this.scanDataModel.removeScanRule(selectedRuleIndex);
                int previousRuleIndex = (selectedRuleIndex - 1) < 0 ? 0 : (selectedRuleIndex - 1);
                int ruleCount = ruleComboBox.getItemCount();
                if (ruleCount > 0) {
                    this.ruleComboBox.setSelectedIndex(previousRuleIndex);
                } else {
                    this.selectedScanRuleIndex = -1;
                    createRuleTable(null);
                }
                fileSaveAction();
                break;
            case JOptionPane.NO_OPTION:
            default:
                break;
        }
    }

    private void loadFileActionPerformed(ActionEvent e) {
        if(loadScanDataModel()) {
            this.selectedScanRuleIndex = -1;
            ruleComboBox.removeAllItems();
            for(CustomScanJSONData.ScanRule rule: scanDataModel.getScanRuleList()) {
                ruleComboBox.addItem(rule.patterns.name);
            }
            LOGGER4J.debug("loadFileActionPerformed.");
        }
    }

    private void saveFileActionPerformed(ActionEvent e) {
        saveToNewFile();
    }

    public void addFlagPatternActionPerformed(ActionEvent e, boolean isAddAction) {
        AddFlagRegex addFlagRegexDialog = new AddFlagRegex(this, Constant.messages.getString("customactivescan.customscanmainpanel.addFlagRegexDialogTitle.text"), Dialog.ModalityType.DOCUMENT_MODAL);
        addFlagRegexDialog.setFlagPatternList(this.flagPatternList, isAddAction);
        addFlagRegexDialog.setVisible(true);
    }

    @SuppressWarnings("unchecked")
    public void ruleComboBoxActionPerformed(ActionEvent e) {
        JComboBox<String> cb = (JComboBox<String>) e.getSource();
        String actionCommandString = e.getActionCommand();

        int comboBoxSelectedIndex = cb.getSelectedIndex();
        LOGGER4J.debug("ruleComboBoxAction[" + e.getActionCommand() + "] item:"
                + cb.getSelectedItem() + " item index:" + comboBoxSelectedIndex + " selectedRuleIndex:" + selectedScanRuleIndex);

        if (selectedScanRuleIndex != comboBoxSelectedIndex && comboBoxSelectedIndex > -1) {
            this.ruleComboBoxActionIsNoNeedSave = true;
            selectedScanRuleIndex = comboBoxSelectedIndex;
            LOGGER4J.debug("selectedScanRuleIndex=" + selectedScanRuleIndex);
            CustomScanJSONData.ScanRule selectedScanRule = scanDataModel.getScanRule(selectedScanRuleIndex);
            createRuleTable(selectedScanRule);
            LOGGER4J.debug("scanLogCheckBox setSelected in ruleComboBoxActionPerformed");
            this.scanLogCheckBox.setSelected(selectedScanRule.getDoScanLogOutput());
            this.convertURLencodedToRawValueChexkBox.setSelected(selectedScanRule.isConvertURLdecodedValue());
            this.randomizeIdleTimeCheckBox.setSelected(selectedScanRule.isRandomIdleTime());
            this.requestCountTextField.setText(Integer.toString(selectedScanRule.getRequestCount()));
            this.minimumIdleTimeTextField.setText(Integer.toString(selectedScanRule.getMinIdleTime()));
            this.maximumIdleTimeTextField.setText(Integer.toString(selectedScanRule.getMaxIdleTime()));
            this.flagPatternListModel.clear();
            for (String data : selectedScanRule.flagResultItems) {
                this.flagPatternListModel.addElement(data);
            }
            this.ruleComboBoxActionIsNoNeedSave = false;
            // <---this below code is exist for fixing problems in selecting JTable header
            // (Null Exception is occured in some Flat IntelliJ LookAndFeel.)
            View.getSingleton().getWorkbench().getTabbedWork().setVisible(this.mainWorkPanelTab, false);
            View.getSingleton().getWorkbench().getTabbedWork().setVisible(this.mainWorkPanelTab, true);
            this.mainWorkPanelTab.setTabFocus();
            // --->
        }
    }

    private void rulePatternTableChanged(TableModelEvent e) {
        String eType;
        switch(e.getType()) {
            case TableModelEvent.INSERT:
                eType = "INSERT";
                break;
            case TableModelEvent.UPDATE:
                eType = "UPDATE";
                break;
            case TableModelEvent.DELETE:
                eType = "DELETE";
                break;
            default:
                eType = "UNKNOWN";
                break;
        }

        LOGGER4J.debug("ruleTableChanged: type:" + eType + " col:" + e.getColumn() + " Row From:" + e.getFirstRow() + " Row To:" + e.getLastRow());
    }

    private boolean saveToNewFile() {
        boolean isSavedToNewFile = false;
        this.showFileDialog = true;
        LOGGER4J.debug("showFileDialog=true");
        File cfile = null;
        String dirname = null;
        try {
            cfile = new File(scanDataModel.getSaveFileName());
            dirname = cfile.getParent();
        } catch (Exception ex) {
            dirname = null;
        }

        if (dirname == null) {
            cfile = null;
            dirname = "";
        }

        Path relativePath = Paths.get(dirname);// specified directory relative path
        if (!Files.exists(relativePath)) {
            dirname = "";// current directory.
            cfile = null;
            relativePath = Paths.get(dirname);
        }
        Path absolutePath = relativePath.toAbsolutePath();
        String absolutePathString = absolutePath.toString();
        JFileChooser jfc = new JFileChooser(absolutePathString) {

            @Override
            public void approveSelection() {
                File f = getSelectedFile();
                if (f.exists() && getDialogType() == SAVE_DIALOG) {
                    String m = String.format(
                            Constant.messages.getString("customactivescan.customscanmainpanel.saveToNewFileApproveAlreadyExistFileFormat.text"),
                            f.getAbsolutePath());
                    int rv = JOptionPane.showConfirmDialog(
                            this, m, Constant.messages.getString("customactivescan.customscanmainpanel.saveToNewFileConfirmTitle.text"), JOptionPane.YES_NO_OPTION);
                    if (rv != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
                super.approveSelection();
            }
        };
        FileFilterForJSON pFilter = new FileFilterForJSON();
        jfc.setFileFilter(pFilter);
        jfc.setDialogTitle(Constant.messages.getString("customactivescan.customscanmainpanel.saveToNewFileJfcTitle.text"));
        if (cfile != null) {
            jfc.setSelectedFile(cfile);
        }

        jfc.setAcceptAllFileFilterUsed(false);
        LOGGER4J.debug("start Popup Save Dialog");
        if (jfc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {// OK button
            File file = jfc.getSelectedFile();
            String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
            if (!pFilter.accept(file)) {
                name += ".json";
            }
            scanDataModel.saveModelToNewFile(name);
            isSavedToNewFile = scanDataModel.isSaved();
        } else { // cancel button
            isSavedToNewFile = true;
        }

        this.showFileDialog = false;
        LOGGER4J.debug("showFileDialog=false");
        return isSavedToNewFile;
    }

    public boolean saveToNewFileIfNoSaved() {
        if (!scanDataModel.isSaved() && !scanDataModel.isSampleLoaded()) {
            return saveToNewFile();
        }
        return false;
    }

    public boolean loadScanDataModel() {
        this.showFileDialog = true;
        LOGGER4J.debug("showFileDialog=true");
        File cfile = null;
        String dirname = null;
        try {
            cfile = new File(scanDataModel.getSaveFileName());
            dirname = cfile.getParent();
        } catch (Exception ex) {
            dirname = null;
        }

        if (dirname == null) {
            cfile = null;
            dirname = "";
        }

        Path relativePath = Paths.get(dirname);// specified directory relative path
        if (!Files.exists(relativePath)) {
            dirname = "";// current directory.
            cfile = null;
            relativePath = Paths.get(dirname);
        }
        Path absolutePath = relativePath.toAbsolutePath();
        String absolutePathString = absolutePath.toString();
        JFileChooser jfc = new JFileChooser(absolutePathString) {

            @Override
            public void approveSelection() {
                File f = getSelectedFile();
                if (!f.exists() && getDialogType() == OPEN_DIALOG) {
                    String m = String.format(
                            Constant.messages.getString("customactivescan.customscanmainpanel.loadScanDataModelApproveFileNotFoundFormat.text"),
                            f.getAbsolutePath());
                    JOptionPane.showMessageDialog(
                            this, m, Constant.messages.getString("customactivescan.customscanmainpanel.loadScanDataModelApproveFileNotFoundDialogTitle.text"), JOptionPane.ERROR_MESSAGE);
                    return;// failed file open.
                }
                super.approveSelection();// succeeded file open.
            }
        };
        FileFilterForJSON pFilter = new FileFilterForJSON();
        jfc.setFileFilter(pFilter);
        jfc.setDialogTitle(Constant.messages.getString("customactivescan.customscanmainpanel.loadScanDataModelJfcTitle.text"));
        if (cfile != null) {
            jfc.setSelectedFile(cfile);
        }

        jfc.setAcceptAllFileFilterUsed(false);
        boolean loadResult = false;
        LOGGER4J.debug("start Popup Load Dialog");
        if (jfc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {// file open.
            File file = jfc.getSelectedFile();
            String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
            if (!pFilter.accept(file)) {
                name += ".json";
            }

            loadResult =  scanDataModel.loadModel(name);

        }

        this.showFileDialog = false;
        LOGGER4J.debug("showFileDialog=false");
        return loadResult;
    }

    private void tableCellEditorFocusLost(DefaultCellEditor dce) {
        if (!showFileDialog) {// when focus move other components except FileChooser(Save dialog)
            dce.stopCellEditing();
        }
    }

    /**
     * update CustomScanDataModel with JTable contents(TableModel)
     * @param jTableModel
     */
    public void updateModelWithJTableModel(TableModel jTableModel) {
        int rowCount = jTableModel.getRowCount();
        CustomScanJSONData.ScanRule selectedScanRule = scanDataModel.getScanRule(selectedScanRuleIndex);
        selectedScanRule.patterns.clearPatterns();
        if ( selectedScanRule.ruleType == CustomScanJSONData.RuleType.SQL) {
            for(int i = 0; i < rowCount; i++) {
                selectedScanRule.patterns.addPattern(
                        (ModifyType) jTableModel.getValueAt(i, 0),
                        (String)jTableModel.getValueAt(i, 1),
                        (String)jTableModel.getValueAt(i, 2),
                        (String)jTableModel.getValueAt(i, 3),
                        (String)jTableModel.getValueAt(i, 4),
                        (String)jTableModel.getValueAt(i, 5),
                        (String)jTableModel.getValueAt(i, 6)
                );
            }
        } else {// PenTest
            for(int i = 0; i < rowCount; i++) {
                selectedScanRule.patterns.addPattern(
                        (ModifyType)jTableModel.getValueAt(i, 0),
                        (String)jTableModel.getValueAt(i, 1),
                        null,
                        null,
                        null,
                        null,
                        null
                );
            }
        }
        fileSaveAction();
    }

    public void updateFlagResultItemsWithFlagPatternListModel(){
        CustomScanJSONData.ScanRule selectedScanRule = getSelectedScanRule();
        if (selectedScanRule != null) {
            int size = this.flagPatternListModel.size();
            selectedScanRule.flagResultItems.clear();
            for(int i = 0; i < size; i++){
                String flagPatternString = this.flagPatternListModel.get(i);
                selectedScanRule.flagResultItems.add(flagPatternString);
            }
            fileSaveAction();
        }
    }

    public final CustomScanJSONData.ScanRule getSelectedScanRule() {
        return scanDataModel.getScanRule(selectedScanRuleIndex);
    }

    private void flagPatternPopupMenuPerformed(MouseEvent evt) {
        if(evt.isPopupTrigger()) {
            if (this.flagPatternList.isSelectionEmpty()){
                this.flagPatternMod.setEnabled(false);
            } else {
                this.flagPatternMod.setEnabled(true);
            }
            this.flagPatternPopupMenu.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }

    public boolean ruleNameIsExistInModel(String ruleName, boolean exceptSample) {
        return this.scanDataModel.ruleNameIsExistInModel(ruleName, exceptSample);
    }

    public void addNewScanRule(String ruleName, CustomScanJSONData.RuleType ruleType, boolean scanLogIsSelected) {
        CustomScanJSONData.ScanRule scanRule = new CustomScanJSONData.ScanRule();
        scanRule.ruleType = ruleType;
        scanRule.setDoScanLogOutput(scanLogIsSelected);
        scanRule.setConvertURLdecodedValue(false);
        scanRule.patterns.name = ruleName;
        scanRule.patterns.addPattern(ModifyType.Add,"", "", "", "", "", "");
        this.scanDataModel.addNewScanRule(scanRule);
        fileSaveAction();
        this.ruleComboBox.addItem(ruleName);// must do this after addNewScanRule method is called. because addItem method invoke ruleComboBoxActionPerformed method.
        // must do following codes. because when ruleComboBox itemCount is larger than 1, then addItem method does not invoke ruleComboBoxActionPerformed.
        int addedRuleIndex = this.ruleComboBox.getItemCount() - 1;
        this.ruleComboBox.setSelectedIndex(addedRuleIndex);
    }

    public boolean addNewScanRuleByCopyFrom(String ruleName, int CopyFromIndexOfScanRule) {
        CustomScanJSONData.ScanRule rule = null;
        if (CopyFromIndexOfScanRule < scanDataModel.getScanRuleCount()) {
            rule = scanDataModel.getScanRule(CopyFromIndexOfScanRule);
        } else if (CopyFromIndexOfScanRule < scanDataModel.getScanRuleCount() + 2) {
            int sampleIndex = CopyFromIndexOfScanRule - scanDataModel.getScanRuleCount();
            rule = scanDataModel.getSampleScanRuleList().get(sampleIndex);
        }

        if (rule != null) {
            CustomScanJSONData.ScanRule newRule = rule.clone();
            newRule.setName(ruleName);
            this.scanDataModel.addNewScanRule(newRule);
            fileSaveAction();
            this.ruleComboBox.addItem(ruleName);// must do this after addNewScanRule method is called. because addItem method invoke ruleComboBoxActionPerformed method.
            // must do following codes. because when ruleComboBox itemCount is larger than 1, then addItem method does not invoke ruleComboBoxActionPerformed.
            int addedRuleIndex = this.ruleComboBox.getItemCount() - 1;
            this.ruleComboBox.setSelectedIndex(addedRuleIndex);
            return true;
        }

        return false;
    }

    public List<CustomScanJSONData.ScanRule> getScanRuleList() {
        return this.scanDataModel.getScanRuleList();
    }

    public List<CustomScanJSONData.ScanRule> getSampleScanRuleList() {
        return this.scanDataModel.getSampleScanRuleList();
    }

    /**
     *  save CustomScanDataModel to JSON file.
     *  if JSON file isn't exist or CustomScanDataModel isn't saved, then save dialog is appeared.
     */
    public void fileSaveAction() {
        scanDataModel.modifiedSample();
        if(!this.saveToNewFileIfNoSaved()) {
            scanDataModel.saveModel();
        }
    }

    public String getMinimumIdleTimeTextFieldValue() {
        return this.minimumIdleTimeTextField.getText();
    }

    public String getMaximumIdleTimeTextFieldValue() {
        return this.maximumIdleTimeTextField.getText();
    }

    public String getRequestCountValue() {
        return this.requestCountTextField.getText();
    }

    public boolean isRandomizeIdleTime() {
        return this.randomizeIdleTimeCheckBox.isSelected();
    }

    public void reflectScanLogPanelInputToMainPanel() {
        CustomScanJSONData.ScanRule selectedScanRule = getSelectedScanRule();
        this.randomizeIdleTimeCheckBox.setSelected(selectedScanRule.isRandomIdleTime());
        this.requestCountTextField.setText(Integer.toString(selectedScanRule.getRequestCount()));
        this.minimumIdleTimeTextField.setText(Integer.toString(selectedScanRule.getMinIdleTime()));
        this.maximumIdleTimeTextField.setText(Integer.toString(selectedScanRule.getMaxIdleTime()));
    }

    @Override
    public void setVisible(boolean b) {
        if (isBuildCalled) {
            super.setVisible(b);
        } else {
            LOGGER4J.error("setVisible is called before build method is called.");
            throw new RuntimeException("setVisible is called before build method is called.");
        }
    }
}
