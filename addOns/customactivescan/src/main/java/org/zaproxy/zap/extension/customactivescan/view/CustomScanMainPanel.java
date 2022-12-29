package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.CustomScanDataModel;
import org.zaproxy.zap.extension.customactivescan.model.InjectionPatterns;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.ItemEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("serial")
public class CustomScanMainPanel extends JPanel {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private JLabel ruleTypeLabel = null;
    private JScrollPane rulePatternScroller = null;
    private int selectedScanRuleIndex = 0;
    private CustomScanDataModel scanDataModel;
    private boolean showSaveFileDialog = false;
    private JCheckBox scanLogCheckBox = null;
    JPopupMenu flagPatternPopupMenu = null;
    JMenuItem flagPatternMod;
    JList<String> flagPatternList;
    DefaultListModel<String> flagPatternListModel;

    public CustomScanMainPanel() {
        super(new GridBagLayout());

        showSaveFileDialog = false;
        // load scan configration data.
        scanDataModel = new CustomScanDataModel();
        scanDataModel.createSampleData();

        CustomScanDataModel.ScanRule selectedScanRule = getSelectedScanRule();

        // create GUI
        GridBagLayout gridBagLayout = (GridBagLayout) getLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        // menu for configuring rule
        JPanel scanRuleMenuBarPanel = new JPanel();
        BorderLayout borderLayout = new BorderLayout();
        scanRuleMenuBarPanel.setLayout(borderLayout);
        JMenuBar scanRuleMenuBar = new JMenuBar();
        //scanRuleMenuBar.setPreferredSize(new Dimension(50, 27));
        JMenu scanRuleMenuTitle = new JMenu("Rule");
        scanRuleMenuBar.add(scanRuleMenuTitle);
        JMenuItem addRuleMenuItem = new JMenuItem("Add Rule");
        scanRuleMenuTitle.add(addRuleMenuItem);
        addRuleMenuItem.addActionListener(e ->{
            addRuleActionPerformed(e);
        });

        ruleTypeLabel = new JLabel(selectedScanRule.getRuleTypeName());
        LineBorder ruleTypeLabelBorderLine = new LineBorder(Color.BLACK, 1, true);
        ruleTypeLabel.setBorder(ruleTypeLabelBorderLine);
        JLabel spaceLabel = new JLabel(" ");
        scanRuleMenuBar.add(ruleTypeLabel);
        scanRuleMenuBar.add(spaceLabel);
        // Gridbaglayout cannot handle JMenuBar properly, so we use Borderlayout for JMenuBar
        scanRuleMenuBarPanel.add(scanRuleMenuBar, BorderLayout.LINE_START);

        // scanRule Combobox
        JComboBox<String> ruleComboBox = new JComboBox<>();
        for(CustomScanDataModel.ScanRule rule: scanDataModel.scanRuleList) {
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

        // custom scan pattern list
        rulePatternScroller = new JScrollPane();
        createRuleTable(selectedScanRule);
        rulePatternScroller.setPreferredSize(new Dimension(400,400));
        rulePatternScroller.setAutoscrolls(true);
        LineBorder rulePatternBorderLine = new LineBorder(Color.BLACK, 2, true);
        TitledBorder rulePatternTitledBorder = new TitledBorder(rulePatternBorderLine,
                "Attacking Patterns for CustomActiveScan",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        rulePatternScroller.setBorder(rulePatternTitledBorder);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 0d;
        gbc.weighty = 0.5d;
        gbc.insets = new Insets(1,1,1,1);
        //gbc.anchor = GridBagConstraints.FIRST_LINE_START;
        gridBagLayout.setConstraints(rulePatternScroller, gbc);
        add(rulePatternScroller);

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
                "\"ScanLog\" window for displaying output response results",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        scanLogPanel.setBorder(scanLogPanelTitledBorder);

        scanLogCheckBox = new JCheckBox("Response results output to \"ScanLog\" window");
        scanLogCheckBox.setSelected(selectedScanRule.doScanLogOutput);
        scanLogCheckBox.addItemListener(e -> {
            CustomScanDataModel.ScanRule currentScanRule = getSelectedScanRule();
            currentScanRule.doScanLogOutput = e.getStateChange() == ItemEvent.SELECTED ? true : false;
        });
        scanLogPanel.add(scanLogCheckBox, BorderLayout.PAGE_START);

        // Regexes for detecting keyword in Http response.
        String[] initflagData = {"ORA-", "Syntax", "Error"};
        this.flagPatternListModel = new DefaultListModel<>();
        for(String data: initflagData) {
            this.flagPatternListModel.addElement(data);
        }
        this.flagPatternList = new JList<>(this.flagPatternListModel);
        this.flagPatternPopupMenu = new JPopupMenu();
        JMenuItem flagPatternAdd = new JMenuItem("Add");
        flagPatternAdd.addActionListener(l ->{
            addFlagPatternActionPerformed(l, true);
        });
        this.flagPatternPopupMenu.add(flagPatternAdd);
        this.flagPatternMod = new JMenuItem("Mod");
        this.flagPatternMod.addActionListener(l ->{
            addFlagPatternActionPerformed(l, false);
        });
        this.flagPatternPopupMenu.add(flagPatternMod);
        JMenuItem flagPatternDel = new JMenuItem("Del");
        flagPatternDel.addActionListener(l -> {
            int selectedIndex = this.flagPatternList.getSelectedIndex();
            if (selectedIndex != -1) {
                this.flagPatternListModel.remove(selectedIndex);
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
                "Regexes for detecting keywords in response results",
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
        GridLayout idleTimeLayout = new GridLayout(3,1);
        idleTimePanel.setLayout(idleTimeLayout);
        LineBorder idleTimePanelBorderLine = new LineBorder(Color.BLACK, 1, true);
        TitledBorder idleTimePanelTitledBorder = new TitledBorder(idleTimePanelBorderLine,
                "Idle Time between sending requests configrations",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        idleTimePanel.setBorder(idleTimePanelTitledBorder);

        // randomize idle time or not
        JCheckBox randomizeIdleTimeCheckBox = new JCheckBox("Randomize Idle time");
        idleTimePanel.add(randomizeIdleTimeCheckBox);

        // Minimum idle time between  sending requests
        LineBorder minimumIdleTimeBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder minimumIdleTimeTitledBorder = new TitledBorder(minimumIdleTimeBorderLine,
                "Minimum Idle Time between sending requests(mSec)",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JTextField minimumIdleTimeTextField = new JTextField("0");
        minimumIdleTimeTextField.setBorder(minimumIdleTimeTitledBorder);
        idleTimePanel.add(minimumIdleTimeTextField);

        // Maximum idle time between  sending requests
        LineBorder maximumIdleTimeBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder maximumIdleTimeTitledBorder = new TitledBorder(maximumIdleTimeBorderLine,
                "Maximum Idle Time between sending requests(mSec)",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JTextField maximumIdleTimeTextField = new JTextField("0");
        maximumIdleTimeTextField.setBorder(maximumIdleTimeTitledBorder);

        idleTimePanel.add(maximumIdleTimeTextField);

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

    }

    private void createRuleTable(CustomScanDataModel.ScanRule selectedScanRule) {
        if (this.rulePatternScroller != null) {
            ruleTypeLabel.setText(selectedScanRule.getRuleTypeName());
            DefaultTableModel defaultTableModel = new DefaultTableModel();
            List<String[]> tableDataList = new ArrayList<>();

            if (scanLogCheckBox != null) {
                scanLogCheckBox.setSelected(selectedScanRule.doScanLogOutput);
            }

            if ( selectedScanRule.ruleType == CustomScanDataModel.RuleType.SQL) {

                String[] columnNames = {"TrueValue", "FalseValue", "ErrorValue", "TrueName", "FalseName", "ErrorName"};
                for(InjectionPatterns.TrueFalsePattern patternRow: selectedScanRule.patterns.patterns) {
                    String[] rowData = {patternRow.trueValuePattern,
                            patternRow.falseValuePattern,
                            patternRow.errorValuePattern,
                            patternRow.trueNamePattern,
                            patternRow.falseNamePattern,
                            patternRow.errorNamePattern
                    };
                    tableDataList.add(rowData);
                }
                String[][] tableDataArray = tableDataList.toArray(new String[0][0]);// specified zero size array means that  new array will be allocated
                defaultTableModel.setDataVector(tableDataArray, columnNames);
            } else { // RuleType.PenTest
                String[] columnNames = {"trueValue"};
                for(InjectionPatterns.TrueFalsePattern patternRow: selectedScanRule.patterns.patterns) {
                    String[] rowData = {
                            patternRow.trueValuePattern
                    };
                    tableDataList.add(rowData);
                }
                String[][] tableDataArray = tableDataList.toArray(new String[0][0]);// specified zero size array means that  new array will be allocated
                defaultTableModel.setDataVector(tableDataArray, columnNames);
            }
            JTable rulePatternTable = new CustomJTable(this, this.rulePatternScroller, defaultTableModel);
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
                    rulePatternTableFocusLost(rulePatternTable.isEditing());
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
        new AddRuleDialog(SwingUtilities.windowForComponent(this), "AddRule", Dialog.ModalityType.DOCUMENT_MODAL).setVisible(true);
    }

    public void addFlagPatternActionPerformed(ActionEvent e, boolean isAddAction) {
        AddFlagRegex addFlagRegexDialog = new AddFlagRegex(SwingUtilities.windowForComponent(this), "Add/Mod flag result item regex", Dialog.ModalityType.DOCUMENT_MODAL);
        addFlagRegexDialog.setFlagPatternList(this.flagPatternList, isAddAction);
        addFlagRegexDialog.setVisible(true);
    }

    @SuppressWarnings("unchecked")
    public void ruleComboBoxActionPerformed(ActionEvent e) {
        JComboBox<String> cb = (JComboBox<String>)e.getSource();
        String actionCommandString = e.getActionCommand();

        LOGGER4J.debug("ruleComboBoxAction[" + e.getActionCommand() + "] item:" + cb.getSelectedItem() + " item index:" + cb.getSelectedIndex());

        if (selectedScanRuleIndex != cb.getSelectedIndex()) {
            selectedScanRuleIndex = cb.getSelectedIndex();
            CustomScanDataModel.ScanRule selectedScanRule = scanDataModel.getScanRule(selectedScanRuleIndex);
            createRuleTable(selectedScanRule);
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

    public void rulePatternTableFocusLost(boolean isEditing) {
        if (isEditing && !scanDataModel.isSaved()) {
            showSaveFileDialog = true;
            LOGGER4J.debug("showSaveDialog=true");
            Path relativePath = Paths.get("");// current directory relative path
            Path absolutePath = relativePath.toAbsolutePath();
            String absolutePathString = absolutePath.toString();
            JFileChooser jfc = new JFileChooser(absolutePathString) {

                @Override
                public void approveSelection() {
                    File f = getSelectedFile();
                    if (f.exists() && getDialogType() == SAVE_DIALOG) {
                        String m = String.format(
                                "<html>%s already exists.<br>Do you want to replace it?",
                                f.getAbsolutePath());
                        int rv = JOptionPane.showConfirmDialog(
                                this, m, "Save As", JOptionPane.YES_NO_OPTION);
                        if (rv != JOptionPane.YES_OPTION) {
                            return;
                        }
                    }
                    super.approveSelection();
                }
            };
            FileFilterForJSON pFilter = new FileFilterForJSON();
            jfc.setFileFilter(pFilter);

            LOGGER4J.debug("start Popup Save Dialog");
            if (jfc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = jfc.getSelectedFile();
                String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
                if(!pFilter.accept(file)){
                    name += ".json";
                }
                scanDataModel.saveToFile(name);
            }

            showSaveFileDialog = false;
            LOGGER4J.debug("showSaveDialog=false");
        }
    }

    private void tableCellEditorFocusLost(DefaultCellEditor dce) {
        if (!showSaveFileDialog) {// when focus move other components except FileChooser(Save dialog)
            dce.stopCellEditing();
        }
    }

    /**
     * update CustomScanDataModel with JTable contents(TableModel)
     * @param jTableModel
     */
    public void updateModelWithJTableModel(TableModel jTableModel) {
        int rowCount = jTableModel.getRowCount();
        CustomScanDataModel.ScanRule selectedScanRule = scanDataModel.getScanRule(selectedScanRuleIndex);
        selectedScanRule.patterns.clearPatterns();
        if ( selectedScanRule.ruleType == CustomScanDataModel.RuleType.SQL) {
            for(int i = 0; i < rowCount; i++) {
                selectedScanRule.patterns.addPattern(
                        (String)jTableModel.getValueAt(i, 0),
                        (String)jTableModel.getValueAt(i, 1),
                        (String)jTableModel.getValueAt(i, 2),
                        (String)jTableModel.getValueAt(i, 3),
                        (String)jTableModel.getValueAt(i, 4),
                        (String)jTableModel.getValueAt(i, 5)
                );
            }
        } else {// PenTest
            for(int i = 0; i < rowCount; i++) {
                selectedScanRule.patterns.addPattern(
                        (String)jTableModel.getValueAt(i, 0),
                        null,
                        null,
                        null,
                        null,
                        null
                );
            }
        }

    }

    public CustomScanDataModel.ScanRule getSelectedScanRule() {
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
}
