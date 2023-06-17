package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.CustomScanJSONData;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ItemEvent;

@SuppressWarnings("serial")
public class AddRuleDialogByCopy extends GridBagJDialog<String> {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    CustomScanMainPanel mainPanel;
    JTextField ruleNameField;
    JComboBox<String> ruleComboBox;
    CustomScanJSONData.ScanRule sampleSQL;
    CustomScanJSONData.ScanRule samplePenTest;


    AddRuleDialogByCopy(CustomScanMainPanel mainPanel, String title, ModalityType modalityType) {
        super(mainPanel, title, modalityType, null, GridBagConstraints.HORIZONTAL);
        this.mainPanel = mainPanel;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected Component createMainPanelContent(Component mainPanelComponent, String optionalObject) {
        this.mainPanel = (CustomScanMainPanel) mainPanelComponent;
        JPanel panel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        panel.setLayout(gridBagLayout);

        GridBagConstraints gbc = new GridBagConstraints();

        // name of new scanRule
        LineBorder ruleNameBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder ruleNameTitledBorder = new TitledBorder(ruleNameBorderLine,
                "Rule Name",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        ruleNameField = new JTextField(40);
        ruleNameField.setBorder(ruleNameTitledBorder);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1d;
        gbc.weighty = 0d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gridBagLayout.setConstraints(ruleNameField, gbc);
        panel.add(ruleNameField);

        // scanRule contents copy from
        LineBorder ruleComboBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder ruleComboTitledBorder = new TitledBorder(ruleComboBorderLine,
                "Select scanRule Copy From",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        ruleComboBox = new JComboBox<>();
        for(CustomScanJSONData.ScanRule scanRule: mainPanel.getScanRuleList()) {
            String ruleName = scanRule.patterns.name;
            LOGGER4J.debug("original ruleName[" + ruleName + "]");
            ruleComboBox.addItem(ruleName);
        }

        // add sample rule if needed.
        for(CustomScanJSONData.ScanRule scanRule: mainPanel.getSampleScanRuleList()) {
            String ruleName = scanRule.patterns.name;
            if (!mainPanel.ruleNameIsExistInModel(ruleName, true)) {
                LOGGER4J.debug("sample ruleName[" + ruleName + "]");
                ruleComboBox.addItem(ruleName);
            }
        }

        ruleComboBox.setBorder(ruleComboTitledBorder);
        ruleComboBox.addActionListener(e -> {
            JComboBox<String> cb = (JComboBox<String>)e.getSource();
            LOGGER4J.debug("ruleComboBoxAction[" + e.getActionCommand() + "] item:" + cb.getSelectedItem() + " item index:" + cb.getSelectedIndex());
        });

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1d;
        gbc.weighty = 0d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);

        gridBagLayout.setConstraints(ruleComboBox, gbc);
        panel.add(ruleComboBox);

        return panel;
    }

    @Override
    protected void okBtnActionPerformed() {
        String ruleName = ruleNameField.getText();
        String errorReasonText = null;
        if (ruleName != null && !ruleName.isEmpty()) {
            if (!this.mainPanel.ruleNameIsExistInModel(ruleName, false)) {
                int index = ruleComboBox.getSelectedIndex();
                this.mainPanel.addNewScanRuleByCopyFrom(ruleName, index);
            } else {
                errorReasonText = String.format("<HTML>ruleName[%s] is already used. use another name.", ruleName);
            }
        }
        if (errorReasonText != null) {
            JOptionPane.showMessageDialog(this, errorReasonText, "", JOptionPane.ERROR_MESSAGE);
        } else {
            dispose();
        }
    }

    @Override
    protected void cancelBtnActionPerformed() {
        dispose();
    }
}
