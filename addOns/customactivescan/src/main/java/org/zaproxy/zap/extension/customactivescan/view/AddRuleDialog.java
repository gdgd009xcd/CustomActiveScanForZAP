package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.CustomScanDataModel;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ItemEvent;

@SuppressWarnings("serial")
public class AddRuleDialog extends GridBagJDialog {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    AddRuleDialog(Window owner, String title, ModalityType modalityType) {
        super(owner, title, modalityType, GridBagConstraints.HORIZONTAL);
    }

    @SuppressWarnings("unchecked")
    @Override
    protected Component createMainPanelContent() {
        JPanel panel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        panel.setLayout(gridBagLayout);

        GridBagConstraints gbc = new GridBagConstraints();

        LineBorder ruleNameBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder ruleNameTitledBorder = new TitledBorder(ruleNameBorderLine,
                "Rule Name",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JTextField ruleNameField = new JTextField(40);
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

        // scanRule Combobox
        LineBorder ruleComboBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder ruleComboTitledBorder = new TitledBorder(ruleComboBorderLine,
                "Select RuleType",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JComboBox<String> ruleComboBox = new JComboBox<>();
        for(String ruleName: CustomScanDataModel.RuleType.getNameList()) {
            ruleComboBox.addItem(ruleName);
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

        JCheckBox scanLogCheckBox = new JCheckBox("Response results output to \"ScanLog\" window");
        scanLogCheckBox.addItemListener(l -> {
            boolean isSelected = l.getStateChange() == ItemEvent.SELECTED ? true : false;
            LOGGER4J.debug("scanLog: " + (isSelected?"YES":"NO"));
        });

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0d;
        gbc.weighty = 0d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;// LEFTTOP
        gridBagLayout.setConstraints(scanLogCheckBox, gbc);
        panel.add(scanLogCheckBox);

        return panel;
    }

    @Override
    protected void okBtnActionPerformed() {
        dispose();
    }

    @Override
    protected void cancelBtnActionPerformed() {
        dispose();
    }
}
