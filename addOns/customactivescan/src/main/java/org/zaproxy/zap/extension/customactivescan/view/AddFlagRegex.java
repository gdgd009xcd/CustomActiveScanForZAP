package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("serial")
public class AddFlagRegex extends GridBagJDialog<String>{
    private JTextField regexPatternField;
    private JList<String> flagPatternList;
    private int selectedIndex = -1;
    private CustomScanMainPanel mainPanel;

    AddFlagRegex(CustomScanMainPanel mainPanel, String title, ModalityType modarityType) {
        super(SwingUtilities.windowForComponent(mainPanel), title, modarityType, null, GridBagConstraints.HORIZONTAL, GridBagConstraints.NORTHEAST);
        this.mainPanel = mainPanel;
    }

    AddFlagRegex(Dialog dialog, CustomScanMainPanel mainPanel, String title, ModalityType modarityType) {
        super(dialog, mainPanel, title, modarityType, null, GridBagConstraints.HORIZONTAL, GridBagConstraints.NORTHEAST);
        this.mainPanel = mainPanel;
    }
    @Override
    protected Component createMainPanelContent(Component mainPanel, String optionalObject) {
        JPanel panel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        panel.setLayout(gridBagLayout);

        GridBagConstraints gbc = new GridBagConstraints();

        LineBorder regexPatternBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder regexPatternTitledBorder = new TitledBorder(regexPatternBorderLine,
                "Matching Regex pattern in Http Response",
                TitledBorder.LEFT,
                TitledBorder.TOP);

        panel.setBorder(regexPatternTitledBorder);

        // regex text field
        this.regexPatternField = new JTextField(40);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1d;
        gbc.weighty = 0d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gridBagLayout.setConstraints(regexPatternField, gbc);
        panel.add(regexPatternField);

        // test regex button
        JButton testButton = new JButton("Test");
        testButton.addActionListener(l ->{
            List<RegexTestDialog.PaneTitleAndContent> paneTitleAndContentList = new ArrayList<>();
            RegexTestDialog.PaneContents paneContents = new RegexTestDialog.PaneContents(this.regexPatternField.getText());
            paneContents.addTitleAndContent("Search Text", "", null);
            RegexTestDialog regexTestDialog = new RegexTestDialog(this,"Regex test", ModalityType.DOCUMENT_MODAL, paneContents);
            regexTestDialog.setRegexTextField(this.regexPatternField);
            regexTestDialog.setVisible(true);
        });
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0d;
        gbc.weighty = 0d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gridBagLayout.setConstraints(testButton, gbc);
        panel.add(testButton);
        return panel;
    }

    @Override
    protected void okBtnActionPerformed() {
        String regexText = this.regexPatternField.getText();
        if (!regexText.isEmpty()) {
            DefaultListModel<String> model = (DefaultListModel<String >) this.flagPatternList.getModel();
            if (selectedIndex != -1) {// modify selected value in JList
                model.set(selectedIndex, regexText);
            } else {// add value to JList
                model.addElement(regexText);
            }
            this.mainPanel.updateFlagResultItemsWithFlagPatternListModel();
        }
        dispose();
    }

    @Override
    protected void cancelBtnActionPerformed() {
        dispose();
    }

    @Override
    public void disposeChild() {

    }

    public void setFlagPatternList(JList<String> flagPatternList, boolean isAddAction) {
        if (flagPatternList != null) {
            this.flagPatternList = flagPatternList;
            if (isAddAction) {
                selectedIndex = -1;
            } else {
                selectedIndex = this.flagPatternList.getSelectedIndex();
                if (selectedIndex != -1) {
                    String selectedData = this.flagPatternList.getSelectedValue();
                    this.regexPatternField.setText(selectedData);
                }
            }
        }
    }
}
