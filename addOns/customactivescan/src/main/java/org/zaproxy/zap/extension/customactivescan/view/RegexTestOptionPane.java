package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;

@SuppressWarnings("serial")
public class RegexTestOptionPane extends GridBagJDialog<RegexTestOptionPane.RegexTestOptions> {

    private RegexTestDialog.SearchTextPane searchTextPane;
    private int pos;

    static class RegexTestOptions {
        String message;
        RegexTestDialog.SearchTextPane searchTextPane;

        public RegexTestOptions(String message, RegexTestDialog.SearchTextPane searchTextPane) {
            this.message = message;
            this.searchTextPane = searchTextPane;
        }
    }

    public RegexTestOptionPane(Component mainPanel, String title, ModalityType modalityType,  RegexTestOptions options, int fill) {
        super(mainPanel, title, modalityType, options, fill);
        this.searchTextPane = options.searchTextPane;
        pos = 0;
        pack();
        setLocationRelativeTo(mainPanel);
    }

    @Override
    protected Component createMainPanelContent(Component mainPanel, RegexTestOptions options) {
        JPanel panel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        panel.setLayout(gridBagLayout);

        GridBagConstraints gbc = new GridBagConstraints();

        JLabel messageLabel = new JLabel(options.message);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        //gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0d;
        gbc.weighty = 0d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gridBagLayout.setConstraints(messageLabel, gbc);
        panel.add(messageLabel);

        return panel;
    }

    @Override
    protected void okBtnActionPerformed() {
        StyledDocument doc = searchTextPane.searchTextPane.getStyledDocument();
        SimpleAttributeSet attr = new SimpleAttributeSet();
        // reset coloring attribute current caret position.
        for(int i=pos * 2; i < pos * 2 + 2; i++) {
            RegexTestDialog.RegexSelectedTextPos regexSelectedTextPos = searchTextPane.foundTextAttrPos.get(i);
            int spt = regexSelectedTextPos.getStartPos();
            int ept = regexSelectedTextPos.getEndPos();
            if (i==pos * 2) {
                StyleConstants.setForeground(attr, Color.BLUE);
            }else {
                StyleConstants.setForeground(attr, Color.BLACK);
            }
            StyleConstants.setBackground(attr, Color.RED);
            doc.setCharacterAttributes(spt, ept - spt, attr, false);
        }

        int nextpos = pos + 1;
        if (nextpos >= this.searchTextPane.findplist.size()) {
            nextpos = 0;
        }

        for(int i=nextpos * 2; i < nextpos * 2 + 2; i++) {
            RegexTestDialog.RegexSelectedTextPos regexSelectedTextPos = searchTextPane.foundTextAttrPos.get(i);
            int spt = regexSelectedTextPos.getStartPos();
            int ept = regexSelectedTextPos.getEndPos();

            if (i == nextpos * 2) {
                StyleConstants.setForeground(attr, Color.BLUE);
            } else {
                StyleConstants.setForeground(attr, Color.WHITE);
            }
            StyleConstants.setBackground(attr, Color.RED);
            doc.setCharacterAttributes(spt, ept - spt, attr, false);
        }
        searchTextPane.searchTextPane.setCaretPosition(searchTextPane.findplist.get(nextpos));
        pos = nextpos;
    }

    @Override
    protected String okBtnLabelString() {
        return "NEXT SEARCH";
    }

    @Override
    protected void cancelBtnActionPerformed() {
        dispose();
    }

    @Override
    protected String cancelBtnLabelString() {
        return "CLOSE";
    }
}
