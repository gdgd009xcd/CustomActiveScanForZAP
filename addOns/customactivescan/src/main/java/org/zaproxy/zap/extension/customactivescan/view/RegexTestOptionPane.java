package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.Constant;

import javax.swing.*;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.text.Style;
import java.awt.*;

import static org.zaproxy.zap.extension.customactivescan.view.RegexTestDialog.*;

@SuppressWarnings("serial")
public class RegexTestOptionPane extends GridBagJDialog<RegexTestOptionPane.RegexTestOptions> {

    private JLabel messageLabel;
    private RegexTestDialog.SearchTextPane searchTextPane;
    private int pos;
    RegexTestDialog dialog;

    static class RegexTestOptions {
        String message;
        RegexTestDialog.SearchTextPane searchTextPane;

        public RegexTestOptions(String message, RegexTestDialog.SearchTextPane searchTextPane) {
            this.message = message;
            this.searchTextPane = searchTextPane;
        }
    }

    public RegexTestOptionPane(RegexTestDialog dialog, String title, ModalityType modalityType,  RegexTestOptions options, int fill) {
        super(dialog, dialog, title, modalityType, options, fill);
        this.searchTextPane = options.searchTextPane;
        pos = 0;
        this.dialog = dialog;
        pack();
        setLocationRelativeTo(dialog);
    }

    @Override
    protected Component createMainPanelContent(Component mainPanel, RegexTestOptions options) {
        JPanel panel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        panel.setLayout(gridBagLayout);

        GridBagConstraints gbc = new GridBagConstraints();

        messageLabel = new JLabel(options.message);
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
        this.dialog.nextBtnActionPerformed();
        int foundCount = searchTextPane.findplist.size();
        String message = String.format(
                Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.formatfound.text"),
                searchTextPane.caretIndex + 1,
                foundCount);
        messageLabel.setText(message);
    }

    @Override
    protected String okBtnLabelString() {
        return "NEXT SEARCH";
    }

    @Override
    protected void cancelBtnActionPerformed() {
        dialog.disposeChild();
    }

    @Override
    protected String cancelBtnLabelString() {
        return "CLOSE";
    }

    @Override
    public void disposeChild() {

    }
}
