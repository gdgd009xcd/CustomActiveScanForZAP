package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SuppressWarnings("serial")
public class RegexTestDialog extends GridBagJDialog {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    // these parameters are set value by createMainPanelContent method.
    // these parameters MUST NOT initialize at declaration here.
    // because createMainPanelContent method is called before parameter initialization process
    // regex text
    private JTextPane regexTextPane;
    // search text
    private JTextPane searchTextPane;

    // attribute List for searched texts
    private List<RegexSelectedTextPos> foundTextAttrPos = null;
    // caretPosition for searchd text at first
    private ArrayList<Integer> findplist;
    private JTextField targetTextField;

    public RegexTestDialog(Window owner, String title, ModalityType modalityType) {
        super(owner, title, modalityType, GridBagConstraints.BOTH);
    }

    private JPanel createRegexTestDialogContent() {
        JPanel panel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        panel.setLayout(gridBagLayout);

        GridBagConstraints gbc = new GridBagConstraints();

        // buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        // Regex test button
        JButton regexTestButton = new JButton("Search");
        regexTestButton.addActionListener(e ->{
            regexSearchActionPerformed(e);
        });
        buttonPanel.add(regexTestButton);
        // button for clear attributes of found text
        JButton clearTestButton = new JButton("Clear");
        clearTestButton.addActionListener(e ->{
            clearTestActionPerformed(e);
        });
        buttonPanel.add(clearTestButton);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1d;
        gbc.weighty = 0d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gridBagLayout.setConstraints(buttonPanel, gbc);
        panel.add(buttonPanel);

        // Regex text pane
        LineBorder regexTextBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder regexTextTitledBorder = new TitledBorder(regexTextBorderLine,
                "Regex text",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JScrollPane regexTextScroller = new JScrollPane();
        regexTextScroller.setBorder(regexTextTitledBorder);
        regexTextScroller.setPreferredSize(new Dimension(400,100));
        regexTextScroller.setMinimumSize(new Dimension(400, 100));
        regexTextScroller.setAutoscrolls(true);
        this.regexTextPane = new JTextPane();
        regexTextScroller.setViewportView(regexTextPane);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1d;
        gbc.weighty = 0d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gridBagLayout.setConstraints(regexTextScroller, gbc);
        panel.add(regexTextScroller);

        // Regex text pane
        LineBorder searchTextBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder searchTextTitledBorder = new TitledBorder(searchTextBorderLine,
                "Search Text",
                TitledBorder.LEFT,
                TitledBorder.TOP);
        JScrollPane searchTextScroller = new JScrollPane();
        searchTextScroller.setBorder(searchTextTitledBorder);
        searchTextScroller.setPreferredSize(new Dimension(400,500));
        searchTextScroller.setAutoscrolls(true);
        searchTextPane = new JTextPane();
        searchTextScroller.setViewportView(searchTextPane);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1d;
        gbc.weighty = 1d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gridBagLayout.setConstraints(searchTextScroller, gbc);
        panel.add(searchTextScroller);

        return panel;
    }

    @Override
    protected Component createMainPanelContent() {
        return createRegexTestDialogContent();
    }

    @Override
    protected void okBtnActionPerformed() {
        if (this.regexTextPane.getText() != null && this.targetTextField != null) {
            this.targetTextField.setText(this.regexTextPane.getText());
        }
        dispose();
    }

    @Override
    protected void cancelBtnActionPerformed() {
        dispose();
    }

    public static class RegexSelectedTextPos {
        int st;
        int et;

        RegexSelectedTextPos(int st, int et) {
            this.st = st;
            this.et = et;
        }

        int getStartPos() {
            return this.st;
        }

        int getEndPos() {
            return this.et;
        }

    }

    private void clearTestActionPerformed(ActionEvent e) {
        SimpleAttributeSet attr = new SimpleAttributeSet();

        if (foundTextAttrPos == null) {
            foundTextAttrPos = new ArrayList<>();
        }

        String regex = this.regexTextPane.getText();

        StyledDocument doc = this.searchTextPane.getStyledDocument();

        if (foundTextAttrPos.size() > 0) {
            StyleConstants.setForeground(attr, Color.BLACK);
            StyleConstants.setBackground(attr, Color.WHITE);

            foundTextAttrPos.forEach(rpos -> {
                doc.setCharacterAttributes(rpos.getStartPos(), rpos.getEndPos() - rpos.getStartPos(), attr, false);
            });

            foundTextAttrPos.clear();
        }
    }

    private void regexSearchActionPerformed(ActionEvent e) {
        // clear attrubutes in searchTextPane
        clearTestActionPerformed(null);

        SimpleAttributeSet attr = new SimpleAttributeSet();

        String regex = regexTextPane.getText();

        StyledDocument doc = searchTextPane.getStyledDocument();

        if (regex == null || regex.isEmpty()) { // if you do it, Too many patterns matched.
            return;
        }

        String original = null;
        try {
            original = doc.getText(0, doc.getLength());
        } catch (BadLocationException ex) {
            Logger.getLogger(RegexTestDialog.class.getName()).log(Level.SEVERE, null, ex);
        }

        findplist = new ArrayList<>();

        //parse Regex
        Pattern compiledregex = null;
        Matcher m = null;
        try{

            compiledregex = Pattern.compile(regex, Pattern.MULTILINE);

            m = compiledregex.matcher(original);
        }catch(Exception ex){
            LOGGER4J.error("Exception:" + ex.getMessage(), ex);
            return;
        }



        int cpt = 0;

        int fcount=0;
        while (m.find()) {
            fcount++;
            int spt0 = -1;
            int ept0 = -1;
            int spt = -1;
            int ept = -1;
            int gcnt = m.groupCount();
            String matchval = null;
            if ( gcnt > 0){
                spt0 = m.start();
                ept0 = m.end();
                for(int n = 0; n < gcnt ; n++){
                    spt = m.start(n+1);
                    ept = m.end(n+1);
                    matchval = m.group(n+1);

                }
                if ( matchval == null){
                    matchval = m.group();
                }
                if ( spt0 > spt){
                    spt0 = spt;
                }
                if(ept0 < ept){
                    ept0 = ept;
                }
                // spt0--->spt<matchval>ept-->ept0
            }else{//Nothing Groups...
                spt0 = m.start();
                ept0 = m.end();
                matchval = m.group();
            }
            if ( spt0 >=0 && ept0 >= 0 ){

                try {

                    // spt0--->spt<matchval>ept-->ept0

                    if (ept0 > spt0) {
                        StyleConstants.setForeground(attr, Color.BLUE);
                        StyleConstants.setBackground(attr, Color.RED);
                        doc.setCharacterAttributes(spt0, ept0-spt0, attr, false);
                        RegexSelectedTextPos rpos = new RegexSelectedTextPos(spt0, ept0);
                        foundTextAttrPos.add(rpos);
                    }

                    if (ept > spt) {
                        StyleConstants.setForeground(attr, Color.WHITE);
                        StyleConstants.setBackground(attr, Color.RED);
                        doc.setCharacterAttributes(spt, ept-spt, attr, false);
                        RegexSelectedTextPos rpos = new RegexSelectedTextPos(spt, ept);
                        foundTextAttrPos.add(rpos);
                    }

                    //int pos = OriginalText.getCaretPosition();
                    int pos = doc.getLength();
                    findplist.add(ept0);
                } catch (Exception ex) {
                    LOGGER4J.error("Exception:" + ex.getMessage(), ex);
                }
            }
        }

        if ( findplist.size() > 0){
            searchTextPane.setCaretPosition(findplist.get(0));
            int foundCount = findplist.size();
            JOptionPane.showMessageDialog(this, Integer.toString(foundCount)+"箇所一致しました", "検索結果", JOptionPane.INFORMATION_MESSAGE);
        }else{
            Toolkit.getDefaultToolkit().beep();
            JOptionPane.showMessageDialog(this, "正規表現が一致しませんでした", "検索結果", JOptionPane.QUESTION_MESSAGE);
        }
    }

    public void setRegexTextField(JTextField targetTextField) {
        if (this.regexTextPane != null) {
            if(targetTextField != null) {
                this.targetTextField = targetTextField;
                this.regexTextPane.setText(targetTextField.getText());
            }
        }
    }

    public void setSearchTextPane(String searchText) {
        if (this.searchTextPane != null) {
            this.searchTextPane.setText(searchText);
        }
    }
}
