package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.customactivescan.StartEndPosition;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;
import org.apache.logging.log4j.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules.triangleUpIcon;
import static org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules.triangleDownIcon;


@SuppressWarnings("serial")
public class RegexTestDialog extends GridBagJDialog<RegexTestDialog.PaneContents> {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    final static Level LAPSETIME = Level.getLevel("LAPSETIME");
    // <---createMainPanelContent initialize member start line---
    // these parameters are set value by createMainPanelContent method.
    // these parameters MUST NOT initialize at declaration here.
    // because createMainPanelContent method is called before parameter initialization process in this class
    // regex text
    private JTextPane regexTextPane;

    private JTabbedPane tabbedPane;

    private List<SearchTextPane> searchTextPaneList;
    JCheckBox searchCountCheckBox;
    Map<String, InterfaceGenerateStyler> generateStylerMap;
    private int fixedStyleWidthMax;
    // ---createMainPanelContent initialize member end line--->

    // no used parameters in createMainPanelContent method
    private RegexTestOptionPane optionPane = null;

    private Dialog dialog = null;
    private Frame frame = null;
    private DisposeChildInterface parent = null;




    static final String SELECTEDGROUP_STYLENAME = "selectedGroupStyle";
    static final String CURRENT_SELECTEDGROUP_STYLENAME = "currentSelectedGroupStyle";
    static final String SELECTED_STYLENAME = "selectedStyle";
    static final String CURRENT_SELECTED_STYLENAME = "currentSelectedStyle";
    static final String ADD_UNDERLINE_STYLENAME = "addUnderLineStyle";
    static final String DEL_UNDERLINE_STYLENAME = "delUnderLineStyle";
    static final String MARK_LCS_STYLENAME = "markLcsStyle";
    static final String CRIMAGE_STYLENAME = "caridgeReturnStyle";
    static final String ADD_BOLD_STYLENAME = "addBoldFontStyle";
    static final String FIXED_LABEL_STYLENAME = "fixedLabelStyle";

    static final String[] styleNameArray = {
            SELECTEDGROUP_STYLENAME,
            CURRENT_SELECTEDGROUP_STYLENAME,
            SELECTED_STYLENAME,
            CURRENT_SELECTED_STYLENAME,
            ADD_UNDERLINE_STYLENAME,
            DEL_UNDERLINE_STYLENAME,
            MARK_LCS_STYLENAME,
            CRIMAGE_STYLENAME,
            ADD_BOLD_STYLENAME,
            FIXED_LABEL_STYLENAME
    };

    static final Color COLOR_PURPLE = new Color(128,0, 128);
    static final Color COLOR_OLIVE = new Color(128,128,0);
    static final Color COLOR_THICK_BLUE = new Color(10,25,226);

    static final int MAX_CONTENT_WRAP_LENGTH = 250000;
    static class SearchTextPane {
        //scroller
        JScrollPane searchScroller;
        // search text
        JTextPane searchTextPane;
        TextPaneWrapEditorKit wrapEditorKit;
        // attribute List for searched texts
        List<RegexSelectedTextPos> foundTextAttrPos;
        // caretPosition for searchd text at first
        List<Integer> findplist;
        // current index of caretPosition
        int caretIndex;
        boolean hasGroup;
        List<StartEndPosition> charIndexOfLcs;
        List<Integer> outBoundOfLcsList;
        int outBoundOfLcsIndex;




        SearchTextPane(List<StartEndPosition> charIndexOfLcs) {
            searchTextPane = null;
            searchScroller = null;
            wrapEditorKit = null;
            foundTextAttrPos = new ArrayList<>();
            findplist = new ArrayList<>();
            caretIndex = 0;
            hasGroup = false;
            this.charIndexOfLcs = charIndexOfLcs;
            this.outBoundOfLcsList = new ArrayList<>();
            this.outBoundOfLcsIndex = -1;
        }
        void updateCharIndexOfLcs(List<StartEndPosition> charIndexOfLcs) {
            this.charIndexOfLcs = charIndexOfLcs;
        }
    }

    static class PaneTitleAndContent {
        String title;
        String content;
        boolean editable = false;
        List<InterfaceOptionStaticStyler> optionStylerList;
        List<StartEndPosition> charIndexesOfContent;
        PaneTitleAndContent(){
            title = "";
            content = "";
            optionStylerList = null;
        }
        PaneTitleAndContent(String title, String content, List<StartEndPosition> charIndexesOfContent) {
            this.title = title;
            this.content = content;
            this.charIndexesOfContent = charIndexesOfContent;
        }

        PaneTitleAndContent(String title, String content, List<StartEndPosition> charIndexesOfContent, boolean editable) {
            this.title = title;
            this.content = content;
            this.charIndexesOfContent = charIndexesOfContent;
            this.editable = editable;
        }
        PaneTitleAndContent(String title, String content, List<StartEndPosition> charIndexesOfContent,
                            List<InterfaceOptionStaticStyler> optionStylerList) {
            this.title = title;
            this.content = content;
            this.charIndexesOfContent = charIndexesOfContent;
            this.optionStylerList = optionStylerList;
        }
    }

    static class PaneContents {
        public List<PaneTitleAndContent> paneTitleAndContentList;
        public String regexText;
        PaneContents(String regexText) {
            this.regexText = regexText;
            paneTitleAndContentList = new ArrayList<>();
        }

        public void addTitleAndContent(String title, String content, List<StartEndPosition> charIndexesOfContent) {
            PaneTitleAndContent paneTitleAndContent = new PaneTitleAndContent(title, content, charIndexesOfContent);
            paneTitleAndContentList.add(paneTitleAndContent);
        }

        public void addTitleAndContent(String title, String content, boolean editable) {
            PaneTitleAndContent paneTitleAndContent = new PaneTitleAndContent(title, content, null, editable);
            paneTitleAndContentList.add(paneTitleAndContent);
        }

        public void addTitleAndContent(String title, String content, List<StartEndPosition> charIndexesOfContent,
                                       List<InterfaceOptionStaticStyler> optionStylerList) {
            PaneTitleAndContent paneTitleAndContent = new PaneTitleAndContent(title, content, charIndexesOfContent, optionStylerList);
            paneTitleAndContentList.add(paneTitleAndContent);
        }
    }

    private JTextField targetTextField;


    public RegexTestDialog(Dialog dialog, String title, ModalityType modalityType, PaneContents paneContents) {
        super(dialog, title, modalityType, paneContents, GridBagConstraints.BOTH);
        this.dialog = dialog;
    }

    public RegexTestDialog(
            Frame frame,
            DisposeChildInterface parent,
            String title,
            ModalityType modalityType,
            PaneContents paneContents
           ) {
        super(frame, title, modalityType, paneContents, GridBagConstraints.BOTH);
        this.frame = frame;
        this.parent = parent;
    }

    private JPanel createRegexTestDialogContent(PaneContents paneContents) {
        searchTextPaneList = new ArrayList<>();
        generateStylerMap = new HashMap<>();
        JLabel fixedTestLabel = new JLabel("HHHHHHHHHHHHH");
        Dimension preferDim = fixedTestLabel.getPreferredSize();
        this.fixedStyleWidthMax = (int)preferDim.getWidth();

        JPanel panel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        panel.setLayout(gridBagLayout);

        GridBagConstraints gbc = new GridBagConstraints();

        // buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        // Regex test button
        JButton regexTestButton = new JButton("Search");
        regexTestButton.addActionListener(e ->{
            regexSearchActionPerformed(e, -1);
        });
        buttonPanel.add(regexTestButton);
        JButton prevSearch = new JButton(triangleUpIcon);
        prevSearch.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                prevBtnActionPerformed();
            }
        });
        buttonPanel.add(prevSearch);
        JButton nextSearch = new JButton(triangleDownIcon);
        nextSearch.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                nextBtnActionPerformed();
            }
        });
        buttonPanel.add(nextSearch);
        searchCountCheckBox = new JCheckBox("00000000/00000000");
        searchCountCheckBox.setSelected(false);
        searchCountCheckBox.setToolTipText("popup SearchResultDialog");
        buttonPanel.add(searchCountCheckBox);
        Dimension preferDimension = searchCountCheckBox.getPreferredSize();
        searchCountCheckBox.setText("0/0");
        searchCountCheckBox.setPreferredSize(preferDimension);
        // button for clear attributes of found text
        JButton clearTestButton = new JButton("Clear");
        clearTestButton.addActionListener(e ->{
            clearTestActionPerformed(e, -1);
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
        this.regexTextPane.setText(paneContents.regexText);
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

        // search text pane
        LineBorder searchTextBorderLine = new LineBorder(Color.BLUE, 1, true);
        TitledBorder searchTextTitledBorder = new TitledBorder(searchTextBorderLine,
                "Search Panes",
                TitledBorder.LEFT,
                TitledBorder.TOP);

        tabbedPane = new JTabbedPane();
        tabbedPane.setBorder(searchTextTitledBorder);
        for(PaneTitleAndContent titleAndContent: paneContents.paneTitleAndContentList) {
            SearchTextPane searchTextPane = createSearchTextScroller(titleAndContent, tabbedPane);
            searchTextPaneList.add(searchTextPane);
        }


        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1d;
        gbc.weighty = 1d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        gridBagLayout.setConstraints(tabbedPane, gbc);
        panel.add(tabbedPane);
        tabbedPane.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                long startTime = 0;
                if (LAPSETIME != null) {
                    startTime = System.currentTimeMillis();
                }
                int selectedTabbedPaneIndex = RegexTestDialog.this.tabbedPane.getSelectedIndex();

                if (selectedTabbedPaneIndex > -1) {
                    SearchTextPane searchTextPane = RegexTestDialog.this.searchTextPaneList.get(selectedTabbedPaneIndex);
                    String counterString = "0/0";
                    if (searchTextPane.findplist != null) {
                        int foundCount = searchTextPane.findplist.size();
                        if (foundCount > 0) {
                            counterString = String.format(
                                    Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.checkbox.formatfound"),
                                    searchTextPane.caretIndex + 1,
                                    foundCount);
                        }
                    }
                    RegexTestDialog.this.searchCountCheckBox.setText(counterString);
                    setImplicitStyles(searchTextPane, false);
                }
                if (LAPSETIME != null) {
                    long endTime = System.currentTimeMillis();
                    LOGGER4J.log(LAPSETIME, "RegexTestDialog stateChanged lapse(sec)=" + Math.round((float)(endTime - startTime)/100)/(float)10);
                }
            }
        });

        return panel;
    }


    private SearchTextPane createSearchTextScroller(PaneTitleAndContent titleAndContent, JTabbedPane tabbedPane) {
        SearchTextPane searchTextPane = new SearchTextPane(titleAndContent.charIndexesOfContent);
        JScrollPane searchTextScroller = new JScrollPane();
        searchTextScroller.setPreferredSize(new Dimension(600, 500));
        searchTextScroller.setAutoscrolls(true);

        searchTextPane.searchTextPane = new JTextPane(SwingStyleProvider.createSwingStyle().createStyledDocument());
        if (titleAndContent.content.length() < MAX_CONTENT_WRAP_LENGTH) {
            // large size of wrapping Text is heavy load for JTextPane.
            // Therefore, it is used when the size is less than MAX_CONTENT_WRAP_LENGTH.
            searchTextPane.wrapEditorKit = new TextPaneWrapEditorKit(SwingStyleProvider.createSwingStyle().createStyledDocument());
            searchTextPane.searchTextPane.setEditorKit(searchTextPane.wrapEditorKit);
            searchTextScroller.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        }
        searchTextPane.searchScroller = searchTextScroller;
        searchTextPane.searchTextPane.setEditable(titleAndContent.editable);
        // setEditorKit create new Document and set it to JTextPane.
        // setEditorKit call TextPaneWrapEditorKit.createDocument method for setting new one.
        // so I override TextPaneWrapEditorKit.createDocument method for setting new document.

        StyledDocument doc = searchTextPane.searchTextPane.getStyledDocument();
        createStyles(doc, titleAndContent.optionStylerList);

        LOGGER4J.debug("title[" + titleAndContent.title + "] size=" + titleAndContent.content.length());
        try {
            doc.remove(0, doc.getLength());
        }catch (Exception ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        insertStringCR(doc, 0, titleAndContent.content);
        searchTextPane.searchTextPane.setCaretPosition(0);
        searchTextScroller.setViewportView(searchTextPane.searchTextPane);
        tabbedPane.add(titleAndContent.title, searchTextScroller);
        return searchTextPane;
    }
    private void createStyles(StyledDocument doc, List<InterfaceOptionStaticStyler> optionStylerList) {
        Style defaultStyle = SwingStyle.getDefaultStyle(doc);
        for (String styleName: styleNameArray) {
            Style style = doc.getStyle(styleName);
            if (style == null) {
                Style newStyle = doc.addStyle(styleName, defaultStyle);
                InterfaceGenerateStyler generateStyler = null;
                switch(styleName){
                    case SELECTEDGROUP_STYLENAME:
                        StyleConstants.setForeground(newStyle, Color.MAGENTA);
                        StyleConstants.setBackground(newStyle, Color.ORANGE);
                        break;
                    case CURRENT_SELECTEDGROUP_STYLENAME:
                        StyleConstants.setForeground(newStyle, Color.WHITE);
                        StyleConstants.setBackground(newStyle, Color.GREEN);
                        break;
                    case SELECTED_STYLENAME:
                        StyleConstants.setForeground(newStyle, Color.BLACK);
                        StyleConstants.setBackground(newStyle, Color.ORANGE);
                        break;
                    case CURRENT_SELECTED_STYLENAME:
                        StyleConstants.setForeground(newStyle, Color.BLACK);
                        StyleConstants.setBackground(newStyle, Color.GREEN);
                        break;
                    case ADD_UNDERLINE_STYLENAME:
                        StyleConstants.setUnderline(newStyle, true);
                        break;
                    case DEL_UNDERLINE_STYLENAME:
                        StyleConstants.setUnderline(newStyle, false);
                        break;
                    case MARK_LCS_STYLENAME:
                        StyleConstants.setForeground(newStyle, COLOR_THICK_BLUE);
                        break;
                    case ADD_BOLD_STYLENAME:
                        StyleConstants.setBold(newStyle,true);
                        break;
                    case CRIMAGE_STYLENAME:
                        generateStyler = new InterfaceGenerateStyler() {
                            @Override
                            public Style getStyle(StyledDocument doc, String text) {
                                return getCRstyle(doc);
                            }
                        };
                        generateStylerMap.put(CRIMAGE_STYLENAME, generateStyler);
                        break;
                    case FIXED_LABEL_STYLENAME:
                        generateStyler = new InterfaceGenerateStyler() {
                            @Override
                            public Style getStyle(StyledDocument doc, String text) {
                                return getAlertTitleStyle(doc, text);
                            }
                        };
                        generateStylerMap.put(FIXED_LABEL_STYLENAME, generateStyler);
                        break;
                    default:
                        break;
                }
            }
        }
        if(optionStylerList != null && !optionStylerList.isEmpty()) {
            for(InterfaceOptionStaticStyler optionStyler: optionStylerList) {
                Style style = doc.getStyle(optionStyler.getStyleName());
                if (style == null) {
                    style = doc.addStyle(optionStyler.getStyleName(), defaultStyle);
                }
                optionStyler.setStyleAttributes(style);
            }
        }
    }

    private void removeStyles(StyledDocument doc) {
        for(String styleName: styleNameArray) {
            Style style = doc.getStyle(styleName);
            if (style != null) {
                doc.removeStyle(styleName);
            }
        }
    }

    private Style getStyleWithText(StyledDocument doc, String styleName, String text) {
        if (!this.generateStylerMap.isEmpty()) {
            InterfaceGenerateStyler generateStyler = this.generateStylerMap.get(styleName);
            if (generateStyler != null) {
                return generateStyler.getStyle(doc, text);
            }
        }
        return doc.getStyle(styleName);
    }

    @Override
    protected Component createMainPanelContent(Component mainPanel, PaneContents paneContents) {
        return createRegexTestDialogContent(paneContents);
    }

    @Override
    protected void okBtnActionPerformed() {
        if (this.regexTextPane.getText() != null && this.targetTextField != null) {
            this.targetTextField.setText(this.regexTextPane.getText());
        }
        if (this.parent != null) {
            this.parent.disposeChild();
        } else {
            dispose();
        }
    }

    @Override
    protected void cancelBtnActionPerformed() {
        if (this.parent != null) {
            this.parent.disposeChild();
        } else {
            dispose();
        }
    }

    public static class RegexSelectedTextPos {
        int st;
        int et;
        String styleName;

        RegexSelectedTextPos(String styleName, int st, int et) {
            this.st = st;
            this.et = et;
            this.styleName = styleName;
        }

        public int getStartPos() {
            return this.st;
        }

        public int getEndPos() {
            return this.et;
        }

        public String getStyleName() {
            return this.styleName;
        }

    }

    private void clearTestActionPerformed(ActionEvent e, int selectedTabbedPaneIndex) {
        if (selectedTabbedPaneIndex < 0) {
            selectedTabbedPaneIndex = this.tabbedPane.getSelectedIndex();
        }
        if (selectedTabbedPaneIndex > -1) {
            SearchTextPane searchTextPane = this.searchTextPaneList.get(selectedTabbedPaneIndex);
            clearSearchedInfo(searchTextPane);
            setImplicitStyles(searchTextPane, false);
        }
        searchCountCheckBox.setText("0/0");
    }

    /**
     * clear searched text info and remove styles from searched text in StyledDocument.
     * this method must call after JTextPane.setText was called.
     * @param searchTextPane
     */
    private void clearSearchedInfo(SearchTextPane searchTextPane) {
        if (searchTextPane != null) {
            StyledDocument doc = searchTextPane.searchTextPane.getStyledDocument();

            SwingStyle.clearAllCharacterAttributes(doc);

            if (searchTextPane.foundTextAttrPos != null) {
                searchTextPane.foundTextAttrPos.clear();
            }
            if (searchTextPane.findplist != null) {
                searchTextPane.findplist.clear();
            }
            searchTextPane.hasGroup = false;
        }
    }

    /**
     * clear All searched text info and remove styles from searched text in StyledDocument.
     * this method must call after JTextPane.setText was called.
     */
    public void clearAllSearchedInfo() {
        for(SearchTextPane searchTextPane: searchTextPaneList) {
            LOGGER4J.debug("clearAllSearchedInfo");
            clearSearchedInfo(searchTextPane);
        }
        searchCountCheckBox.setText("0/0");
    }

    public void regexSearchActionPerformed(ActionEvent e, int selectedTabbedPaneIndex) {
        // clear attrubutes in searchTextPane
        clearTestActionPerformed(null, selectedTabbedPaneIndex);

        if (selectedTabbedPaneIndex < 0) {
            selectedTabbedPaneIndex = this.tabbedPane.getSelectedIndex();
        }
        if (selectedTabbedPaneIndex > -1) {
            SearchTextPane searchTextPane = this.searchTextPaneList.get(selectedTabbedPaneIndex);

            String regex = regexTextPane.getText();

            StyledDocument doc = searchTextPane.searchTextPane.getStyledDocument();


            if (regex == null || regex.isEmpty()) { // if you do it, Too many patterns matched.
                return;
            }

            String original = null;
            try {
                original = doc.getText(0, doc.getLength());
            } catch (BadLocationException ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }

            searchTextPane.findplist = new ArrayList<>();

            //parse Regex
            Pattern compiledregex = null;
            Matcher m = null;
            try {

                compiledregex = Pattern.compile(regex, Pattern.MULTILINE);

                m = compiledregex.matcher(original);
            } catch (Exception ex) {
                LOGGER4J.error("Exception:" + ex.getMessage(), ex);
                return;
            }


            int cpt = 0;

            int fcount = 0;
            while (m.find()) {
                fcount++;
                int spt0 = -1;
                int ept0 = -1;
                int spt = -1;
                int ept = -1;
                int gcnt = m.groupCount();
                String matchval = null;
                if (gcnt > 0) {
                    spt0 = m.start();
                    ept0 = m.end();
                    for (int n = 0; n < gcnt; n++) {
                        spt = m.start(n + 1);
                        ept = m.end(n + 1);
                        matchval = m.group(n + 1);

                    }
                    if (matchval == null) {
                        matchval = m.group();
                    }
                    if (spt0 > spt) {
                        spt0 = spt;
                    }
                    if (ept0 < ept) {
                        ept0 = ept;
                    }
                    searchTextPane.hasGroup = true;
                    // spt0--->spt<matchval>ept-->ept0
                    LOGGER4J.debug("hasGroup=true gcount=" + gcnt);
                } else {//Nothing Groups...
                    spt0 = m.start();
                    ept0 = m.end();
                    matchval = m.group();
                    searchTextPane.hasGroup = false;
                    LOGGER4J.debug("hasGroup=false");
                }
                if (spt0 >= 0 && ept0 >= 0) {

                    try {

                        // spt0--->spt<matchval>ept-->ept0

                        if (ept0 > spt0) {
                            Style style = getStyleWithText(doc, SELECTED_STYLENAME, null);
                            Style underLineStyle = getStyleWithText(doc, DEL_UNDERLINE_STYLENAME, null);
                            if (fcount == 1) {
                                underLineStyle = getStyleWithText(doc, ADD_UNDERLINE_STYLENAME, null);
                                style = getStyleWithText(doc, CURRENT_SELECTED_STYLENAME, null);
                            }
                            doc.setCharacterAttributes(spt0, ept0 - spt0, style, false);
                            doc.setCharacterAttributes(spt0, ept0 - spt0, underLineStyle, false);
                            RegexSelectedTextPos rpos = new RegexSelectedTextPos(SELECTED_STYLENAME, spt0, ept0);
                            searchTextPane.foundTextAttrPos.add(rpos);
                        }

                        if (ept > spt) {// same as hasGroup == true
                            String styleName = "";
                            if (fcount == 1) {
                                styleName = CURRENT_SELECTEDGROUP_STYLENAME;
                            } else {
                                styleName = SELECTEDGROUP_STYLENAME;
                            }
                            Style style = getStyleWithText(doc, styleName, null);
                            doc.setCharacterAttributes(spt, ept - spt, style, false);
                            RegexSelectedTextPos rpos = new RegexSelectedTextPos(styleName, spt, ept);
                            searchTextPane.foundTextAttrPos.add(rpos);
                        }

                        //int pos = OriginalText.getCaretPosition();
                        int pos = doc.getLength();
                        searchTextPane.findplist.add(ept0);
                    } catch (Exception ex) {
                        LOGGER4J.error("Exception:" + ex.getMessage(), ex);
                    }
                }
            }

            if (searchTextPane.findplist.size() > 0) {
                searchTextPane.caretIndex = 0;
                int foundCount = searchTextPane.findplist.size();
                String counterString = String.format(
                        Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.checkbox.formatfound"),
                        searchTextPane.caretIndex + 1,
                        foundCount);
                this.searchCountCheckBox.setText(counterString);
                searchTextPane.searchTextPane.setCaretPosition(searchTextPane.findplist.get(0));
                if (searchCountCheckBox.isSelected()) {
                    popupRegexTestOptionPane(searchTextPane);
                }

            } else {
                Toolkit.getDefaultToolkit().beep();
                if (searchCountCheckBox.isSelected()) {
                    JOptionPane.showMessageDialog(this,
                            Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.formatnotfound.text"),
                            Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.title.text"),
                            JOptionPane.QUESTION_MESSAGE);
                }
            }
        }
    }

    public void setImplicitStylesOnSelectedPane(boolean moveCaretToLcs, int selectedTabbedPaneIndex) {
        if (selectedTabbedPaneIndex < 0) {
            selectedTabbedPaneIndex = this.tabbedPane.getSelectedIndex();
        }
        if (selectedTabbedPaneIndex > -1) {
            SearchTextPane searchTextPane = this.searchTextPaneList.get(selectedTabbedPaneIndex);
            if (searchTextPane != null) {
                setImplicitStyles(searchTextPane, moveCaretToLcs);
            }
        }
    }

    private void setImplicitStyles(SearchTextPane searchTextPane, boolean moveCaretToLcs){
        long startTime = 0;
        searchTextPane.outBoundOfLcsList.clear();
        searchTextPane.outBoundOfLcsIndex = -1;
        if (LAPSETIME != null) {
            startTime = System.currentTimeMillis();
        }
        StyledDocument doc = searchTextPane.searchTextPane.getStyledDocument();
        if (searchTextPane.charIndexOfLcs != null && !searchTextPane.charIndexOfLcs.isEmpty()) {
            Style baseLcsStyle = getStyleWithText(doc, MARK_LCS_STYLENAME, null);
            Style outBoundStyle = getStyleWithText(doc, ADD_BOLD_STYLENAME, null);
            if (baseLcsStyle != null) {
                int outBoundStart = 0;
                for (StartEndPosition position : searchTextPane.charIndexOfLcs) {
                    if (outBoundStart < position.start) {
                        doc.setCharacterAttributes(outBoundStart, position.start - outBoundStart, outBoundStyle, true);
                        if (moveCaretToLcs) {
                            searchTextPane.searchTextPane.setCaretPosition(outBoundStart);
                            moveCaretToLcs = false;
                            searchTextPane.outBoundOfLcsIndex = 0;
                        }
                        searchTextPane.outBoundOfLcsList.add(outBoundStart);
                    }
                    Style lcsStyle = baseLcsStyle;
                    String optionLcsStyleName = position.styleName;
                    if (optionLcsStyleName != null) {
                        try {
                            String optionText = doc.getText(position.start, position.end - position.start);
                            lcsStyle = getStyleWithText(doc, optionLcsStyleName, optionText);
                        } catch (Exception ex) {
                            LOGGER4J.error(ex.getMessage(), ex);
                            lcsStyle = null;
                        }
                        if (lcsStyle == null) {
                            lcsStyle = baseLcsStyle;
                            String defaultName = SwingStyle.getDefaultStyleName(doc);
                            LOGGER4J.debug("default=" + defaultName + " position.styleName is null but optionLcsStyleName=" + optionLcsStyleName);
                        }
                    }
                    doc.setCharacterAttributes(position.start, position.end - position.start, lcsStyle, true);
                    LOGGER4J.debug("LCS start=" + position.start + " end=" + position.end);
                    outBoundStart = position.end;
                }
                int docLength = doc.getLength();
                if (outBoundStart < docLength) {
                    doc.setCharacterAttributes(outBoundStart, docLength - outBoundStart, outBoundStyle, true);
                    if (moveCaretToLcs) {
                        searchTextPane.searchTextPane.setCaretPosition(outBoundStart);
                        moveCaretToLcs = false;
                        searchTextPane.outBoundOfLcsIndex = 0;
                    }
                    searchTextPane.outBoundOfLcsList.add(outBoundStart);
                }

            }
        }
        if (moveCaretToLcs && !searchTextPane.outBoundOfLcsList.isEmpty() && searchTextPane.findplist.isEmpty()) {
            String counterString = String.format(
                    Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.checkbox.formatfound"),
                    searchTextPane.outBoundOfLcsIndex+1,
                    searchTextPane.outBoundOfLcsList.size());
            this.searchCountCheckBox.setText(counterString);
        }
        if (LAPSETIME != null) {
            long endTime = System.currentTimeMillis();
            LOGGER4J.log(LAPSETIME, "setImplicitStyles lapse(sec)=" + Math.round((float)(endTime - startTime)/100)/(float)10);
        }
    }
    private void popupRegexTestOptionPane(SearchTextPane searchTextPane) {
        int foundCount = searchTextPane.findplist.size();
        String counterString = String.format(
                Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.formatfound.text"),
                searchTextPane.caretIndex + 1,
                foundCount);

        RegexTestOptionPane.RegexTestOptions options = new RegexTestOptionPane.RegexTestOptions(counterString, searchTextPane);
        disposeChild();
        optionPane = new RegexTestOptionPane(
                this,
                Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.title.text"),
                ModalityType.DOCUMENT_MODAL, options, GridBagConstraints.NONE);
        optionPane.setVisible(true);
    }

    protected void nextBtnActionPerformed() {
        int selectedTabbedPaneIndex = this.tabbedPane.getSelectedIndex();
        if (selectedTabbedPaneIndex > -1) {
            SearchTextPane searchTextPane = this.searchTextPaneList.get(selectedTabbedPaneIndex);
            if (searchTextPane.findplist.size() > 0) {
                int foundCount = searchTextPane.findplist.size();
                int caretIndex = searchTextPane.caretIndex;
                StyledDocument doc = searchTextPane.searchTextPane.getStyledDocument();
                SimpleAttributeSet attr = new SimpleAttributeSet();
                // reset coloring attribute current caret position.
                int offset = searchTextPane.hasGroup ? 2 : 1;
                for (int i = caretIndex * offset; i < caretIndex * offset + offset; i++) {
                    RegexTestDialog.RegexSelectedTextPos regexSelectedTextPos = searchTextPane.foundTextAttrPos.get(i);
                    int spt = regexSelectedTextPos.getStartPos();
                    int ept = regexSelectedTextPos.getEndPos();
                    String styleName = regexSelectedTextPos.getStyleName();
                    if (i == caretIndex * offset) {// spt0-->(spt-group->ept)-->ept0
                        styleName = SELECTED_STYLENAME;// setting color to outside group
                        Style delUnderLineStyle = getStyleWithText(doc, DEL_UNDERLINE_STYLENAME, null);
                        doc.setCharacterAttributes(spt, ept - spt, delUnderLineStyle, false);
                    } else {
                        styleName = SELECTEDGROUP_STYLENAME;// setting color to inside group
                    }
                    Style style = getStyleWithText(doc, styleName, null);
                    doc.setCharacterAttributes(spt, ept - spt, style, false);
                }

                int nextCaretIndex = caretIndex + 1;
                if (nextCaretIndex >= searchTextPane.findplist.size()) {
                    nextCaretIndex = 0;
                }

                for (int i = nextCaretIndex * offset; i < nextCaretIndex * offset + offset; i++) {
                    RegexTestDialog.RegexSelectedTextPos regexSelectedTextPos = searchTextPane.foundTextAttrPos.get(i);
                    int spt = regexSelectedTextPos.getStartPos();
                    int ept = regexSelectedTextPos.getEndPos();
                    String styleName = regexSelectedTextPos.getStyleName();
                    if (i == nextCaretIndex * offset) {// spt0-->(spt-group->ept)-->ept0
                        styleName = CURRENT_SELECTED_STYLENAME;// setting color to outside group
                        Style addUnderLineStyle = getStyleWithText(doc, ADD_UNDERLINE_STYLENAME, null);
                        doc.setCharacterAttributes(spt, ept - spt, addUnderLineStyle, false);
                    } else {
                        styleName = CURRENT_SELECTEDGROUP_STYLENAME;// setting color to inside group
                    }
                    Style style = getStyleWithText(doc, styleName, null);
                    doc.setCharacterAttributes(spt, ept - spt, style, false);
                }
                String counterString = String.format(
                        Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.checkbox.formatfound"),
                        nextCaretIndex+1,
                        foundCount);
                this.searchCountCheckBox.setText(counterString);
                searchTextPane.searchTextPane.setCaretPosition(searchTextPane.findplist.get(nextCaretIndex));
                searchTextPane.caretIndex = nextCaretIndex;
                if(searchCountCheckBox.isSelected() && optionPane == null) {
                    popupRegexTestOptionPane(searchTextPane);
                }
            } else {
                nextBtnActionDefault(searchTextPane);
            }
        }
    }

    protected void prevBtnActionPerformed() {
        int selectedTabbedPaneIndex = this.tabbedPane.getSelectedIndex();
        if (selectedTabbedPaneIndex > -1) {
            SearchTextPane searchTextPane = this.searchTextPaneList.get(selectedTabbedPaneIndex);
            if (searchTextPane.findplist.size() > 0) {
                int foundCount = searchTextPane.findplist.size();
                int caretIndex = searchTextPane.caretIndex;
                StyledDocument doc = searchTextPane.searchTextPane.getStyledDocument();
                SimpleAttributeSet attr = new SimpleAttributeSet();
                // reset coloring attribute current caret position.
                int offset = searchTextPane.hasGroup ? 2 : 1;
                for (int i = caretIndex * offset; i < caretIndex * offset + offset; i++) {
                    RegexTestDialog.RegexSelectedTextPos regexSelectedTextPos = searchTextPane.foundTextAttrPos.get(i);
                    int spt = regexSelectedTextPos.getStartPos();
                    int ept = regexSelectedTextPos.getEndPos();
                    String styleName = regexSelectedTextPos.getStyleName();
                    if (i == caretIndex * offset) {// spt0-->(spt-group->ept)-->ept0
                        styleName = SELECTED_STYLENAME;// setting color to outside group
                        Style delUnderLineStyle = getStyleWithText(doc, DEL_UNDERLINE_STYLENAME, null);
                        doc.setCharacterAttributes(spt, ept - spt, delUnderLineStyle, false);
                    } else {
                        styleName = SELECTEDGROUP_STYLENAME;// setting color to inside group
                    }
                    Style style = getStyleWithText(doc, styleName, null);
                    doc.setCharacterAttributes(spt, ept - spt, style, false);
                }

                int nextCaretIndex = caretIndex - 1;
                if (nextCaretIndex < 0) {
                    nextCaretIndex = foundCount - 1;
                }

                for (int i = nextCaretIndex * offset; i < nextCaretIndex * offset + offset; i++) {
                    RegexTestDialog.RegexSelectedTextPos regexSelectedTextPos = searchTextPane.foundTextAttrPos.get(i);
                    int spt = regexSelectedTextPos.getStartPos();
                    int ept = regexSelectedTextPos.getEndPos();
                    String styleName = regexSelectedTextPos.getStyleName();
                    if (i == nextCaretIndex * offset) {// spt0-->(spt-group->ept)-->ept0
                        styleName = CURRENT_SELECTED_STYLENAME;// setting color to outside group
                        Style addUnderLineStyle = getStyleWithText(doc, ADD_UNDERLINE_STYLENAME, null);
                        doc.setCharacterAttributes(spt, ept - spt, addUnderLineStyle, false);
                    } else {
                        styleName = CURRENT_SELECTEDGROUP_STYLENAME;// setting color to inside group
                    }
                    Style style = getStyleWithText(doc, styleName, null);
                    doc.setCharacterAttributes(spt, ept - spt, style, false);
                }
                String counterString = String.format(
                        Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.checkbox.formatfound"),
                        nextCaretIndex+1,
                        foundCount);
                this.searchCountCheckBox.setText(counterString);
                searchTextPane.searchTextPane.setCaretPosition(searchTextPane.findplist.get(nextCaretIndex));
                searchTextPane.caretIndex = nextCaretIndex;
                if(searchCountCheckBox.isSelected() && optionPane == null) {
                    popupRegexTestOptionPane(searchTextPane);
                }
            } else {
                prevBtnActionDefault(searchTextPane);
            }
        }
    }

    private void nextBtnActionDefault(SearchTextPane selectedSearchTextPane) {
        if(!selectedSearchTextPane.outBoundOfLcsList.isEmpty()) {
            int maxLcsList = selectedSearchTextPane.outBoundOfLcsList.size();
            if ( ++selectedSearchTextPane.outBoundOfLcsIndex >= maxLcsList) {
                selectedSearchTextPane.outBoundOfLcsIndex = 0;
            }
            int oubBoundStart = selectedSearchTextPane.outBoundOfLcsList.get(selectedSearchTextPane.outBoundOfLcsIndex);
            selectedSearchTextPane.searchTextPane.setCaretPosition(oubBoundStart);

            String counterString = String.format(
                    Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.checkbox.formatfound"),
                    selectedSearchTextPane.outBoundOfLcsIndex+1,
                    selectedSearchTextPane.outBoundOfLcsList.size());
            this.searchCountCheckBox.setText(counterString);

        }
    }

    private void prevBtnActionDefault(SearchTextPane selectedSearchTextPane) {
        if (!selectedSearchTextPane.outBoundOfLcsList.isEmpty()) {
            int maxLcsList = selectedSearchTextPane.outBoundOfLcsList.size();
            if (--selectedSearchTextPane.outBoundOfLcsIndex < 0) {
                selectedSearchTextPane.outBoundOfLcsIndex = maxLcsList - 1;
            }
            int oubBoundStart = selectedSearchTextPane.outBoundOfLcsList.get(selectedSearchTextPane.outBoundOfLcsIndex);
            selectedSearchTextPane.searchTextPane.setCaretPosition(oubBoundStart);
            String counterString = String.format(
                    Constant.messages.getString("customactivescan.testsqlinjection.regexsearch.checkbox.formatfound"),
                    selectedSearchTextPane.outBoundOfLcsIndex+1,
                    selectedSearchTextPane.outBoundOfLcsList.size());
            this.searchCountCheckBox.setText(counterString);
        }
    }

    public void disposeChild() {
        if (this.optionPane != null) {
            this.optionPane.dispose();
            this.optionPane = null;
        }
    }
    public void setRegexTextField(JTextField targetTextField) {
        this.targetTextField = null;
        if (this.regexTextPane != null) {
            if(targetTextField != null) {
                this.targetTextField = targetTextField;
                this.regexTextPane.setText(targetTextField.getText());
            }
        }
    }

    public void selectTabbedPane(int index) {
        this.tabbedPane.setSelectedIndex(index);
    }


    /**
     * move scollbars to left/top on each scrollPane
     */
    public void resetScrollBarToLeftTop() {
        int tabCount = this.tabbedPane.getTabCount();
        for(int i=0; i < tabCount; i++) {
            JScrollPane scrollPane = (JScrollPane) this.tabbedPane.getComponentAt(i);
            JScrollBar verticalBar = scrollPane.getVerticalScrollBar();
            JScrollBar horizontalBar = scrollPane.getHorizontalScrollBar();
            verticalBar.setValue(verticalBar.getMinimum());
            horizontalBar.setValue(horizontalBar.getMinimum());
        }
    }

    public void updateContentsWithPaneContents(PaneContents paneContents) {

        int currentPaneCount = this.tabbedPane.getTabCount();
        int updatePaneCount = paneContents.paneTitleAndContentList.size();

        int paneIndex = 0;
        for(PaneTitleAndContent titleAndContent: paneContents.paneTitleAndContentList) {
            if (paneIndex >= currentPaneCount) {//create
                SearchTextPane searchTextPane = createSearchTextScroller(titleAndContent, tabbedPane);
                searchTextPaneList.add(searchTextPane);
                paneIndex++;
            } else {//update
                SearchTextPane searchTextPane = searchTextPaneList.get(paneIndex++);
                StyledDocument doc = searchTextPane.searchTextPane.getStyledDocument();
                try {
                    doc.remove(0, doc.getLength());
                } catch (Exception ex) {
                    LOGGER4J.error(ex.getMessage(), ex);
                }

                searchTextPane.updateCharIndexOfLcs(titleAndContent.charIndexesOfContent);
                if (titleAndContent.content.length() < MAX_CONTENT_WRAP_LENGTH) {
                    // large size of wrapping Text is heavy load for JTextPane.
                    // Therefore, it is used when the size is less than MAX_CONTENT_WRAP_LENGTH.
                    if (searchTextPane.wrapEditorKit == null) {
                        searchTextPane.wrapEditorKit = new TextPaneWrapEditorKit(SwingStyleProvider.createSwingStyle().createStyledDocument());
                        searchTextPane.searchTextPane.setEditorKit(searchTextPane.wrapEditorKit);
                    }
                    searchTextPane.searchScroller.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
                    searchTextPane.wrapEditorKit.setIsWrapText(true);
                } else {
                    searchTextPane.searchScroller.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                    if (searchTextPane.wrapEditorKit != null) {
                        searchTextPane.wrapEditorKit.setIsWrapText(false);
                    }
                }

                insertStringCR(doc, 0, titleAndContent.content);
                searchTextPane.searchTextPane.setSelectionStart(0);
                searchTextPane.searchTextPane.setSelectionEnd(0);
                searchTextPane.searchTextPane.setCaretPosition(0);
            }
        }
        currentPaneCount = this.tabbedPane.getTabCount();
        while(paneIndex < currentPaneCount) {
            this.tabbedPane.remove(paneIndex);
            this.searchTextPaneList.remove(paneIndex++);
        }
        resetScrollBarToLeftTop();
    }


    private void insertStringCR(StyledDocument doc, int insertStartPosition, String text) {
        long startTime = 0;
        if (LAPSETIME != null) {
            startTime = System.currentTimeMillis();
        }
        if (text == null || text.length() < 1) return;
        int cpos = 0;
        int npos = -1;
        int totallen = text.length();
        while ((npos = text.indexOf("\r", cpos)) != -1) {
            try {
                doc.insertString(insertStartPosition, text.substring(cpos, npos), null);
                cpos = npos;
                insertStartPosition = doc.getLength();
                doc.insertString(insertStartPosition, text.substring(cpos, cpos + 1), null);
                doc.setCharacterAttributes(insertStartPosition, 1, getCRstyle(doc), true);
                cpos++;
                insertStartPosition = doc.getLength();
            } catch (BadLocationException ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
        if (cpos < totallen) {
            try {
                doc.insertString(insertStartPosition, text.substring(cpos, totallen), null);
            } catch (BadLocationException ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
        if (LAPSETIME != null) {
            long endTime = System.currentTimeMillis();
            LOGGER4J.log(LAPSETIME, "insertStringCR lapse(sec)=" + Math.round((float)(endTime - startTime)/100)/(float)10);
        }
    }

    private Style getCRstyle(StyledDocument doc) {
        Style CRstyle = doc.getStyle(CRIMAGE_STYLENAME);
        // component must always create per call setComponent.
        JLabel crlabel = new JLabel("CR");
        crlabel.setOpaque(true);
        LineBorder border = new LineBorder(Color.GREEN, 1, true);
        Font labelFont = crlabel.getFont();
        crlabel.setFont(new Font(labelFont.getName(), Font.PLAIN, 8));
        crlabel.setBorder(border);
        float avf = crlabel.getAlignmentY();
        // LOGGER4J.debug("Y=" + avf);
        avf = (float) 0.8;
        crlabel.setAlignmentY(avf);
        // StyleConstants.setAlignment(defstyle, StyleConstants.ALIGN_CENTER);
        StyleConstants.setComponent(CRstyle, crlabel);
        return CRstyle;
    }

    private Style getAlertTitleStyle(StyledDocument doc, String text) {
        return getFixedLabelstyle(doc, this.fixedStyleWidthMax, text);
    }
    private Style getFixedLabelstyle(StyledDocument doc, int width, String text) {
        Style fixedLabelStyle = doc.getStyle(FIXED_LABEL_STYLENAME);
        // component must always create per call setComponent.
        JLabel fixedLabel = new JLabel(text);
        //fixedLabel.setOpaque(true);
        Dimension originalDim = fixedLabel.getPreferredSize();
        LOGGER4J.debug("dim w=" + originalDim.getWidth() + " height=" + originalDim.getHeight());
        fixedLabel.setPreferredSize(new Dimension(width, (int)originalDim.getHeight()));
        fixedLabel.setMaximumSize(new Dimension(width, (int)originalDim.getHeight()));
        LineBorder border = new LineBorder(Color.GREEN, 1, true);
        //Font labelFont = crlabel.getFont();
        //crlabel.setFont(new Font(labelFont.getName(), Font.PLAIN, 8));
        //fixedLabel.setBorder(border);
        float avf = fixedLabel.getAlignmentY();
        // LOGGER4J.debug("Y=" + avf);
        avf = (float) 0.8;
        fixedLabel.setAlignmentY(avf);
        StyleConstants.setAlignment(fixedLabelStyle, StyleConstants.ALIGN_CENTER);
        StyleConstants.setComponent(fixedLabelStyle, fixedLabel);
        return fixedLabelStyle;
    }

    private Style getSampleButton(StyledDocument doc, String text) {
        Style CRstyle = doc.getStyle(FIXED_LABEL_STYLENAME);
        StyleConstants.setAlignment(CRstyle, StyleConstants.ALIGN_CENTER);

        JButton button = new JButton();
         button.setText(text);

        button.setCursor(Cursor.getDefaultCursor());
        button.setMargin(new Insets(0,0,0,0));
        StyleConstants.setComponent(CRstyle, button);
        return CRstyle;
    }
}
