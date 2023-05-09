package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import java.awt.*;

@SuppressWarnings("serial")
public abstract class GridBagJDialog extends JDialog {

    /**
     * create basic dialog<br>
     *
     * <pre>
     *  |------------------------------------------------|
     *  |                                                |
     *  |              mainPanelContent                  |
     *  |                                                |
     *  | -----------------------------------------------|
     *  | | OK |                              |  CANCEL ||
     *  |________________________________________________|
     * </pre>
     */

    /**
     *
     * @param owner  You may set owner parameter by<BR> SwingUtilities.windowForComponent(yourComponent)<P></P><P></P>
     * @param title  Dialog title String<P></P><P></P>
     * @param modalityType  specifies whether dialog blocks input to other windows when shown.<P></P>
     *                      <UL>
     *                       ModalityType.DOCUMENT_MODAL : A DOCUMENT_MODAL blocks all top-level windows from the same JFrame which launched this dialog except those from its own child hierarchy.<P></P>
     *                       ModalityType.APPLICATION_MODAL : An APPLICATION_MODAL blocks all top-level windows from the same Java application except those from its own child hierarchy.<P></P>
     *                       ModalityType.MODELESS: MODELESS dialog doesn't block any top-level windows.<P></P>
     *                       ModalityType.TOOLKIT_MODAL : This is the same as APPLICATION_MODAL. because almost all applications do not share toolkits between applications
     *                      </UL><P></P><P></P>
     *
     * @param fill specifies whether resize mainPanelContent vertically/horizontally or both<P></P>
     *             <UL>
     *              GridBagConstraints.HORIZONTAL: mainPanelContent size is expanded horizontally.<P></P>
     *              GridBagConstraints.VERTICAL: mainPanelContent size is expanded vertically.<P></P>
     *              GridBagConstraints.BOTH: mainPanelContent size is expanded both horizontal and vertical
     *             </UL><P></P>
     *
     */
    public GridBagJDialog(Window owner, String title, ModalityType modalityType, int fill) {
        super(owner, title, modalityType);
        init(fill, -1, createMainPanelContent(null));
    }

    public GridBagJDialog(Component mainPanel, String title, ModalityType modalityType, int fill) {
        super(SwingUtilities.windowForComponent(mainPanel), title, modalityType);
        init(fill, -1, createMainPanelContent(mainPanel));
    }

    /**
     *
     * @param owner  You may set owner parameter by<BR> SwingUtilities.windowForComponent(yourComponent)<P></P><P></P>
     * @param title  Dialog title String<P></P><P></P>
     * @param modalityType  specifies whether dialog blocks input to other windows when shown.<P></P>
     *                      <UL>
     *                        ModalityType.DOCUMENT_MODAL : A DOCUMENT_MODAL blocks all top-level windows from the same JFrame which launched this dialog except those from its own child hierarchy.<P></P>
     *                        ModalityType.APPLICATION_MODAL : An APPLICATION_MODAL blocks all top-level windows from the same Java application except those from its own child hierarchy.<P></P>
     *                        ModalityType.MODELESS: MODELESS dialog doesn't block any top-level windows.<P></P>
     *                        ModalityType.TOOLKIT_MODAL : This is the same as APPLICATION_MODAL. because almost all applications do not share toolkits between applications
     *                      </UL><P></P><P></P>
     *
     * @param fill specifies whether resize mainPanelContent vertically/horizontally or both<P></P>
     *             <UL>
     *              GridBagConstraints.HORIZONTAL: mainPanelContent size is expanded horizontally.<P></P>
     *              GridBagConstraints.VERTICAL: mainPanelContent size is expanded vertically.<P></P>
     *              GridBagConstraints.BOTH: mainPanelContent size is expanded both horizontal and vertical
     *             </UL><P></P><P></P>

     * @param anchor This field is used when the component is smaller than its display area.<P></P>
     *               <UL>
     *                GridBagConstraints.CENTER/NORTH/WEST/SOUTH/EAST<BR>
     *                GridBagConstraints.NORTHEAST/NORTHWEST<BR>
     *                GridBagConstraints.SOUTHEAST/SOUTHWEST
     *               </UL>
     */
    public GridBagJDialog(Window owner, String title, ModalityType modalityType, int fill, int anchor) {
        super(owner, title, modalityType);
        init(fill, anchor, createMainPanelContent(null));
    }

    /**
     * create this dialog contents<br>
     * you must implement createMainPanelContent method and pass this method's mainPanelContent.
     * Caution: you MUST NOT initialize member parameter that are set in createMainPanelContent method.
     * because createMainPanelContent is called before member parameter initialization process.
     *
     * class yourDialog extends GridBagJDialog {
     *     private JTextPane regexTextPane;// Ok. this parameter value is set in createMainPanelContent method.
     *     private JTextPane regexTextPane = null;// AAUGH. NG. this value will be null after createMainPanelContent is called
     *     private JPanel mainPanel;
     *
     *     public yourDialog(Component mainPanelComponent, String title, ModalityType modalityType) {
     *         super(mainPanelComponent, title, modalityType, GridBagConstraints.BOTH);
     *     }
     *
     *     @Override
     *     protected Component createMainPanelContent(Component mainPanelComponent) {
     *         this.mainPanel = (JPanel) mainPanelComponent;
     *         ...
     *         this.regexTextPane = new JTextPane();// regexTextPane is set BEFORE initialization in class parameter definition.
     *         ...
     *     }
     * }
     */
    protected void init(int fill, int anchor, Component mainPanelContent) {
        GridBagLayout layout = new GridBagLayout();
        JPanel panel = new JPanel();
        panel.setLayout(layout);

        GridBagConstraints gbc = new GridBagConstraints();

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());
        mainPanel.add(mainPanelContent, BorderLayout.CENTER);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 4;
        gbc.gridheight = 2;
        gbc.fill = fill;
        gbc.weightx = 1.0d;
        gbc.weighty = 0.8d;// 0 means do not resize height mainpanel
        gbc.insets = new Insets(5, 5, 5, 5);
        if (anchor != -1) {
            gbc.anchor = anchor;
        }
        layout.setConstraints(mainPanel, gbc);
        panel.add(mainPanel);

        JSeparator separator = new JSeparator();

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 4;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0d;
        gbc.weighty = 0d;
        gbc.anchor = GridBagConstraints.CENTER;// restore default value.
        gbc.insets = new Insets(0, 5, 0, 5);

        layout.setConstraints(separator, gbc);
        panel.add(separator);

        JButton okBtn = new JButton("OK");

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.25d;
        gbc.weighty = 0.1d;
        gbc.insets = new Insets(5, 5, 5, 5);
        layout.setConstraints(okBtn, gbc);
        panel.add(okBtn);

        okBtn.addActionListener(
                e -> {
                    okBtnActionPerformed();
                });

        JButton cancelBtn = new JButton("CANCEL");

        gbc.gridx = 3;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.25d;
        gbc.weighty = 0.1d;
        gbc.insets = new Insets(5, 5, 5, 5);
        layout.setConstraints(cancelBtn, gbc);
        panel.add(cancelBtn);

        cancelBtn.addActionListener(
                e -> {
                    cancelBtnActionPerformed();
                });

        getContentPane().add(panel, "Center");
        setResizable(true);
        pack();
        // set dialog position to centre of Owner window.
        setLocationRelativeTo(getOwner());
    }

    /**
     * implement mainPanelContent component<br>
     *
     * @param mainPanel - specify mainPanel component from which this dialog opens
     * @return
     */

    protected abstract Component createMainPanelContent(Component mainPanel);

    /**
     * OK button Action<br>
     * You must specify dispose() method at last line of this method.
     */
    protected abstract void okBtnActionPerformed();

    /**
     * CANCEL button Action<br>
     * You must specify dispose() method at last line of this method.
     */
    protected abstract void cancelBtnActionPerformed();
}
