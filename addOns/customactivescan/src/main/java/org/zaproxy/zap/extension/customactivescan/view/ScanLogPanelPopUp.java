package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.view.MainPopupMenu;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.messagecontainer.http.DefaultSingleHttpMessageContainer;

import javax.swing.*;
import javax.swing.text.Position;
import java.awt.*;

public class ScanLogPanelPopUp extends JPopupMenu {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private MainPopupMenu mainPopupMenu;
    private ScanLogPanel scanLogPanel;
    private JViewport scanLogViewPort = null;
    ScanLogPanelPopUp(JScrollPane scanLogScroller, ScanLogPanel scanLogPanel) {
        this.scanLogPanel = scanLogPanel;
        this.mainPopupMenu = View.getSingleton().getPopupMenu();
        this.scanLogViewPort = scanLogScroller.getViewport();
    }
        private static final long serialVersionUID = 1L;


    @Override
    public JMenuItem add(JMenuItem item) {
        return this.mainPopupMenu.add(item);
    }
    @Override
    public void show(Component invoker, int x, int y) {
        /**
        if (!httpPanelTextArea.isFocusOwner()) {
            httpPanelTextArea.requestFocusInWindow();
        }

        if (httpPanelTextArea.getMessage() instanceof HttpMessage) {
            SingleHttpMessageContainer messageContainer =
                    new DefaultSingleHttpMessageContainer(
                            messageContainerName,
                            httpPanelTextArea,
                            (HttpMessage) httpPanelTextArea.getMessage());
            View.getSingleton().getPopupMenu().show(messageContainer, x, y);
        } else {
            View.getSingleton().getPopupMenu().show(httpPanelTextArea, x, y);
        }
         **/
        LOGGER4J.debug("scanLogPane is " + (scanLogPanel==null ? "null" : "valid"));
        if (scanLogPanel.getSelectedMessage() != null) {

            //It's very difficult to control popup standard menu items in zaproxy.
            // I think each invoker components might provide performAction,
            // Therefore, it is better if the popup menu item's performAction can be overridden by the caller.
            // action in standard popup menu item itself does not provide performing action of invoker component
            DefaultSingleHttpMessageContainer messageContainer =
                    new DefaultSingleHttpMessageContainer(
                            "ScanLogPopUpContainer",
                            scanLogPanel,
                            scanLogPanel.getSelectedMessage());
            Point viewPoint = this.scanLogViewPort.getViewPosition();
            // fix popup is showed in outer area of scanLogViewPort
            this.mainPopupMenu.show(messageContainer, x, y - viewPoint.y);

            LOGGER4J.debug("x=" + x + " y=" + y);
        } else {
            LOGGER4J.debug("getSelectedMessage is NULL");
        }

    }
}
