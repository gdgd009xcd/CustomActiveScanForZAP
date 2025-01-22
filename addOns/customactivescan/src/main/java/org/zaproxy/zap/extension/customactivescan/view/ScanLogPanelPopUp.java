package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.messagecontainer.http.DefaultSingleHttpMessageContainer;

import javax.swing.*;
import java.awt.*;

public class ScanLogPanelPopUp extends JPopupMenu {

    private static final long serialVersionUID = 1L;
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    final private ScanLogPanel scanLogPanel;
    final private JViewport scanLogViewPort;

    ScanLogPanelPopUp(JScrollPane scanLogScroller, ScanLogPanel scanLogPanel) {
        this.scanLogPanel = scanLogPanel;
        this.scanLogViewPort = scanLogScroller.getViewport();
    }

    @Override
    public void show(Component invoker, int x, int y) {

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
            // fix popup is showed in outer area of scanLogViewPort y ->  y -viewPoint.y
            // Don't get the instance of org.parosproxy.paros.view.MainPopupMenu from View.getSingleton().getPopupMenu() directly.
            // Because it is not a pure singleton instance. if you get the instance from View.getSingleton().getPopupMenu() and reuse it,
            // you may encouter strange behavior that the popup menu enlarge its size each time when it is shown.
            View.getSingleton().getPopupMenu().show(messageContainer, x, y - viewPoint.y);
            LOGGER4J.debug("x=" + x + " y=" + (y - viewPoint.y));
        } else {
            LOGGER4J.debug("getSelectedMessage is NULL");
        }
    }
}
