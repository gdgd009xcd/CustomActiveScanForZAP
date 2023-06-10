package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class JTableRowSelector extends MouseAdapter {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private JTable table;

    JTableRowSelector(JTable table) {
        this.table = table;
    }

    @Override
    public void mousePressed(MouseEvent event) {
        Point point = event.getPoint();
        int currentRow = table.rowAtPoint(point);
        if (currentRow != -1) {
            LOGGER4J.debug("JTableRowSelector currentRow:" + currentRow);
            table.setRowSelectionInterval(currentRow, currentRow);
        }
    }
}
