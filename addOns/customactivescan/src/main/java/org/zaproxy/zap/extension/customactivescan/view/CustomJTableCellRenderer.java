package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
@SuppressWarnings("serial")
public class CustomJTableCellRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component compo = super.getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column);
        if (compo instanceof JLabel) {
            ((JLabel) compo).setHorizontalAlignment(SwingConstants.CENTER);
        }
        return compo;
    }
}
