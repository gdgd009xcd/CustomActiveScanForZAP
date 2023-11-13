package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import java.awt.event.MouseEvent;

@SuppressWarnings("serial")
public class TableHeaderToolTips extends JTableHeader {
    String[] toolTipStrings;
    public TableHeaderToolTips(TableColumnModel model, String[] toolTipStrings) {
        super(model);
        this.toolTipStrings = toolTipStrings;
    }
    @Override
    public String getToolTipText(MouseEvent e) {
        int col = columnAtPoint(e.getPoint());
        int modelCol = getTable().convertColumnIndexToModel(col);
        String retStr;
        try {
            retStr = toolTipStrings[modelCol];
        } catch (NullPointerException ex) {
            retStr = "";
        } catch (ArrayIndexOutOfBoundsException ex) {
            retStr = "";
        }
        if (retStr.length() < 1) {
            retStr = super.getToolTipText(e);
        }
        return retStr;
    }
}
