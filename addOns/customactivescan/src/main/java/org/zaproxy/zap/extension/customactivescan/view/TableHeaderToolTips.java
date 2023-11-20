package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import java.awt.event.MouseEvent;
import java.util.logging.Logger;

@SuppressWarnings("serial")
public class TableHeaderToolTips extends JTableHeader {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    String[] toolTipStrings;
    public TableHeaderToolTips(TableColumnModel model, String[] toolTipStrings) {
        super(model);
        this.toolTipStrings = toolTipStrings;
    }
    @Override
    public String getToolTipText(MouseEvent e) {
        java.awt.Point p = e.getPoint();
        int index = columnModel.getColumnIndexAtX(p.x);
        int realIndex =
                columnModel.getColumn(index).getModelIndex();
        LOGGER4J.debug("index=" + index + " realIndex=" + realIndex);
        int col = columnAtPoint(e.getPoint());
        int modelCol = getTable().convertColumnIndexToModel(col);
        LOGGER4J.debug("col=" + col  + " modelCol=" + modelCol);
        String retStr = "";
        try {
            retStr = toolTipStrings[modelCol];
        } catch (NullPointerException ex) {
            retStr = "";
        } catch (ArrayIndexOutOfBoundsException ex) {
            retStr = "";
        }
        /**
        if (retStr.length() < 1) {
            retStr = super.getToolTipText(e);
        }
         **/
        return retStr;
    }
}
