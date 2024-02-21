package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.customactivescan.model.ModifyType;

import static org.zaproxy.zap.extension.customactivescan.view.MyFontUtils.getScale;

@SuppressWarnings("serial")
public class CustomJTable extends JTable implements CellEditorListener {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    DefaultTableModel tableModel = null;
    CustomScanMainPanel mainPanel;
    JPopupMenu popupTableMenu;

    private static final int[] columnSizes = {
            5,
            15,
            15,
            15,
            15,
            17,
            18
    };
    private static final Object[] addRowData = new Object[] {
            ModifyType.Add,
            ""
    };

    private static final String[] headerToolTips = {
            Constant.messages.getString("customactivescan.CustomJTable.headerColumnNames.col0.tooltip.text"),
            Constant.messages.getString("customactivescan.CustomJTable.headerColumnNames.col1.tooltip.text"),
            Constant.messages.getString("customactivescan.CustomJTable.headerColumnNames.col2.tooltip.text"),
            Constant.messages.getString("customactivescan.CustomJTable.headerColumnNames.col3.tooltip.text"),
            Constant.messages.getString("customactivescan.CustomJTable.headerColumnNames.col4.tooltip.text"),
            Constant.messages.getString("customactivescan.CustomJTable.headerColumnNames.col5.tooltip.text"),
            Constant.messages.getString("customactivescan.CustomJTable.headerColumnNames.col6.tooltip.text")
    };

    public CustomJTable(CustomScanMainPanel mainPanel, JScrollPane scroller, DefaultTableModel model) {
        super(model);
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);// you can select only 1 row at a time.
        this.tableModel = model;
        this.mainPanel = mainPanel;

        scroller.setViewportView(this);

        TableColumn column0 = this.getColumnModel().getColumn(0);
        column0.setCellEditor(new ComboBoxCellEditor());
        column0.setCellRenderer(new CustomJTableCellRenderer());
        TableHeaderToolTips tableHeaderToolTips =  new TableHeaderToolTips(
                this.getColumnModel(),
                headerToolTips);
        this.setTableHeader(tableHeaderToolTips);



        for(int colIndex = 0; colIndex < this.getColumnModel().getColumnCount(); colIndex++) {
            TableColumn column =  this.getColumnModel().getColumn(colIndex);
            float width = (float) columnSizes[colIndex]/100 * 400;
            int widthInteger = Math.round(width);
            column.setPreferredWidth(widthInteger);
        }

        // popup menu
        this.popupTableMenu = new JPopupMenu();
        JMenuItem insertTableRow = new JMenuItem("Insert");
        insertTableRow.addActionListener(l ->{
            int selectedRow = this.getSelectedRow();
            if (selectedRow != -1) {

                this.tableModel.insertRow(selectedRow, addRowData);
            }
        });
        this.popupTableMenu.add(insertTableRow);

        JMenuItem addTableRow = new JMenuItem("Add");
        addTableRow.addActionListener(l ->{
            this.tableModel.addRow(addRowData);
        });
        this.popupTableMenu.add(addTableRow);

        JMenuItem delTableRow = new JMenuItem("Delete");
        delTableRow.addActionListener(l ->{
            int selectedRow = this.getSelectedRow();
            if (selectedRow != -1) {
                if (isEditing()) { // if there is on focus in ComboBox, We must call editingStopped before remove it.
                    // Because after calling remove row, editingStopped will be called at deleted row,col position and exception will be raised.
                    getCellEditor().stopCellEditing();
                }
                this.tableModel.removeRow(selectedRow);
                this.mainPanel.updateModelWithJTableModel(this.tableModel);// update CustomScanDataModel with JTable's Data
            }
        });
        this.popupTableMenu.add(delTableRow);

        JMenuItem upTableRow = new JMenuItem("▲Up");
        upTableRow.addActionListener(l ->{
            int selectedRow = this.getSelectedRow();
            if (selectedRow > 0) {
                this.tableModel.moveRow(selectedRow, selectedRow, selectedRow - 1);
                this.mainPanel.updateModelWithJTableModel(this.tableModel);// update CustomScanDataModel with JTable's Data
            }
        });
        this.popupTableMenu.add(upTableRow);

        JMenuItem downTableRow = new JMenuItem("▼Down");
        downTableRow.addActionListener(l ->{
            int selectedRow = this.getSelectedRow();
            int lastRow = this.tableModel.getRowCount() - 1;
            LOGGER4J.debug("Down: selectedRow:" + selectedRow + " lastRow:" + lastRow);
            if (selectedRow >= 0 && selectedRow < lastRow) {
                this.tableModel.moveRow(selectedRow, selectedRow, selectedRow + 1);
                this.mainPanel.updateModelWithJTableModel(this.tableModel);// update CustomScanDataModel with JTable's Data
            }
        });
        this.popupTableMenu.add(downTableRow);

        //add mouse listener for popup menu
        scroller.addMouseListener(new MouseListener() {// Pop-up menu on the viewport except the JTable columns area
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {

            }

            @Override
            public void mousePressed(MouseEvent mouseEvent) {
                popupMenuPerformed(mouseEvent);
            }

            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                popupMenuPerformed(mouseEvent);
            }

            @Override
            public void mouseEntered(MouseEvent mouseEvent) {

            }

            @Override
            public void mouseExited(MouseEvent mouseEvent) {

            }
        });
        this.addMouseListener(new MouseListener() {// Pop-up menu in the JTable columns area of the viewport
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {
            }

            @Override
            public void mousePressed(MouseEvent mouseEvent) {
                popupMenuPerformed(mouseEvent);
            }

            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                popupMenuPerformed(mouseEvent);
            }

            @Override
            public void mouseEntered(MouseEvent mouseEvent) {

            }

            @Override
            public void mouseExited(MouseEvent mouseEvent) {

            }
        });
    }

    @Override
    public void editingStopped(ChangeEvent e) {
        try {
            super.editingStopped(e);
        } catch(Exception ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        LOGGER4J.debug("editingStopped");
        // update CustomScanDataModel with this JTable contents
        mainPanel.updateModelWithJTableModel(tableModel);
    }

    @Override
    public void editingCanceled(ChangeEvent e) {
        super.editingCanceled(e);
        LOGGER4J.debug("editingCancelled");
    }

    private void popupMenuPerformed(MouseEvent evt) {
        if(evt.isPopupTrigger()) {
            this.popupTableMenu.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }

    @Override
    public Component prepareRenderer(TableCellRenderer tcr, int row, int col) {
        Component c = super.prepareRenderer(tcr, row, col);
        JComponent jc = (JComponent)c;
        EtchedBorder cellEtchedBorder = new EtchedBorder(Color.WHITE, Color.LIGHT_GRAY);
        jc.setBorder(cellEtchedBorder);
        return c;
    }

}
