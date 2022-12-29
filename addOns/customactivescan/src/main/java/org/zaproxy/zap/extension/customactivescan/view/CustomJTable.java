package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

@SuppressWarnings("serial")
public class CustomJTable extends JTable implements CellEditorListener {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    DefaultTableModel tableModel = null;
    CustomScanMainPanel mainPanel;
    JPopupMenu popupTableMenu;

    public CustomJTable(CustomScanMainPanel mainPanel, JScrollPane scroller, DefaultTableModel model) {
        super(model);
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);// you can select only 1 row at a time.
        this.tableModel = model;
        this.mainPanel = mainPanel;

        scroller.setViewportView(this);

        // popup menu
        this.popupTableMenu = new JPopupMenu();
        JMenuItem insertTableRow = new JMenuItem("Insert");
        insertTableRow.addActionListener(l ->{
            int selectedRow = this.getSelectedRow();
            if (selectedRow != -1) {
                this.tableModel.insertRow(selectedRow, new Object[0]);
            }
        });
        this.popupTableMenu.add(insertTableRow);

        JMenuItem addTableRow = new JMenuItem("Add");
        addTableRow.addActionListener(l ->{
            this.tableModel.addRow(new Object[0]);
        });
        this.popupTableMenu.add(addTableRow);

        JMenuItem delTableRow = new JMenuItem("Delete");
        delTableRow.addActionListener(l ->{
            int selectedRow = this.getSelectedRow();
            if (selectedRow != -1) {
                this.tableModel.removeRow(selectedRow);
                this.mainPanel.rulePatternTableFocusLost(true);// popup save file dialog if needed
                this.mainPanel.updateModelWithJTableModel(this.tableModel);// update CustomScanDataModel with JTable's Data
            }
        });
        this.popupTableMenu.add(delTableRow);

        JMenuItem upTableRow = new JMenuItem("▲Up");
        upTableRow.addActionListener(l ->{

        });
        this.popupTableMenu.add(upTableRow);

        JMenuItem downTableRow = new JMenuItem("▼Down");
        downTableRow.addActionListener(l ->{

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
        super.editingStopped(e);
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
