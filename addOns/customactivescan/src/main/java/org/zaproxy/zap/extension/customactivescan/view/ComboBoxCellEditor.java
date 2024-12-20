package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.ModifyType;

import javax.swing.*;
@SuppressWarnings("serial")
public class ComboBoxCellEditor extends DefaultCellEditor {

    // celleditor's combobox. when input focus is given this cell, this combobox is appeared.
    // Only one has input focus at a time. Therefore, only one combobox object is sufficient.
    // private static ModifyTypeComboBox modifyTypeComboBox = ModifyTypeComboBox.newInstance();
    private static ModifyTypeComboBox modifyTypeComboBox = new ModifyTypeComboBox();
    public ComboBoxCellEditor() {
        super(modifyTypeComboBox);
    }
}
