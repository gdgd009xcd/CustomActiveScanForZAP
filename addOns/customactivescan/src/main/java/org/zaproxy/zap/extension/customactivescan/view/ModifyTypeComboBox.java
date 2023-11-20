package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.ModifyType;

import javax.swing.*;
@SuppressWarnings("serial")
public class ModifyTypeComboBox extends JComboBox<ModifyType> {
    public ModifyTypeComboBox() {
        super(ModifyType.values());
        DefaultListCellRenderer defaultRenderer = new DefaultListCellRenderer();
        defaultRenderer.setHorizontalAlignment(DefaultListCellRenderer.CENTER);
        this.setRenderer(defaultRenderer);
    }
}
