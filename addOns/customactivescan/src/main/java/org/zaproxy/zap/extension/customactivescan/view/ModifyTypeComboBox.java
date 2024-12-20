package org.zaproxy.zap.extension.customactivescan.view;

import org.zaproxy.zap.extension.customactivescan.model.ModifyType;

import javax.swing.*;
@SuppressWarnings("serial")
public class ModifyTypeComboBox extends JComboBox<ModifyType> {

    /**
     * default package private constructor<br>
     * this means that this class can be instantiated only in this package.
     */
    ModifyTypeComboBox() {
        super(ModifyType.values());
        postSuper();
    }

    /**
     * build this GUI.<br>
     * you must call this method after creating this object.
     */
    private void postSuper() {
        DefaultListCellRenderer defaultRenderer = new DefaultListCellRenderer();
        defaultRenderer.setHorizontalAlignment(DefaultListCellRenderer.CENTER);
        setRenderer(defaultRenderer);
    }
}
