package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.*;

@SuppressWarnings({"unchecked", "serial"})
public class StyleLabel extends JLabel implements InterfaceCompoStyleName {
    private String styleName;
    public StyleLabel(String styleName, String value){
        super(value);
        this.styleName = styleName;
    }

    @Override
    public void setStyleName(String name) {
        this.styleName = name;
    }

    @Override
    public String getStyleName() {
        return this.styleName;
    }
}
