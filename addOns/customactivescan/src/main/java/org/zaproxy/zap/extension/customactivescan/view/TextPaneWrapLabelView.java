package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.text.Element;
import javax.swing.text.LabelView;
import javax.swing.text.View;

class TextPaneWrapLabelView extends LabelView {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public TextPaneWrapLabelView(Element elem) {
        super(elem);
    }

    public float getMinimumSpan(int axis) {
        switch (axis) {
            case View.X_AXIS:
                return 0;
            case View.Y_AXIS:
                return super.getMinimumSpan(axis);
            default:
                throw new IllegalArgumentException("Invalid axis: " + axis);
        }
    }

}