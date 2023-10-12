package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.text.StyledEditorKit;
import javax.swing.text.ViewFactory;
@SuppressWarnings("serial")
class TextPaneWrapEditorKit extends StyledEditorKit {
    ViewFactory defaultFactory=new TextPaneWrapColumnFactory();
    public ViewFactory getViewFactory() {
        return defaultFactory;
    }

}