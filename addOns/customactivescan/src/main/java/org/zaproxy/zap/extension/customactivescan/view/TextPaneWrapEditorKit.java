package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.text.Document;
import javax.swing.text.StyledEditorKit;
import javax.swing.text.ViewFactory;
@SuppressWarnings("serial")
class TextPaneWrapEditorKit extends StyledEditorKit {
    ViewFactory defaultFactory=new TextPaneWrapColumnFactory();
    Document doc ;
    TextPaneWrapEditorKit(Document doc) {
        this.doc = doc;
    }
    @Override
    public ViewFactory getViewFactory() {
        return defaultFactory;
    }

    /**
     * setEditorKit call setDocument with this method as argument
     * @return
     */
    @Override
    public Document createDefaultDocument() {
        return this.doc;
    }

}