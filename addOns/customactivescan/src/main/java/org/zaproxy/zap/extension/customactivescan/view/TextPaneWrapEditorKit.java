package org.zaproxy.zap.extension.customactivescan.view;

import javax.swing.text.Document;
import javax.swing.text.StyledEditorKit;
import javax.swing.text.ViewFactory;
import java.util.logging.Logger;

@SuppressWarnings("serial")
class TextPaneWrapEditorKit extends StyledEditorKit {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    ViewFactory wrapViewFactory = new TextPaneWrapColumnFactory();
    ViewFactory currentViewFactory = null;
    Document doc ;
    Boolean isWrapText;
    TextPaneWrapEditorKit(Document doc) {
        this.doc = doc;
        this.isWrapText = true;
        this.currentViewFactory = wrapViewFactory;
    }
    @Override
    public ViewFactory getViewFactory() {
        return this.currentViewFactory;
    }

    /**
     * setEditorKit call setDocument with this method as argument
     * @return
     */
    @Override
    public Document createDefaultDocument() {
        return this.doc;
    }

    public void setIsWrapText(boolean isWrapText) {
        this.isWrapText = isWrapText;
        if (this.isWrapText) {
            this.currentViewFactory = wrapViewFactory;
        } else {
            this.currentViewFactory = super.getViewFactory();
        }
    }

}