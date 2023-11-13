package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.messagecontainer.MessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

import javax.swing.*;
import java.awt.*;

public class PopUpMenuItem extends PopupMenuItemHttpMessageContainer {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private static final long serialVersionUID = 1L;

    private Class<? extends Object> clazz;

    public PopUpMenuItem(Class<? extends Component> clazz,
            String label, Icon icon) {
        super(label);
        this.clazz = clazz;

        if (icon != null) {
            setIcon(icon);
        }
        setMenuIndex(1);
    }

    @Override
    protected void performAction(HttpMessage message) {
        if (message != null) {
            if (InterfacePopUpAction.class.isAssignableFrom(message.getClass())){
                InterfacePopUpAction action =  (InterfacePopUpAction) message;
                action.popUpActionPerformed(message);
            }
        }
    }

    @Override
    public boolean isEnableForMessageContainer(MessageContainer<?> messageContainer) {
        boolean result = super.isEnableForMessageContainer(messageContainer);
        if (clazz != null && messageContainer != null) {
            Component compo =  messageContainer.getComponent();
            if (compo != null) {
                if (LOGGER4J.isDebugEnabled()) {
                    if (clazz.equals(compo.getClass())) {
                        LOGGER4J.debug("is Enable compo is same clazz[" + clazz.getName() + "]");
                    } else {
                        LOGGER4J.debug("is Enable compo is different clazz[" + clazz.getName() + "]");
                    }
                }
                return clazz.equals(compo.getClass());
            }
        }
        return result;
    }
}

