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

    /**
     * Constructor for calling super class constructor.<br>
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     *
     * @param clazz
     * @param label
     * @param icon
     */
    protected PopUpMenuItem(Class<? extends Component> clazz,
            String label, Icon icon) {
        super(label);
        this.clazz = clazz;
    }

   /**
     * new instance method<br>
     * you must define this in your extended classes for instantiation<br>
     *
     * @param clazz
     * @param label
     * @param icon
     * @return this object
     */
    public static PopUpMenuItem newInstance(Class<? extends Component> clazz,
            String label, Icon icon) {
        PopUpMenuItem popupMenuItem = new PopUpMenuItem(clazz, label, icon);
        // you must call buildPopUpMenuItem() method after instanciated this object.
        return popupMenuItem.buildPopUpMenuItem(icon);
    }

    /**
     * you must call this method after creating this object.<br>
     * See newInstace() method.
     *
     * @param icon
     * @return this object
     */
    protected final PopUpMenuItem buildPopUpMenuItem(Icon icon) {
        if (icon != null) {
            setIcon(icon);
        }
        setMenuIndex(1);
        return this;
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

