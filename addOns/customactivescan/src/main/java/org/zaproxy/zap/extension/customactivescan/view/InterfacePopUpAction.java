package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.network.HttpMessage;

public interface InterfacePopUpAction {
    public void popUpActionPerformed(HttpMessage message);
}
