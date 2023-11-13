package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.parosproxy.paros.view.WorkbenchPanel;
import org.zaproxy.zap.extension.alert.AlertPanel;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemSiteNodeContainer;

import java.util.List;

@SuppressWarnings("serial")
public class PopUpMenuInAlert extends PopupMenuItemSiteNodeContainer {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    public PopUpMenuInAlert() {
        super("alertMenu", false);
    }
    @Override
    protected void performAction(SiteNode siteNode) {
        ExtensionAlert extensionAlert =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAlert.class);

        List<Alert> alerts = siteNode.getAlerts();
        HistoryReference historyReference = siteNode.getHistoryReference();
        String uri = historyReference.getURI().toString();
        for(Alert alert: alerts) {
                String param = alert.getParam();
            if (alert.getUri().equals(uri)
                    && !alert.getAttack().isEmpty()
            && alert.getName().equals(Constant.messages.getString("customactivescan.testsqlinjection.name.text"))) {
                LOGGER4J.debug("Name[" + alert.getName() +"]");
                LOGGER4J.debug("Alert id[" + alert.getAlertId() + "]");
                LOGGER4J.debug("attack[" + alert.getAttack() + "]");
                LOGGER4J.debug("URL[" + alert.getUri() + "]");
                extensionAlert.displayAlert(alert);
                break;
            }
        }
        WorkbenchPanel workBenchPanel = View.getSingleton().getWorkbench();
        for (AbstractPanel panel: workBenchPanel.getSortedPanels(WorkbenchPanel.PanelType.STATUS)) {
            LOGGER4J.debug("panel[" + panel.getName() + "]");
            if (panel.getName().equals("Alerts")){
                if (panel instanceof AlertPanel) {
                    LOGGER4J.debug("Alert Panel Found.");
                    AlertPanel alertPanel = (AlertPanel) panel;
                }
            }
        }



    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer){
      if(invoker==Invoker.SITES_PANEL){
          return false;
      }
      return true;
    }
}
