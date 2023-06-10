package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.customactivescan.model.PauseActionObject;
import org.zaproxy.zap.extension.customactivescan.view.ScanLogPanel;
import org.zaproxy.zap.extension.customactivescan.view.ScanLogPanelFrame;

import javax.swing.*;

public class CustomScannerListener implements org.parosproxy.paros.core.scanner.ScannerListener {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    @Override
    public void scannerComplete(int id) {
        LOGGER4J.debug("scanner Completed scannerId[" + id + "]");
        ScanLogPanelFrame scanLogPanelFrame = ExtensionAscanRules.scannerIdScanLogFrameMap.remove(id);
        PauseActionObject pauseActionObject = ExtensionAscanRules.scannerIdPauseActionMap.get(id);

        if (pauseActionObject != null) {
            synchronized(pauseActionObject) {// monitor pauseActionObject in this Thread.
                pauseActionObject.terminate();
                pauseActionObject.notifyAll();
                ExtensionAscanRules.scannerIdThreadMap.remove(id);
            }
        }
        if (scanLogPanelFrame != null) {
            ScanLogPanel scanLogPanel = scanLogPanelFrame.getScanLogPanel();
            if (scanLogPanel != null) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        scanLogPanel.disablePauseCheckBox();
                    }
                });
            }
        }

        ExtensionAscanRules.scannerIdPauseActionMap.remove(id);
        ExtensionAscanRules.scannerIdWaitTimerMap.remove(id);
        LOGGER4J.debug("scanner Completed scannerId[" + id + "] running scanlog count after this completion:" + ExtensionAscanRules.scannerIdScanLogFrameMap.size());
    }

    @Override
    public void hostNewScan(int id, String hostAndPort, HostProcess hostThread) {

    }

    @Override
    public void hostProgress(int id, String hostAndPort, String msg, int percentage) {

    }

    @Override
    public void hostComplete(int id, String hostAndPort) {

    }

    @Override
    public void alertFound(Alert alert) {

    }

    @Override
    public void notifyNewMessage(HttpMessage msg) {

    }
}
