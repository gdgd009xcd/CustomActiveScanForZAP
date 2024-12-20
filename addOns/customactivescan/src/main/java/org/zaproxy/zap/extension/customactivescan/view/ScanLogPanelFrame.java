package org.zaproxy.zap.extension.customactivescan.view;

import org.parosproxy.paros.view.AbstractFrame;
import org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules;
import org.zaproxy.zap.extension.customactivescan.model.PauseActionObject;

import javax.swing.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

@SuppressWarnings("serial")
public class ScanLogPanelFrame extends AbstractFrame {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private ScanLogPanel scanLogPanel;
    private boolean isDisposed = false;

    /**
     * Constructor for calling super class constructor.<br>
     * Do not call this constructor directly for instantiating this class.<br>
     * use newInstance() method instead.
     *
     * @param flagColumns
     * @param scannerId
     */
    protected ScanLogPanelFrame(String[] flagColumns, int scannerId) {
        super();
    }

    /**
     * new instance method<br>
     * you must define this in your extended classes<br>
     *
     * @param flagColumns
     * @param scannerId
     * @return
     */
    public final static ScanLogPanelFrame newInstance(String[] flagColumns, int scannerId) {
        ScanLogPanelFrame scanLogPanelFrame = new ScanLogPanelFrame(flagColumns, scannerId);
        return scanLogPanelFrame.buildScanLogPanelFrame(flagColumns, scannerId);
    }

    /**
     * you must call this method after creating this object.<br>
     * See newInstace() method.
     *
     * @param flagColumns
     * @param scannerId
     * @return
     */
    protected final ScanLogPanelFrame buildScanLogPanelFrame(String[] flagColumns, int scannerId) {
        this.scanLogPanel = ScanLogPanel.newInstance(this, ExtensionAscanRules.customScanMainPanel,flagColumns, scannerId, false);

        add(this.scanLogPanel);
        pack();// fit frame size with it's contents size.
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                ScanLogPanelFrame.this.isDisposed = true;// notify scanner to terminate pauseAction.
                setVisible(false);
                dispose();
                LOGGER4J.debug("windowClosing called");
                PauseActionObject pauseActionObject = ExtensionAscanRules.scannerIdPauseActionMap.get(scannerId);
                if (pauseActionObject != null) {
                    synchronized(pauseActionObject) {// monitor pauseActionObject in this Thread.
                        pauseActionObject.terminate();
                        pauseActionObject.notifyAll();
                        ExtensionAscanRules.scannerIdThreadMap.remove(scannerId);
                    }
                }

                ExtensionAscanRules.scannerIdPauseActionMap.remove(scannerId);
                ExtensionAscanRules.removeScanLogPanelFrame(scannerId);
                LOGGER4J.debug("ScanLogPanelFrame remove Pauseactionmap and frame by scannerId=" + scannerId);
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        ExtensionAscanRules.customScanMainPanel.reflectScanLogPanelInputToMainPanel();
                    }
                });
            }
        });
        setTitle("ScanLogPanel");

        setVisible(true);
        return this;
    }

    public ScanLogPanel getScanLogPanel() {
        return this.scanLogPanel;
    }

    public boolean isDisposed() { return this.isDisposed; }

    public void updateRequestCounter(int offset) {
        if (this.scanLogPanel != null) {
            this.scanLogPanel.updateRequestCounter(offset);
        }
    }

    public void postPmtParamsToScanLogPanel(int selectedRequestNo, int lastRequestNo, int tabIndex) {
        if (this.scanLogPanel != null) {
            this.scanLogPanel.postPmtParamsToScanLogPanel(selectedRequestNo, lastRequestNo, tabIndex);
        }
    }
}
