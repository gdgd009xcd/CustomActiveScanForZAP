package org.zaproxy.zap.extension.customactivescan;

import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerHook;
import org.parosproxy.paros.network.HttpMessage;

public class CustomScannerHook implements ScannerHook {

    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    @Override
    public void scannerComplete() {

    }

    @Override
    public void beforeScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {
        LOGGER4J.debug("beforeScan plugin[" + plugin.getName() + "]");
    }

    @Override
    public void afterScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {
        LOGGER4J.debug("afterScan plugin[" + plugin.getName() + "]");
    }
}
