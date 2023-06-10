package org.zaproxy.zap.extension.customactivescan.model;

import java.util.Random;

public class WaitTimerObject {
    private long prevNanoTime = -1;
    private Random random;
    public WaitTimerObject() {
        prevNanoTime = -1;
        random = new Random();
    }

    public void waitUntilSpecifiedTimePassed(CustomScanJSONData.ScanRule selectedScanRule) {
        long mSecWaitTime = selectedScanRule.getIdleTime(this.random);
        long currentNanoTime = System.nanoTime();
        if (this.prevNanoTime != -1) {
            long nanoWaitTime = mSecWaitTime * 1000000;
            long lapseNanoTime = currentNanoTime - this.prevNanoTime;
            if (lapseNanoTime < nanoWaitTime) {
                // wait until nanoWaitTime passes
                long sleepMSecTime = Math.round((double)(nanoWaitTime - lapseNanoTime) / 1000000);
                try {
                    Thread.sleep(sleepMSecTime);
                } catch (Exception ex) {

                }
            }
        }
        this.prevNanoTime = System.nanoTime();
    }
}
