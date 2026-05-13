package org.zaproxy.zap.extension.customactivescan.model;

import org.zaproxy.zap.extension.customactivescan.CustomSQLInjectionScanRule;

import java.util.Random;

public class WaitTimerObject {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private long prevNanoTime = -1;
    private Random random;
    private CustomSQLInjectionScanRule scanRuleCode;
    private final long POLLINTERVAL = 10; // MSec: polling interval when sleeping
    public WaitTimerObject(CustomSQLInjectionScanRule scanRuleCode) {
        prevNanoTime = -1;
        random = new Random();
        this.scanRuleCode = scanRuleCode;
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
                    //Thread.sleep(sleepMSecTime);
                    pollAndSleep(sleepMSecTime);
                } catch (Exception ex) {
                    LOGGER4J.error(ex.getMessage(), ex);
                }
            }
        }
        this.prevNanoTime = System.nanoTime();
    }

    private void pollAndSleep(long mSecTime) throws InterruptedException {
        long quotient = mSecTime / POLLINTERVAL;
        long remainder = mSecTime % POLLINTERVAL;
        for (long i = 0; i < quotient; i++) {
            if(!this.scanRuleCode.isStoppedThisScan()) {
                Thread.sleep(POLLINTERVAL);
            } else {
                LOGGER4J.debug("detected isStoppedThisScan when sleeping i=" + i);
                return;
            }
        }
        if (remainder > 0) {
            if (!this.scanRuleCode.isStoppedThisScan()) {
                Thread.sleep(remainder);
            } else {
                LOGGER4J.debug("detected isStoppedThisScan when sleeping remainder" + remainder);
            }
        }
    }
}
