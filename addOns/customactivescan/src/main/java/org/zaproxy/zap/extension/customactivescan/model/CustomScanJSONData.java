package org.zaproxy.zap.extension.customactivescan.model;

import java.util.Collection;

// JSON data format for saving CustomScanDataModel to file.

public class CustomScanJSONData {
    public int minIdleTime = 0;
    public int maxIdleTime = 0;
    public boolean randomieIdleTime = false;
    Collection<String> flagResults;
    Collection<RuleJSONData> ruleJSONData;

    public static class RuleJSONData {
        public String ruleType;
        public boolean doScanLogOutput;
        public InjectionPatterns patterns;
    }
}
